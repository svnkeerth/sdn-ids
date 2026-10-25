"""
SDN intrusion detection + response  (Ryu controller, OpenFlow 1.3)

Pipeline:  packet-in (new TCP SYN)  ->  sliding-window rules  ->  drop flow-mod
Flow priorities on the switch:
    0   table-miss        -> send to controller
    10  per-connection    -> forward (idle timeout 5 s, so every NEW connection reaches us)
    100 block rule        -> DROP everything from an offending source IP (hard timeout)

Run from the repository root:   ryu-manager controller/ids.py
Baseline (no IDS):              IDS_MODE=off ryu-manager controller/ids.py
"""
import collections
import csv
import os
import time

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.lib.packet import ethernet, ipv4, packet, tcp
from ryu.ofproto import ofproto_v1_3

# ---------------- configuration (override with environment variables) ----------------
MODE = os.environ.get('IDS_MODE', 'on')              # 'on' = IDS active, 'off' = static baseline
SERVER_IP = os.environ.get('SERVER_IP', '10.0.0.3')  # protected TCP server
WINDOW = float(os.environ.get('WINDOW', 5))          # sliding window length (s)
RATE_LIMIT = int(os.environ.get('RATE_LIMIT', 30))   # R1: max new connections / window / source
PORT_LIMIT = int(os.environ.get('PORT_LIMIT', 10))   # R2: max distinct dst ports / window / source
SHORT_FLOWS = int(os.environ.get('SHORT_FLOWS', 15)) # R3: max tiny flows seen in one stats poll
BLOCK_TIME = int(os.environ.get('BLOCK_TIME', 60))   # how long a source stays blocked (s)
POLL_EVERY = float(os.environ.get('POLL_EVERY', 2))  # flow-stats polling period (s)
DET_LOG = os.environ.get('IDS_LOG', 'results/detections.csv')
STAT_LOG = os.environ.get('STATS_LOG', 'results/flowstats.csv')

PRIO_MISS, PRIO_CONN, PRIO_DROP = 0, 10, 100


def _open_csv(path, header):
    d = os.path.dirname(path)
    if d:
        os.makedirs(d, exist_ok=True)
    new = not os.path.exists(path)
    f = open(path, 'a', newline='')
    w = csv.writer(f)
    if new:
        w.writerow(header)
        f.flush()
    return f, w


class IDS(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(IDS, self).__init__(*args, **kwargs)
        self.dps = {}                                   # dpid -> datapath
        self.mac_to_port = {}                           # dpid -> {mac: port}   (learning switch)
        self.blocked = {}                               # src ip -> time blocked
        self.syn_log = collections.defaultdict(collections.deque)  # src ip -> deque[(t, dport)]
        self.packet_ins = 0                             # controller overhead counter
        self.det_f, self.det_w = _open_csv(DET_LOG, [
            'block_time', 'src', 'rule', 'first_event_time', 'detect_time',
            'detect_ms', 'response_ms', 'packet_ins'])
        self.stat_f, self.stat_w = _open_csv(STAT_LOG, [
            'time', 'src', 'flows', 'packets', 'bytes'])
        hub.spawn(self._poll)
        self.logger.info('IDS started: mode=%s window=%ss R1>%s conns R2>%s ports block=%ss',
                         MODE, WINDOW, RATE_LIMIT, PORT_LIMIT, BLOCK_TIME)

    # ------------------------------------------------------------------ OpenFlow plumbing
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp = ev.msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        self.dps[dp.id] = dp
        # table-miss: anything without a matching flow goes to the controller (whole packet)
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(dp, PRIO_MISS, parser.OFPMatch(), actions)

    def _add_flow(self, dp, priority, match, actions, idle=0, hard=0):
        ofp, parser = dp.ofproto, dp.ofproto_parser
        inst = []
        if actions:                                     # empty action list == DROP
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=priority, match=match,
                                      instructions=inst, idle_timeout=idle, hard_timeout=hard))

    # ------------------------------------------------------------------ packet-in
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp, parser = dp.ofproto, dp.ofproto_parser
        in_port = msg.match['in_port']
        self.packet_ins += 1

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        # --- learning switch ---
        self.mac_to_port.setdefault(dp.id, {})[eth.src] = in_port
        out_port = self.mac_to_port[dp.id].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        ip = pkt.get_protocol(ipv4.ipv4)
        t = pkt.get_protocol(tcp.tcp)
        if ip and t:
            if ip.src in self.blocked:
                return                                  # already blocked: drop silently
            is_syn = (t.bits & tcp.TCP_SYN) and not (t.bits & tcp.TCP_ACK)   # new connection
            if is_syn and ip.dst == SERVER_IP:
                self._inspect(ip.src, t.dst_port)
                if ip.src in self.blocked:              # this very SYN triggered the block
                    return
            if out_port != ofp.OFPP_FLOOD:
                # one flow per TCP connection (5-tuple) -> the NEXT new connection misses
                # the table and reaches us, which is what lets us count connection rates.
                match = parser.OFPMatch(eth_type=0x0800, ip_proto=6,
                                        ipv4_src=ip.src, ipv4_dst=ip.dst,
                                        tcp_src=t.src_port, tcp_dst=t.dst_port)
                self._add_flow(dp, PRIO_CONN, match, actions, idle=5)
        # ARP / ICMP / UDP: forwarded by packet-out only, NO flow installed
        # (a coarse L2 flow here would hide TCP packets from the controller!)

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                        in_port=in_port, actions=actions, data=data))

    # ------------------------------------------------------------------ detection rules
    def _inspect(self, src, dport):
        if MODE != 'on':
            return
        now = time.time()
        q = self.syn_log[src]
        q.append((now, dport))
        while q and now - q[0][0] > WINDOW:             # slide the window
            q.popleft()
        if len(q) > RATE_LIMIT:                                      # R1
            self._block(src, 'R1_HIGH_CONN_RATE', q[0][0], now)
        elif len({d for _, d in q}) > PORT_LIMIT:                    # R2
            self._block(src, 'R2_PORT_SCAN', q[0][0], now)

    # ------------------------------------------------------------------ response
    def _block(self, src, rule, first_event, t_detect):
        if MODE != 'on' or src in self.blocked:
            return
        for dp in self.dps.values():
            parser = dp.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src)
            self._add_flow(dp, PRIO_DROP, match, [], hard=BLOCK_TIME)   # no actions = DROP
        t_block = time.time()
        self.blocked[src] = t_block
        det_ms = (t_detect - first_event) * 1000
        resp_ms = (t_block - t_detect) * 1000
        self.det_w.writerow(['%.6f' % t_block, src, rule, '%.6f' % first_event,
                             '%.6f' % t_detect, '%.1f' % det_ms, '%.2f' % resp_ms,
                             self.packet_ins])
        self.det_f.flush()
        self.logger.warning('BLOCKED %s by %s | detection %.1f ms | response %.2f ms',
                            src, rule, det_ms, resp_ms)
        hub.spawn(self._unblock_later, src)

    def _unblock_later(self, src):
        hub.sleep(BLOCK_TIME)                           # switch removes the drop flow itself
        self.blocked.pop(src, None)                     # (hard timeout); we just forget the state
        self.syn_log.pop(src, None)
        self.logger.info('UNBLOCKED %s', src)

    # ------------------------------------------------------------------ flow statistics
    def _poll(self):
        while True:
            hub.sleep(POLL_EVERY)
            for dp in list(self.dps.values()):
                dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply(self, ev):
        now = time.time()
        agg = collections.defaultdict(lambda: [0, 0, 0])   # src -> [flows, packets, bytes]
        short = collections.Counter()
        for s in ev.msg.body:
            if s.priority != PRIO_CONN or 'ipv4_src' not in s.match:
                continue
            src = s.match['ipv4_src']
            a = agg[src]
            a[0] += 1
            a[1] += s.packet_count
            a[2] += s.byte_count
            if s.match['ipv4_dst'] == SERVER_IP and s.packet_count <= 2:
                short[src] += 1                         # tiny flow = probe / half-open connection
        for src, (f, p, b) in agg.items():
            self.stat_w.writerow(['%.3f' % now, src, f, p, b])
        self.stat_f.flush()
        for src, n in short.items():                    # R3
            if n > SHORT_FLOWS:
                self._block(src, 'R3_SHORT_FLOWS', now, now)
