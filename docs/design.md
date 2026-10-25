# Design notes

## Components

| Component | File | Role |
|---|---|---|
| TCP server | `app/app_server.py` | Multi-client request service on port 5000 (h3) |
| Legitimate client | `app/app_client.py` | One new TCP connection per request, logs latency and success (h2) |
| Attack generator | `app/attack.py` | Controlled port scan and connection flood (h1) |
| Topology | `topology/topo.py` | 1 OVS switch (OpenFlow 1.3), hosts h1-h4, remote controller |
| Controller | `controller/ids.py` | Learning switch, detection rules, blocking, flow statistics |

## Application protocol (TCP, line based)

| Request | Response |
|---|---|
| `GET <number>\n` | `OK <number> <100-byte payload>\n` |
| `BYE\n` | server closes the connection |
| anything else | `ERR\n` |

Concurrency: the main thread only `accept()`s and puts connections in a bounded queue (64). Eight worker threads take connections
from the queue. A full queue means the connection is closed immediately (load shedding). Idle connections time out after 3 s.
Each request includes 20 ms of simulated work.

## Controller logic

1. **Switch connects**: install the table-miss flow (priority 0) that sends packets to the controller.
2. **Packet-in**: learn the source MAC and port; pick the output port (flood if unknown).
3. **TCP packets**: for a SYN without ACK sent to the server, update the sliding window of the source and evaluate R1 and R2.
   Then install a per-connection flow (priority 10, 5 s idle timeout, match on the 5-tuple), so the next new connection misses
   the table and is seen again.
4. **Other packets (ARP, ICMP, UDP)**: forwarded with packet-out only, no flow installed. A coarse flow here would match TCP
   packets too and hide them from the controller.
5. **Block**: install a priority-100 flow matching the source IP with no actions (drop) and a 60 s hard timeout; record the
   timestamps in `results/detections.csv`.
6. **Flow statistics**: every 2 s a flow-stats request is sent; per-source flow, packet and byte totals go to
   `results/flowstats.csv`, and R3 counts tiny flows towards the server.

Only SYN packets destined to the server are counted. Counting every TCP packet would flag the server itself, because its replies
go to many different client ports.

## Rules and thresholds

| Rule | Detects | Default | Why |
|---|---|---|---|
| R1 | connection flood | > 30 new connections in 5 s | The normal client makes about 100 requests in 23 s (about 22 per 5 s window), so 30 leaves headroom |
| R2 | port scan | > 10 distinct ports in 5 s | A normal client uses one port; 10 is far above that and fires after about 0.2 s of scanning |
| R3 | half-open or probe-like flows | > 15 flows with at most 2 packets in one poll | Complete connections exchange more than 2 packets |

The margin of R1 over normal traffic is deliberately modest; a bursty legitimate client could exceed it. Studying this
trade-off (detection speed against false positives) is planned for Demo 2.

Expected detection times follow from the attack rates: the scan sends 50 probes per second, so 11 distinct ports take about
0.22 s (measured 214 ms); the flood sends 100 connections per second, so 31 connections take about 0.31 s (measured 296 ms).

## Why these flow priorities

OpenFlow selects the highest-priority matching flow. The drop rule (100) must outrank the forwarding flows (10), otherwise
the attacker's packets would still match a forwarding flow. The table-miss (0) is the lowest so it only catches new traffic.

## Limitations

* Threshold rules, no learning
* Single switch, spoofed source addresses would block the wrong host
* The controller sees only the first packet of each connection (scalable, but no payload inspection)
* Blocking is by source IP for all traffic, including ICMP
