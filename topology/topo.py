#!/usr/bin/env python3
"""
Mininet topology: 1 OpenFlow-1.3 switch, 4 hosts, remote Ryu controller.
    h1 10.0.0.1 attacker      h2 10.0.0.2 legitimate client
    h3 10.0.0.3 TCP server    h4 10.0.0.4 second attacker (Demo 2)

    sudo python3 topology/topo.py                 -> interactive Mininet CLI
    sudo python3 topology/topo.py --demo scan     -> automated run: normal | scan | flood
"""
import argparse
import os
import time

from mininet.cli import CLI
from mininet.log import setLogLevel
from mininet.net import Mininet
from mininet.node import OVSSwitch, RemoteController

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
APP = os.path.join(ROOT, 'app')
RES = os.path.join(ROOT, 'results')


def build():
    net = Mininet(controller=None, switch=OVSSwitch, autoSetMacs=True)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6653)
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    for name, ip in (('h1', '10.0.0.1'), ('h2', '10.0.0.2'),
                     ('h3', '10.0.0.3'), ('h4', '10.0.0.4')):
        net.addLink(net.addHost(name, ip=ip + '/24'), s1)
    return net


def run_demo(net, scenario):
    h1, h2, h3 = net.get('h1', 'h2', 'h3')
    s1 = net.get('s1')
    os.makedirs(RES, exist_ok=True)
    client_csv = '%s/client_%s.csv' % (RES, scenario)
    attack_log = '%s/attack_%s.log' % (RES, scenario)

    print('\n== starting TCP server on h3')
    h3.cmd('python3 %s/app_server.py > %s/server.log 2>&1 &' % (APP, RES))
    time.sleep(1)
    print('== connectivity check')
    net.pingAll()

    print('== legitimate client (h2) starts: 100 requests, ~23 s')
    h2.sendCmd('python3 %s/app_client.py 10.0.0.3 100 0.2 > %s' % (APP, client_csv))
    time.sleep(5)
    if scenario != 'normal':
        print('== t=5s: %s attack from h1 for 10 s' % scenario)
        h1.cmd('python3 %s/attack.py %s 10.0.0.3 --duration 10 > %s' % (APP, scenario, attack_log))
        print('== attack finished; switch drop rules (priority 100):')
        flows = s1.cmd('ovs-ofctl -O OpenFlow13 dump-flows s1')
        print('\n'.join(l.strip() for l in flows.splitlines() if 'priority=100' in l) or '  (none)')
        print('== can h1 still reach the server?')
        print(h1.cmd('ping -c 2 -W 1 10.0.0.3').strip().splitlines()[-2:])
    h2.waitOutput()
    print('== results')
    os.system('python3 %s/scripts/summarize.py %s %s %s/detections.csv' % (
        ROOT, attack_log if scenario != 'normal' else '-', client_csv, RES))
    h3.cmd('pkill -f app_server.py')


if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--demo', choices=['normal', 'scan', 'flood'])
    args = ap.parse_args()
    setLogLevel('info')
    net = build()
    net.start()
    try:
        if args.demo:
            run_demo(net, args.demo)
        else:
            CLI(net)
    finally:
        net.stop()
