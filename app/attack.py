#!/usr/bin/env python3
"""
Controlled TCP security-test traffic generator (for the isolated Mininet lab ONLY).
  scan : sequential port probing of <target> (ports lo..hi)
  flood: repeated new connections to one port (connection-rate test)
Output: ATTACK_START <ts>, then CSV lines  time,port,success , then ATTACK_END <ts>
"""
import argparse
import socket
import time


def probe(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        return s.connect_ex((ip, port)) == 0
    except OSError:
        return False
    finally:
        s.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('mode', choices=['scan', 'flood'])
    ap.add_argument('target')
    ap.add_argument('--port', type=int, default=5000, help='flood: destination port')
    ap.add_argument('--lo', type=int, default=1)
    ap.add_argument('--hi', type=int, default=1024)
    ap.add_argument('--rate', type=float, default=None, help='attempts per second')
    ap.add_argument('--duration', type=float, default=10)
    ap.add_argument('--timeout', type=float, default=0.3)
    a = ap.parse_args()
    rate = a.rate or (50 if a.mode == 'scan' else 100)

    t_start = time.time()
    print('ATTACK_START %.6f' % t_start, flush=True)
    nxt, port = t_start, a.lo
    while time.time() - t_start < a.duration:
        if a.mode == 'scan':
            p = port
            port = a.lo if port >= a.hi else port + 1
        else:
            p = a.port
        t = time.time()
        ok = probe(a.target, p, a.timeout)
        print('%.6f,%d,%d' % (t, p, int(ok)), flush=True)
        nxt += 1.0 / rate
        if nxt > time.time():
            time.sleep(nxt - time.time())
    print('ATTACK_END %.6f' % time.time(), flush=True)


if __name__ == '__main__':
    main()
