#!/usr/bin/env python3
"""Legitimate client. Usage: app_client.py <server_ip> <num_requests> <gap_seconds>
One new TCP connection per request. Prints CSV lines:  start_time,latency_ms,success"""
import socket
import sys
import time

ip, n, gap = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
for i in range(n):
    t0 = time.time()
    ok = False
    try:
        s = socket.create_connection((ip, 5000), timeout=1)
        s.sendall(('GET %d\n' % i).encode())
        ok = s.recv(256).startswith(b'OK')
        s.sendall(b'BYE\n')
        s.close()
    except OSError:
        pass
    print('%.6f,%.1f,%d' % (t0, (time.time() - t0) * 1000, int(ok)), flush=True)
    time.sleep(gap)
