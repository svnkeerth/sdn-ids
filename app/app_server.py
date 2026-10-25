#!/usr/bin/env python3
"""
Multi-client TCP request server (low-level sockets).

Protocol (text, one message per line):
    GET <number>\\n   ->  OK <number> <100-byte payload>\\n
    BYE\\n            ->  server closes the connection
    anything else    ->  ERR\\n

Concurrency: the main thread only accept()s and puts connections in a BOUNDED queue;
WORKERS threads take them from the queue. If the queue is full the server sheds load
(closes the connection) instead of crashing.
Optional: set ALERT_ADDR=ip:port to send UDP alerts to the SDN controller (used in Demo 2).
"""
import json
import os
import queue
import socket
import threading
import time

PORT = int(os.environ.get('PORT', 5000))
WORKERS = int(os.environ.get('WORKERS', 8))
IDLE_TIMEOUT = float(os.environ.get('IDLE_TIMEOUT', 3))
QUEUE_SIZE = int(os.environ.get('QUEUE_SIZE', 64))
ALERT_ADDR = os.environ.get('ALERT_ADDR')               # "ip:port" or unset (disabled)

jobs = queue.Queue(maxsize=QUEUE_SIZE)
served = 0
lock = threading.Lock()
udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)


def alert(kind, src):
    if not ALERT_ADDR:
        return
    host, port = ALERT_ADDR.split(':')
    try:
        udp.sendto(json.dumps({'kind': kind, 'src': src, 't': time.time()}).encode(),
                   (host, int(port)))
    except OSError:
        pass                                            # never let an alert failure kill a worker


def handle(conn, addr):
    global served
    conn.settimeout(IDLE_TIMEOUT)
    f = conn.makefile('rwb')
    try:
        for raw in f:                                   # one request per line
            parts = raw.decode(errors='ignore').split()
            if len(parts) == 2 and parts[0] == 'GET' and parts[1].isdigit():
                time.sleep(0.02)                        # simulated processing time
                f.write(('OK %s %s\n' % (parts[1], 'x' * 100)).encode())
                f.flush()
                with lock:
                    served += 1
            elif parts[:1] == ['BYE']:
                break
            else:
                alert('MALFORMED', addr[0])
                f.write(b'ERR\n')
                f.flush()
    except socket.timeout:
        alert('IDLE_TIMEOUT', addr[0])                  # slow / idle client
    except OSError:
        pass                                            # client reset the connection
    finally:
        try:
            f.close()
        except OSError:
            pass
        conn.close()


def worker():
    while True:
        conn, addr = jobs.get()
        handle(conn, addr)


def reporter():
    last = 0
    while True:
        time.sleep(5)
        with lock:
            n = served
        print('[server] served=%d (+%d) queue=%d' % (n, n - last, jobs.qsize()), flush=True)
        last = n


def main():
    for _ in range(WORKERS):
        threading.Thread(target=worker, daemon=True).start()
    threading.Thread(target=reporter, daemon=True).start()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(('0.0.0.0', PORT))
    srv.listen(128)
    print('[server] listening on %d with %d workers' % (PORT, WORKERS), flush=True)
    while True:
        conn, addr = srv.accept()
        try:
            jobs.put_nowait((conn, addr))
        except queue.Full:
            alert('OVERLOAD', addr[0])
            conn.close()                                # load shedding


if __name__ == '__main__':
    main()
