#!/usr/bin/env python3
"""usage: summarize.py <attack.log | -> <client.csv> [detections.csv] [attacker_ip]"""
import csv
import sys


def p95(v):
    v = sorted(v)
    return v[min(len(v) - 1, int(round(0.95 * (len(v) - 1))))] if v else float('nan')


def main():
    attack_log, client_csv = sys.argv[1], sys.argv[2]
    det_csv = sys.argv[3] if len(sys.argv) > 3 else None
    attacker = sys.argv[4] if len(sys.argv) > 4 else '10.0.0.1'

    cli = []
    for line in open(client_csv):
        p = line.strip().split(',')
        if len(p) == 3:
            try:
                cli.append((float(p[0]), float(p[1]), int(p[2])))
            except ValueError:
                pass

    start = end = None
    att = []
    if attack_log != '-':
        for line in open(attack_log):
            if line.startswith('ATTACK_START'):
                start = float(line.split()[1])
            elif line.startswith('ATTACK_END'):
                end = float(line.split()[1])
            else:
                p = line.strip().split(',')
                if len(p) == 3:
                    att.append((float(p[0]), int(p[1]), int(p[2])))

    win = [r for r in cli if start and end and start <= r[0] <= end] if start else cli
    label = 'during attack' if start else 'whole run'
    print('--- legitimate client (%s) ---' % label)
    print('requests            : %d' % len(win))
    if win:
        print('success rate        : %.1f %%' % (100.0 * sum(r[2] for r in win) / len(win)))
        print('p95 latency         : %.1f ms' % p95([r[1] for r in win]))

    if att:
        print('--- attacker ---')
        print('probes sent         : %d   succeeded: %d' % (len(att), sum(r[2] for r in att)))
        det = None
        if det_csv:
            try:
                for r in csv.DictReader(open(det_csv)):
                    if r['src'] == attacker and float(r['block_time']) >= start - 1:
                        det = r
                        break
            except (OSError, KeyError):
                pass
        if det:
            tb = float(det['block_time'])
            print('rule fired          : %s' % det['rule'])
            print('detection time      : %s ms (first SYN in window -> rule fires)' % det['detect_ms'])
            print('response time       : %s ms (rule fires -> drop flow sent)' % det['response_ms'])
            print('end-to-end          : %.1f ms (attack start -> drop flow sent)' % ((tb - start) * 1000))
            print('probes OK after blk : %d   (should be 0)' % sum(1 for r in att if r[0] > tb and r[2]))
            print('controller packet-ins at block time: %s' % det['packet_ins'])
        else:
            print('no detection recorded (baseline mode, or attacker not detected)')


if __name__ == '__main__':
    main()
