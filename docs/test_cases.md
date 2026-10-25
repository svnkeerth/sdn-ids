# Test cases

| ID | Test | Command | Expected | Status |
|---|---|---|---|---|
| T1 | Connectivity | `scripts/run.sh normal` (pingall inside) | 0% dropped | Pass: 12/12 received |
| T2 | Normal traffic, no false positive | `scripts/run.sh normal` | 100% client success, no `BLOCKED` line | Pass: 100 of 100 |
| T3 | Port scan detected and blocked | `scripts/run.sh scan` | R2 fires, drop rule at priority 100, 0 probes OK after block | Pass: 214 ms |
| T4 | Connection flood detected and blocked | `scripts/run.sh flood` | R1 fires, drop rule, 0 probes OK after block | Pass: 296 ms |
| T5 | Legitimate traffic unaffected during attack | T3 and T4 | Client success stays near 100% | Pass: 100% |
| T6 | Automatic unblock | Run T4, wait `BLOCK_TIME` (60 s), then `h1 ping -c 2 10.0.0.3` in the CLI | Drop rule disappears, ping works again | To verify before submission |
| T7 | Static baseline | `scripts/run.sh scan off`, `scripts/run.sh flood off` | No detection, no drop rule, attacker unaffected | Pass: 500 and 1000 probes |

## How to run T6 manually

```bash
sudo mn -c
# terminal A (venv): BLOCK_TIME=20 ryu-manager --ofp-tcp-listen-port 6653 controller/ids.py
# terminal B:
sudo python3 topology/topo.py
mininet> h3 python3 app/app_server.py > results/server.log 2>&1 &
mininet> h1 python3 app/attack.py flood 10.0.0.3 --duration 5 > /dev/null
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=100     # rule present
mininet> h1 ping -c 2 -W 1 10.0.0.3                                       # 100% loss
# wait 20 s
mininet> sh ovs-ofctl -O OpenFlow13 dump-flows s1 | grep priority=100     # gone
mininet> h1 ping -c 2 10.0.0.3                                            # works again
```
