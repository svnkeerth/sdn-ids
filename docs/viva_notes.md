# Viva preparation

| Question | Short answer |
|---|---|
| What does the project do? | A TCP service runs on a Mininet network. An SDN controller watches new connections, detects scans and floods with sliding-window rules, and installs drop flows on the switch. |
| Where is the SDN part? | The controller programs the switch with OpenFlow: table-miss to controller, per-connection forwarding, and a priority-100 drop flow when a rule fires. |
| How do socket and SDN interact? | The app's TCP connections generate packet-ins at the controller; the controller's decision (a drop flow) changes what the server can receive. Demo 2 adds direct app-to-controller UDP alerts. |
| Why count only SYN packets? | A SYN without ACK is exactly one new connection. Counting all packets would flag the server's replies. |
| Why one flow per TCP connection? | So every new connection misses the table and reaches the controller. The cost is more packet-ins, which grows controller load. |
| Why does the drop flow have priority 100? | OpenFlow uses the highest-priority match; the drop rule must outrank the forwarding flows (10). |
| Why no flows for ARP and ICMP? | A coarse L2 flow would also match TCP packets and hide them from the controller. |
| How were thresholds chosen? | The normal client makes about 22 connections per 5 s window; R1 = 30 leaves headroom. R2 = 10 ports because a normal client uses one. |
| What is the false-positive risk? | A bursty legitimate client could exceed R1. Demo 2 tests this and shows the speed-versus-false-positive trade-off. |
| Why is detection about 214 ms / 296 ms? | The attack rate and the threshold decide it: 11 ports at 50/s, 31 connections at 100/s. The controller reacts at the first moment the rule allows. |
| What is response time? | From rule firing to the flow-mod being sent: about 0.12 ms. |
| How is the baseline different? | Same controller and same attacks with `IDS_MODE=off`: it only forwards. The attacker sends 500 scan probes and completes 1000 flood connections. |
| Why was legitimate success 100% in both modes? | The attack does not overload an 8-worker server. The benefit shown is containment and reduced load; overload scenarios are Demo 2. |
| How does the server handle concurrency? | Accept thread, bounded queue, 8 worker threads, idle timeouts, and load shedding when the queue is full. |
| What are the limitations? | Threshold rules, one switch, spoofed IPs, controller bottleneck, no payload inspection. |
| What went wrong during development? | `sudo mn -c` killing Ryu (run order), Ryu not installing on new Python (3.9 venv, pinned build tools), and an attribute name (`self.events`) shadowing Ryu's internal queue. |

Be ready to open: `controller/ids.py` (`_inspect`, `_block`, `packet_in`), `app/app_server.py` (worker pool, queue), `scripts/run.sh`.
