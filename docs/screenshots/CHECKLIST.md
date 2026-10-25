# Screenshot checklist

Save the images in this folder with these names. Keep the command you typed visible at the top of each screenshot.

| File | Content | How |
|---|---|---|
| 01_architecture.png | Architecture diagram | open `docs/architecture.svg` |
| 02_topology.png | Topology and controller connected | `sudo python3 topology/topo.py`, then `net` and `sh ovs-vsctl show` (`is_connected: true`) |
| 03_socket_app.png | Server and client exchange | CLI: start `app_server.py` on h3, run `app_client.py 10.0.0.3 5 0.5` on h2 |
| 04_normal_run.png | Normal run, no false positive | `scripts/run.sh normal` |
| 05_scan_blocked.png | Scan blocked, drop rule visible | `scripts/run.sh scan` |
| 06_flood_blocked.png | Flood blocked | `scripts/run.sh flood` |
| 07_baseline_scan.png | Baseline scan, IDS off | `scripts/run.sh scan off` |
| 08_baseline_flood.png | Baseline flood, IDS off | `scripts/run.sh flood off` |
| 09_controller_log.png | BLOCKED lines in controller log | `grep BLOCKED results/ryu_scan_on.log results/ryu_flood_on.log` |
| 10_detections_csv.png | Logged measurements | `cat results/detections.csv` and `head results/flowstats.csv` |
| 11_unblock.png | Automatic unblock (T6) | steps in `docs/test_cases.md` |
