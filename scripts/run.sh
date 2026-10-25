#!/bin/bash
# One-command runner that does the steps in the CORRECT order:
#   usage:  scripts/run.sh <normal|scan|flood> [on|off]      (default mode: on)
# 1) mn -c  2) start Ryu (in background, own log)  3) wait for port 6653  4) run demo  5) stop Ryu
cd "$(dirname "$0")/.." || exit 1
SCEN=${1:?usage: scripts/run.sh normal|scan|flood [on|off]}
MODE=${2:-on}
mkdir -p results
source "${RYU_VENV:-$HOME/ryuenv}/bin/activate" || { echo "ryuenv not found"; exit 1; }
sudo mn -c > /dev/null 2>&1
IDS_MODE=$MODE ryu-manager --ofp-tcp-listen-port 6653 controller/ids.py > results/ryu_${SCEN}_${MODE}.log 2>&1 &
RP=$!
for i in $(seq 1 30); do ss -ltn | grep -q ':6653 ' && break; sleep 0.5; done
if ! ss -ltn | grep -q ':6653 '; then echo "Ryu did not start, see results/ryu_${SCEN}_${MODE}.log"; kill $RP 2>/dev/null; exit 1; fi
echo "Ryu running (mode=$MODE). Starting demo: $SCEN"
sudo python3 topology/topo.py --demo "$SCEN"
echo "---- controller log (BLOCKED lines) ----"
grep BLOCKED results/ryu_${SCEN}_${MODE}.log || echo "(none)"
kill $RP 2>/dev/null
