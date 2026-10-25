# Setup (Ubuntu VM)

Verified on Ubuntu 26.04 (VM). Mininet and Open vSwitch run on the system Python; Ryu runs in its own Python 3.9 virtualenv.

## 1. Mininet and Open vSwitch

```bash
sudo apt update
sudo apt install -y mininet openvswitch-switch curl unzip
sudo systemctl enable --now openvswitch-switch
sudo ovs-vsctl show          # prints an ID and ovs_version, no error
sudo mn --test pingall       # 0% dropped
```

Note the spelling: `openvswitch-switch` (with the **v**). If `apt` says it cannot locate the package, check for a typo first.
Open vSwitch can already be present as a dependency of Mininet; the check above confirms it. The service names are
`ovs-vswitchd` and `ovsdb-server`.

## 2. Ryu in a Python 3.9 virtualenv

Ryu 4.34 does not run on current Python versions. `uv` downloads a standalone Python 3.9 without touching the system Python.

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.local/bin/env
uv venv --python 3.9 ~/ryuenv
source ~/ryuenv/bin/activate
python --version                                   # Python 3.9.x
uv pip install "setuptools<58" wheel pbr           # old build tools needed by ryu's installer
uv pip install --no-build-isolation eventlet==0.30.2 ryu
ryu-manager --version                              # ryu-manager 4.34
```

A harmless `SyntaxWarning` from `ryu/lib/packet/cfm.py` may be printed; ignore it.
If you only run `uv pip install ryu` the build fails with `get_script_args`; that is why the pinned build tools are installed first.

## 3. Check the environment before using the project

```bash
sudo mn -c                                                       # clean up FIRST
# terminal A (venv active)
ryu-manager --ofp-tcp-listen-port 6653 ryu.app.simple_switch_13
# terminal B (no venv)
sudo mn --controller=remote,ip=127.0.0.1,port=6653 --switch ovsk,protocols=OpenFlow13 --topo single,3
mininet> pingall                                                 # 0% dropped
```

## 4. Run the project

```bash
cd sdn-ids
scripts/run.sh normal
scripts/run.sh scan
scripts/run.sh flood
scripts/run.sh scan off
scripts/run.sh flood off
```

## Order rules that avoid most problems

* `sudo mn -c` kills any running `ryu-manager`. Always: `mn -c`, then start Ryu, then start Mininet (`scripts/run.sh` does this).
* The Ryu terminal needs the virtualenv (`(ryuenv)` in the prompt). The Mininet terminal does not.
* `sudo` uses the system Python, which is correct for Mininet.
