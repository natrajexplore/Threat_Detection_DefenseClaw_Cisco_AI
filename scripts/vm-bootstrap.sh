#!/usr/bin/env bash
# Step 1 of 2 — run ONCE as your admin (sudo) user inside the Ubuntu lab VM.
# Creates the dedicated non-root lab login, base packages, a host firewall with no inbound
# access, and systemd user lingering so OpenClaw/DefenseClaw user services survive logout.
#
#   sudo bash scripts/vm-bootstrap.sh            # default user: netops
#   sudo LAB_USER=netops2 bash scripts/vm-bootstrap.sh
set -euo pipefail

LAB_USER="${LAB_USER:-netops}"

if [[ $EUID -ne 0 ]]; then echo "Run with sudo." >&2; exit 1; fi
. /etc/os-release
echo "==> Host: $PRETTY_NAME ($(uname -m))"
case "$(uname -m)" in x86_64|aarch64) ;; *) echo "DefenseClaw supports Linux x86_64/arm64 only." >&2; exit 1;; esac
[[ "$VERSION_ID" == "26.04" ]] || echo "NOTE: lab docs are written for Ubuntu 26.04; continuing on $VERSION_ID."

echo "==> Packages"
apt-get update -y
apt-get install -y git curl jq ufw ca-certificates build-essential iproute2

echo "==> Lab user '$LAB_USER' (non-root, no sudo)"
if id "$LAB_USER" &>/dev/null; then
  echo "    user exists, skipping"
else
  adduser --gecos "DefenseClaw NetOps lab" "$LAB_USER"   # prompts for the login password
fi
# Deliberately NOT added to the sudo group: the agent runs as this user, so it must not be able to escalate.
chmod 750 "/home/$LAB_USER"

echo "==> systemd user lingering (gateway services keep running without an open session)"
loginctl enable-linger "$LAB_USER"

echo "==> Host firewall: deny all inbound, allow outbound"
ufw default deny incoming
ufw default allow outgoing
# Uncomment if you manage the VM over SSH from the host:
# ufw allow from 192.168.56.0/24 to any port 22 proto tcp
ufw --force enable
ufw status verbose

cat <<EOF

Done. Next:
  1. Log in as '$LAB_USER' (new terminal / su - $LAB_USER).
  2. Put this repo at /home/$LAB_USER/defenseclaw-openclaw-lab (git clone or shared folder copy).
  3. Run: bash scripts/lab-user-setup.sh
  4. Take a VM snapshot named 00-clean.
EOF
