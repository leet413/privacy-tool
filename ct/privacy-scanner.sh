#!/usr/bin/env bash
# Privacy Scanner - Proxmox VE LXC installer.
# Run as root on the Proxmox host (not inside a container):
#
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/YOUR_GITHUB_USER/privacy-scanner/main/ct/privacy-scanner.sh)"
#
# Update an existing install later:   ./privacy-scanner.sh update <CTID>
#
# Every setting below can be overridden with an environment variable, e.g.
#   CTID=210 STORAGE=local-zfs DISK=10 IP=192.168.1.50/24 GATEWAY=192.168.1.1 ./privacy-scanner.sh
set -Eeuo pipefail

REPO="${REPO:-YOUR_GITHUB_USER/privacy-scanner}"   # GitHub "user/repo" (must be public)
BRANCH="${BRANCH:-main}"
CT_NAME="${CT_NAME:-privacy-scanner}"
CORES="${CORES:-2}"
RAM="${RAM:-1024}"          # MB
SWAP="${SWAP:-512}"         # MB
DISK="${DISK:-8}"           # GB
BRIDGE="${BRIDGE:-vmbr0}"
IP="${IP:-dhcp}"            # "dhcp" or CIDR such as 192.168.1.50/24
GATEWAY="${GATEWAY:-}"      # only used with a static IP
VLAN="${VLAN:-}"
DNS="${DNS:-}"
SSH_KEY_FILE="${SSH_KEY_FILE:-}"   # optional public key file to install for root

msg() { printf '\n\033[1;34m==>\033[0m %s\n' "$*"; }
die() { printf '\033[1;31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "Run this as root on the Proxmox VE host."
command -v pct >/dev/null || die "'pct' not found. This must run on a Proxmox VE host."

# ------------------------------------------------------------------ update mode
if [[ "${1:-}" == "update" ]]; then
  [[ -n "${2:-}" ]] || die "Usage: $0 update <CTID>"
  msg "Updating Privacy Scanner in container $2"
  pct exec "$2" -- env DEBIAN_FRONTEND=noninteractive bash /opt/privacy-scanner/install/setup.sh
  exit 0
fi

if [[ "$REPO" == *YOUR_GITHUB_USER* ]]; then
  die "Set REPO to your GitHub repo, e.g.  REPO=alice/privacy-scanner $0   (or edit the REPO line in this script)."
fi

# ------------------------------------------------------------------ pick defaults
pick_storage() { pvesm status --content "$1" 2>/dev/null | awk 'NR>1 && $3=="active"{print $1; exit}'; }
CTID="${CTID:-$(pvesh get /cluster/nextid)}"
STORAGE="${STORAGE:-$(pick_storage rootdir)}"
TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-$(pick_storage vztmpl)}"
[[ -n "$STORAGE" ]] || die "No storage that supports container disks was found. Set STORAGE=<name>."
[[ -n "$TEMPLATE_STORAGE" ]] || die "No storage that supports templates was found. Set TEMPLATE_STORAGE=<name>."

NET="name=eth0,bridge=${BRIDGE},ip=${IP}"
if [[ "$IP" != "dhcp" && -n "$GATEWAY" ]]; then NET+=",gw=${GATEWAY}"; fi
if [[ -n "$VLAN" ]]; then NET+=",tag=${VLAN}"; fi

cat <<EOF

  Container ID : $CTID
  Hostname     : $CT_NAME
  Resources    : ${CORES} cores, ${RAM} MB RAM, ${SWAP} MB swap, ${DISK} GB disk on '${STORAGE}'
  Network      : $NET
  Source       : github.com/${REPO} (${BRANCH})
EOF

if [[ -t 0 && "${ASSUME_YES:-0}" != "1" ]]; then
  read -rp "Create this container? [Y/n] " ans
  [[ "${ans:-Y}" =~ ^[Yy]$ ]] || die "Aborted."
fi

trap 'printf "\n\033[1;31mFailed at line %s.\033[0m If container %s was created it is left in place for inspection (remove with: pct stop %s; pct destroy %s)\n" "$LINENO" "$CTID" "$CTID" "$CTID"' ERR

# ------------------------------------------------------------------ template
msg "Locating Ubuntu template"
pveam update >/dev/null || true
TEMPLATE="$(pveam available --section system | awk '{print $2}' | grep -E '^ubuntu-24\.04-standard' | sort -V | tail -1 || true)"
if [[ -z "$TEMPLATE" ]]; then
  TEMPLATE="$(pveam available --section system | awk '{print $2}' | grep -E '^ubuntu-22\.04-standard' | sort -V | tail -1 || true)"
fi
[[ -n "$TEMPLATE" ]] || die "Could not find an Ubuntu 24.04 or 22.04 template via pveam."
if ! pveam list "$TEMPLATE_STORAGE" | grep -q "$TEMPLATE"; then
  msg "Downloading $TEMPLATE"
  pveam download "$TEMPLATE_STORAGE" "$TEMPLATE"
fi

# ------------------------------------------------------------------ create + start
msg "Creating container $CTID"
ARGS=()
if [[ -n "$DNS" ]]; then ARGS+=(--nameserver "$DNS"); fi
if [[ -n "$SSH_KEY_FILE" ]]; then ARGS+=(--ssh-public-keys "$SSH_KEY_FILE"); fi

pct create "$CTID" "${TEMPLATE_STORAGE}:vztmpl/${TEMPLATE}" \
  --hostname "$CT_NAME" --cores "$CORES" --memory "$RAM" --swap "$SWAP" \
  --rootfs "${STORAGE}:${DISK}" --net0 "$NET" \
  --unprivileged 1 --features nesting=1 --onboot 1 --ostype ubuntu \
  --tags privacy --timezone host "${ARGS[@]}"

msg "Starting container"
pct start "$CTID"

msg "Waiting for network (DHCP + DNS)"
ready=0
for _ in $(seq 1 40); do
  if pct exec "$CTID" -- getent hosts github.com >/dev/null 2>&1; then ready=1; break; fi
  sleep 2
done
[[ $ready -eq 1 ]] || die "The container cannot resolve github.com. Check BRIDGE / VLAN / IP / GATEWAY / DNS settings."

# ------------------------------------------------------------------ install app
msg "Installing prerequisites"
pct exec "$CTID" -- env DEBIAN_FRONTEND=noninteractive bash -c "apt-get update -qq && apt-get install -y -qq curl ca-certificates"

msg "Installing Privacy Scanner (this takes a minute or two)"
pct exec "$CTID" -- env REPO="$REPO" BRANCH="$BRANCH" DEBIAN_FRONTEND=noninteractive \
  bash -c "curl -fsSL https://raw.githubusercontent.com/${REPO}/${BRANCH}/install/setup.sh | bash"

trap - ERR
CT_IP="$(pct exec "$CTID" -- hostname -I | awk '{print $1}')"
cat <<EOF

Done.
  Open:     http://${CT_IP}:8080
  First visit creates the admin account; add your partner from the "Users" page.
  Shell:    pct enter ${CTID}
  Logs:     pct exec ${CTID} -- journalctl -u privacy-scanner -f
  Update:   $0 update ${CTID}
  Config:   /etc/privacy-scanner/env  (inside the container; add BRAVE_API_KEY here, then restart the service)

  Tip: give the container a DHCP reservation or a static IP, and keep it LAN-only
  (do not port-forward it). The data stored here is sensitive.
EOF
