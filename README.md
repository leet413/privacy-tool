# Privacy Scanner (Proxmox LXC)

Self-hosted, multi-user tool that searches the web for data-broker / people-search listings of you,
links each one to its opt-out page, and tracks your removals (including alerts when a site re-lists you).

## Install

1. Create a **public** GitHub repo (e.g. `youruser/privacy-scanner`) and push this folder to it.
   It contains no secrets: keys and the database are generated on the container.
2. On the Proxmox host shell, as root:

```bash
REPO=youruser/privacy-scanner bash -c "$(curl -fsSL https://raw.githubusercontent.com/youruser/privacy-scanner/main/ct/privacy-scanner.sh)"
```

(Or edit the `REPO=` default at the top of `ct/privacy-scanner.sh` and drop the prefix.)

3. Open the URL it prints (`http://<container-ip>:8080`). The first visit creates the admin account.
   Add your girlfriend from **Users**. Each user's profiles, scans, and tracker are private to them;
   admins manage accounts but cannot see anyone's data.

Override defaults with env vars: `CTID, CT_NAME, CORES, RAM, SWAP, DISK, STORAGE, TEMPLATE_STORAGE,
BRIDGE, IP (dhcp or 192.168.1.50/24), GATEWAY, VLAN, DNS, SSH_KEY_FILE, BRANCH, ASSUME_YES=1`.

## Operate

| Task | Command |
|------|---------|
| Update to the latest GitHub version | `./privacy-scanner.sh update <CTID>` (on the PVE host) |
| Shell into the container | `pct enter <CTID>` |
| Logs | `pct exec <CTID> -- journalctl -u privacy-scanner -f` |
| Settings (Brave API key, scan delay) | edit `/etc/privacy-scanner/env`, then `systemctl restart privacy-scanner` |
| Database | `/var/lib/privacy-scanner/app.db`; nightly copies in `backups/` (14 days) |

## Security notes
- Keep it LAN-only; do not port-forward it. Add an HTTPS reverse proxy (and set `COOKIE_SECURE=1`) if you want TLS.
- Passwords are hashed, forms are CSRF-protected, logins are rate-limited, and a strict CSP is set.
- Profile data is stored unencrypted in SQLite. Use encrypted storage for the container and Proxmox backups if that matters to you.
- Scans send search queries containing your details to DuckDuckGo (or Brave). That is inherent to searching.
- Opt-out URLs in `app/privacy_scanner.py` (`BROKERS`) can go stale; verify before submitting, and edit the list as needed.
