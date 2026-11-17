# security-check (Arch Linux)

# Linux Arch-based security audit script for CachyOS, Arch, EndeavourOS, Manjaro, and other Arch derivatives.

# Security Check Script - Arch Linux Edition

A Linux security auditing tool adapted for Arch Linux that checks for system updates, listening ports, running services, rootkit indicators, malware, and authentication logs in one automated workflow.

This is the Arch Linux port of the original Debian/Ubuntu security check script, modified to use `pacman` package manager and Arch-specific logging (systemd journal).

## Features

- Checks for available system updates using `pacman`.
- Lists listening TCP and UDP ports with process information.
- Detects running Docker containers if Docker is installed.
- Detects running Podman containers if Podman is installed.
- Runs `rkhunter` for rootkit detection.
- Runs ClamAV for malware scanning.
- Reviews recent login activity.
- Reviews failed login attempts.
- Displays recent system warnings via `journalctl`.
- Searches systemd journal for failed password attempts (sshd and all services).
- Displays recent sudo activity via `journalctl`.
- Checks `/var/log/auth.log` if present (for syslog setups).
- Shows fail2ban jail status when fail2ban is installed.

## Requirements

- Python 3
- Arch Linux-based system (Arch, CachyOS, EndeavourOS, Manjaro, etc.)
- `sudo` privileges for full functionality

### Optional tools

- `rkhunter`
- `clamav`
- `fail2ban`
- `docker`
- `podman`

## Installation

```bash
# Clone the repository
git clone https://github.com/p4l0m1n0/security-check-arch.git
cd security-check-arch

# Install optional tools (recommended)
sudo pacman -S rkhunter clamav fail2ban docker podman

# Enable and start services if needed
sudo systemctl enable --now docker
sudo systemctl enable --now fail2ban
sudo systemctl enable --now clamav-freshclam
```

## Usage

Run the script with:

```bash
sudo python3 security_check_arch.py
```

## Key Differences from Ubuntu/Debian Version

| Feature | Ubuntu/Debian | Arch Linux |
|---------|---------------|------------|
| Package Manager | `apt` | `pacman` |
| Update Command | `apt update && apt upgrade` | `pacman -Syu` |
| List Upgradable | `apt list --upgradable` | `pacman -Qu` |
| Install Packages | `apt install <pkg>` | `pacman -S <pkg>` |
| Auth Logs | `/var/log/auth.log` | `journalctl` (primary) |
| ClamAV Package | `clamav clamav-freshclam` | `clamav` (includes freshclam) |

## How It Works

The script is organized into sections:

1. **System update checks** - Uses `pacman -Sy` to sync databases, `pacman -Qu` to list upgradable packages, `pacman -Su` to upgrade.
2. **Network and service enumeration** - Uses `ss -tulpn` for listening ports, checks Docker/Podman containers.
3. **Rootkit and malware detection** - Runs `rkhunter` and `clamscan`.
4. **Authentication and log analysis** - Uses `journalctl` for systemd journal (primary on Arch), falls back to `/var/log/auth.log` if present.

It is designed to be non-destructive and to provide clear output that can be reviewed manually by the administrator.

## Project Background

This Arch Linux version was adapted from the original Debian/Ubuntu security check script. The original Bash version focused on layered host security checks, including package updates, service enumeration, rootkit detection, malware scanning, and log analysis. The Python version expands on that structure while keeping the same security-focused workflow.

## Files

- `security_check_arch.py` — main Python script for Arch Linux.
- `README.md` — project documentation.

## Notes

- Some checks may be skipped if the required tools are not installed, although you will be warned if they are not.
- The script should be run with `sudo` for full access to logs and system information.
- Scanning the full filesystem with ClamAV may take a while depending on system size.
- Arch uses systemd journal as the primary logging system; `journalctl` queries replace most `/var/log/auth.log` grepping.
- On CachyOS, the script works out of the box since it's Arch-based.