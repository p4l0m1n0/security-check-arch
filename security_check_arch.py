#!/usr/bin/env python3
"""
Combined Security Check Script for Arch Linux (no AIDE)
Run with: sudo python3 security_check_arch.py

Adapted for Arch Linux / CachyOS using pacman package manager.
"""

import subprocess
import shutil
import datetime
import os
import sys


def run_command(command, check=False, capture_output=True):
    """
    Run a shell command and return the result.

    Args:
        command: Shell command string to execute
        check: If True, raise exception on non-zero exit code
        capture_output: If True, return stdout/stderr; if False, print directly

    Returns:
        Stripped stdout string if capture_output=True, else None
    """
    try:
        result = subprocess.run(
            command,
            shell=True,
            check=check,
            capture_output=capture_output,
            text=True
        )
        return result.stdout.strip() if capture_output else None
    except subprocess.CalledProcessError as e:
        # Command failed - return error message
        return e.stderr.strip() if capture_output else None
    except Exception as e:
        # Other exception (e.g., command not found)
        return str(e)


def print_ascii_header():
    """
    Print ASCII art header for the security check script.
    Uses a box-style border with centered title.
    """
    print("\n" + "=" * 50)
    print("║" + " 🔒 COMBINED SECURITY CHECK - ARCH LINUX 🔒 " + "║")
    print("║" + f" Run Time: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}" + " " * 9 + "║")
    print("=" * 50)


def print_ascii_footer():
    """
    Print ASCII art footer for the security check script.
    Uses a matching box-style border with completion message.
    """
    print("\n" + "=" * 57)
    print("║" + " ✅ SECURITY CHECK COMPLETE ✅ " + " " * 24 + "║")
    print("=" * 57 + "\n")


def print_section(title):
    """
    Print a formatted section header with equal signs.
    Used for main sections (1, 2, 3, 4) within the script.
    """
    print("\n" + "=" * 47)
    print(title)
    print("=" * 47)


def print_subsection(title):
    """
    Print a formatted subsection header with dashes.
    Used for subsections within each main section.
    """
    print(f"\n--- {title} ---")


def check_system_updates():
    """
    Section 1: System Updates (Arch Linux / pacman)

    Checks for and applies system package updates using pacman.
    This ensures the system has the latest security patches.
    """
    print_section("1. Checking for system updates (pacman)...")

    # Sync pacman databases - refreshes the list of available packages
    print("Running: sudo pacman -Sy (syncing package databases)...")
    run_command("sudo pacman -Sy", capture_output=False)

    # List upgradable packages - shows packages that can be updated
    print("\nUpgradable packages (packages that can be updated):")
    upgradable = run_command("pacman -Qu")
    if upgradable:
        print(upgradable)
    else:
        print("No upgradable packages found (system is up to date).")

    # Upgrade all packages - installs the latest versions of upgradable packages
    # This applies security updates and bug fixes
    print("\nRunning: sudo pacman -Su (installing updates)...")
    run_command("sudo pacman -Su", capture_output=False)


def check_network_and_services():
    """
    Section 2: Network and Services

    Examines network connections, listening ports, and running services.
    Critical for identifying unauthorized network access or suspicious services.
    """
    print_section("2. Network and Services")

    # Show listening ports - displays all TCP/UDP ports with active listeners
    # ss is faster than netstat and shows process names (p), numeric addresses (n)
    # -t: TCP, -u: UDP, -l: listening only, -p: show process, -n: numeric
    print_subsection("Listening TCP/UDP ports (ss -tulpn)")
    ports = run_command("sudo ss -tulpn")
    if ports:
        print(ports)
    else:
        print("No listening ports found or command failed.")

    # List Docker containers - shows all running Docker containers
    # Useful for identifying containerized services that might be vulnerable
    print_subsection("Running Docker containers")
    if shutil.which("docker"):
        docker_containers = run_command("sudo docker ps")
        if docker_containers:
            print(docker_containers)
        else:
            print("No Docker containers running.")
    else:
        print("Docker not installed. Install with: sudo pacman -S docker")

    # List Podman containers - shows all running Podman containers
    # Podman is a daemonless alternative to Docker with similar CLI
    # Useful for identifying rootless or systemd-managed containers
    print_subsection("Running Podman containers")
    if shutil.which("podman"):
        podman_containers = run_command("sudo podman ps")
        if podman_containers:
            print(podman_containers)
        else:
            print("No Podman containers running.")
    else:
        print("Podman not installed. Install with: sudo pacman -S podman")


def check_rootkit_and_malware():
    """
    Section 3: Rootkit & Malware Checks

    Runs rkhunter (rootkit hunter) and ClamAV (antivirus) to detect
    malicious software, rootkits, and security compromises.
    """
    print_section("3. Rootkit & Malware Checks")

    # rkhunter check - scans for rootkits, malware, and system anomalies
    # --check: perform check, --skip-keypress: don't wait for key input
    # Rootkits are malicious software that hide deep in the system
    print_subsection("Running rkhunter (rootkit hunter)")
    if shutil.which("rkhunter"):
        print("Running rkhunter scan (this may take 5-15 minutes)...")
        # Filter out grep/egrep warnings from rkhunter's internal checks (known issue with grep 3.8+)
        # Matches: "grep: warning: stray \ before -" and "grep: warning: stray \ before +" etc.
        # And: "egrep: warning: egrep is obsolescent; using grep -E"
        rkhunter_cmd = (
            "sudo rkhunter --check --skip-keypress 2>&1 | "
            "grep -v -E '^(grep|egrep): warning: (stray \\\\\\\\ before .|egrep is obsolescent)'"
        )
        run_command(rkhunter_cmd, capture_output=False)
        print("rkhunter check completed.")
        print("Results logged to /var/log/rkhunter.log")
        rkhunter_result = None  # or read log file if you need it
    else:
        print("rkhunter not installed. Install with: sudo pacman -S rkhunter")

    # ClamAV scan - antivirus scan of the entire filesystem
    # Updates virus definitions first, then scans recursively
    print_subsection("Running ClamAV antivirus scan on root (/)")
    print("Note: This may take a while depending on system size (could be 10-30+ minutes).")

    if shutil.which("clamscan"):
        # Update virus definitions - downloads latest virus signatures
        # freshclam updates the ClamAV database to detect new threats
        print("Updating ClamAV virus definitions (freshclam)...")
        if shutil.which("freshclam"):
            run_command("sudo freshclam --quiet", capture_output=False)
        else:
            print("freshclam not found; skipping definition update.")

        # Scan entire filesystem recursively
        # -r: recursive scan, --infected: show only infected files
        # --exclude-dir: skip virtual filesystems to avoid errors/slowdown
        # --log: save scan results to file for later review
        print("Starting scan (excluding /proc, /sys, /dev, /run)...")
        scan_command = (
            "sudo clamscan -r / "
            "--exclude-dir=/proc "      # Virtual kernel process info
            "--exclude-dir=/sys "       # Virtual sysfs filesystem
            "--exclude-dir=/dev "       # Device files
            "--exclude-dir=/run "       # Runtime data
            "--infected "               # Show only infected files
            "--recursive "              # Scan subdirectories
            "--log=/tmp/clamav_scan.log"  # Save results to log file
        )
        run_command(scan_command, capture_output=False)
        print("Scan completed. Check /tmp/clamav_scan.log for details.")
    else:
        print("ClamAV not installed. Install with: sudo pacman -S clamav")


def check_authentication_and_logs():
    """
    Section 4: Authentication & Log Analysis

    Analyzes authentication logs, failed login attempts, and system warnings
    to detect potential security breaches or unauthorized access attempts.
    """
    print_section("4. Authentication & Log Analysis")

    # Show recent login history - displays when users logged in/out
    # last -a shows login times in aligned format, head -20 limits to 20 entries
    # Useful for spotting unusual login patterns or times
    print_subsection("Last 20 login entries (last -a)")
    last_log = run_command("sudo last -a | head -20")
    if last_log:
        print(last_log)
    else:
        print("No login entries found.")

    # Show failed login attempts - displays unsuccessful authentication attempts
    # lastb reads /var/log/btmp (failed login database)
    # Critical for detecting brute-force attacks or unauthorized access attempts
    print_subsection("Last 20 failed login attempts (lastb)")
    lastb_log = run_command("sudo lastb | head -20")
    if lastb_log:
        print(lastb_log)
    else:
        print("No failed login attempts found.")

    # Show system warnings - displays journalctl warnings from last 24 hours
    # --priority=warning: show warning-level messages only
    # --since "24h ago": limit to last 24 hours, tail -50 shows last 50 lines
    # Useful for detecting system issues or security events
    print_subsection("Last 50 system warnings (last 24h)")
    warnings = run_command("sudo journalctl --priority=warning --since '24h ago' | tail -50")
    if warnings:
        print(warnings)
    else:
        print("No system warnings found in the last 24 hours.")

    # Show failed password attempts - grep journalctl for failed password entries
    # Arch uses systemd journal primarily; auth.log may not exist by default
    print_subsection("Recent authentication failures (journalctl)")
    failed_passwords = run_command("sudo journalctl -u sshd --since '24h ago' | grep -i 'failed password' | tail -10")
    if failed_passwords:
        print(failed_passwords)
    else:
        print("No 'Failed password' entries found in sshd journal (last 24h).")

    # Also check for general auth failures in journal
    print_subsection("Recent authentication failures (all services, journalctl)")
    auth_failures = run_command("sudo journalctl --since '24h ago' | grep -i 'authentication failure' | tail -10")
    if auth_failures:
        print(auth_failures)
    else:
        print("No authentication failures found in journal (last 24h).")

    # Show sudo command history - displays all sudo commands executed
    # Important for auditing privileged command usage and detecting misuse
    print_subsection("Recent sudo commands (journalctl)")
    sudo_entries = run_command("sudo journalctl --since '24h ago' | grep -i 'sudo:' | tail -10")
    if sudo_entries:
        print(sudo_entries)
    else:
        print("No sudo entries found in journal (last 24h).")

    # Also check /var/log/auth.log if it exists (for rsyslog/syslog-ng setups)
    print_subsection("Recent authentication failures (/var/log/auth.log)")
    if os.path.exists("/var/log/auth.log"):
        failed_passwords = run_command("sudo grep 'Failed password' /var/log/auth.log | tail -10")
        if failed_passwords:
            print(failed_passwords)
        else:
            print("No 'Failed password' entries found in auth.log.")
    else:
        print("/var/log/auth.log not found (Arch uses systemd journal by default).")

    # Fail2ban jail status - shows active fail2ban protection jails
    # fail2ban blocks IPs after too many failed login attempts
    # Each jail protects a specific service (ssh, apache, etc.)
    print_subsection("Fail2ban jail status (IP blocking protection)")
    if shutil.which("fail2ban-client"):
        # Get overall fail2ban status to find active jails
        status_output = run_command("sudo fail2ban-client status")
        if status_output:
            # Parse jail list from status output (find line containing "Jail list:")
            jail_line = None
            for line in status_output.split('\n'):
                if 'Jail list:' in line:
                    jail_line = line
                    break

            if jail_line:
                # Extract jail names after "Jail list:" and clean formatting
                jails = jail_line.split('Jail list:')[1].strip()
                jails = jails.replace(',', ' ').replace('\t', ' ').strip()

                if not jails:
                    print("No jails are currently configured or active.")
                else:
                    print(f"Active jails found: {jails}")
                    print()

                    # Get detailed status for each jail
                    for jail in jails.split():
                        print("------------------------")
                        print(f"Jail: {jail} (protects this service)")
                        jail_status = run_command(f"sudo fail2ban-client status '{jail}'")
                        if jail_status:
                            print(jail_status)
                        print()
            else:
                print("Could not parse jail list from fail2ban status output.")
        else:
            print("No fail2ban status output returned.")
    else:
        print("fail2ban-client not found. Install with: sudo pacman -S fail2ban")


def main():
    """
    Main function - orchestrates all security check sections.

    Prints ASCII header/footer, checks for root privileges,
    and runs all security check functions in sequence.
    Handles interrupts and errors gracefully.
    """
    # Print cool ASCII header
    print_ascii_header()

    # Check if running as root (required for most commands)
    # os.geteuid() returns effective user ID (0 = root)
    # Many security tools need root to read logs, scan files, check ports
    if os.geteuid() != 0:
        print("\n⚠️  WARNING: This script should be run with sudo for full functionality.")
        print("   Many commands need root access to read logs, scan files, and check ports.")
        print("   Run with: sudo python3 security_check_arch.py\n")
        print("   Continuing without sudo (some checks may fail or show incomplete data)...")
        print()

    try:
        # Run all security check sections in order
        check_system_updates()
        check_network_and_services()
        check_rootkit_and_malware()
        check_authentication_and_logs()

        # Print cool ASCII footer
        print_ascii_footer()

    except KeyboardInterrupt:
        # Handle Ctrl+C interrupt gracefully
        print("\n\n⚠️  Script interrupted by user (Ctrl+C)")
        print("\n" + "=" * 62)
        print("║" + " ❌ SCRIPT INTERRUPTED ❌ " + " " * 28 + "║")
        print("=" * 62 + "\n")
        sys.exit(1)
    except Exception as e:
        # Handle any other unexpected errors
        print(f"\n\n❌ Error occurred: {e}")
        print("\n" + "=" * 62)
        print("║" + " ❌ SCRIPT FAILED ❌ " + " " * 32 + "║")
        print("=" * 62 + "\n")
        sys.exit(1)


if __name__ == "__main__":
    # Entry point - only run main() when script is executed directly
    # This prevents running when imported as a module
    main()