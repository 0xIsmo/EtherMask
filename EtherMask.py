#!/usr/bin/env python3
import subprocess
import argparse
import re
import os
import sys
import time
from netaddr import EUI, mac_unix_expanded
import random
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from datetime import datetime

COLOR_RED = "\033[91m"
COLOR_GREEN = "\033[92m"
COLOR_YELLOW = "\033[93m"
COLOR_CYAN = "\033[96m"
COLOR_RESET = "\033[0m"

console = Console()
ORIGINAL_MAC_BACKUP_FILE = ".original_mac_backup"

# قائمة OUIs لمصنعين حقيقيين
VENDOR_OUIS = [
    "3C:15:C2",  # Apple
    "00:1E:68",  # Intel
    "F4:5C:89",  # Samsung
    "BC:92:6B",  # Huawei
    "00:1A:2B",  # Example Vendor
]

def get_vendor_name(mac):
    try:
        return EUI(mac).oui.registration().org
    except Exception:
        return "Unknown Vendor"

def display_banner():
    print(f"""{COLOR_CYAN}
==========================================
   MAC Address Changer v1
   Developed by: Ismail Jaber
   LinkedIn: https://www.linkedin.com/in/ismail-jaber-496b1631b/
   GitHub:   https://github.com/0xIsmo
==========================================
{COLOR_RESET}""")

def check_root_privileges():
    if os.geteuid() != 0:
        sys.exit(f"{COLOR_RED}[-] Please run this program as root (use sudo){COLOR_RESET}")

def parse_arguments():
    def rich_help():
        console.print(Panel.fit(
            "[bold cyan]MAC Address Changer v1[/bold cyan]\n"
            "Developed by: Ismail Jaber\n"
            "[link=https://www.linkedin.com/in/ismail-jaber-496b1631b/]LinkedIn[/link] | "
            "[link=https://github.com/0xIsmo]GitHub[/link]",
            title="About",
            border_style="cyan"
        ))

        table = Table(show_header=True, header_style="bold yellow")
        table.add_column("Option", style="cyan", no_wrap=True)
        table.add_column("Description", style="white")

        table.add_row("-i, --interface", "Network interface to change MAC address (e.g., eth0)")
        table.add_row("-m, --mac", "New MAC address, 'random', or 'identity' for vendor-based spoofing")
        table.add_row("--mac-interval", "Change MAC every N seconds")
        table.add_row("-r, --restore", "Restore original MAC address from backup")
        table.add_row("-h, --help", "Show this help message and exit")

        console.print(table)

        console.print("\n[bold white]Examples:[/bold white]")
        console.print("  [green]sudo python3 MacChanger.py -i eth0 -m random[/green]")
        console.print("  [green]sudo python3 MacChanger.py -i wlan0 -m identity[/green]")
        console.print("  [green]sudo python3 MacChanger.py -i eth0 --mac-interval 60[/green]")
        console.print("  [green]sudo python3 MacChanger.py -i eth0 -r[/green]\n")
        sys.exit()

    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("-i", "--interface", dest="interface", help="Network interface")
    parser.add_argument("-m", "--mac", dest="new_mac", help="New MAC address, 'random', or 'identity'")
    parser.add_argument("--mac-interval", type=int, help="Change MAC every N seconds")
    parser.add_argument("-r", "--restore", dest="restore", action='store_true', help="Restore original MAC")
    parser.add_argument("-h", "--help", action="store_true", help="Show help")

    args = parser.parse_args()

    if args.help:
        rich_help()

    if args.restore:
        if not args.interface:
            console.print("[red]Please specify an interface with --interface when restoring[/red]")
            sys.exit()
        return args

    if not args.interface:
        console.print("[red]Please specify a network interface with --interface[/red]")
        sys.exit()

    if args.new_mac and args.new_mac.lower() not in ['random', 'identity']:
        try:
            mac_obj = EUI(args.new_mac)
            mac_obj.dialect = mac_unix_expanded
            args.new_mac = str(mac_obj)
        except Exception:
            console.print("[red]Invalid MAC address format! Example: 00:1A:2B:3C:4D:5E[/red]")
            sys.exit()

    if not any([args.new_mac, args.mac_interval, args.restore]):
        console.print("[red]Please specify at least one action: --mac / --mac-interval / --restore[/red]")
        sys.exit()

    return args

def generate_random_mac(identity_mode=False):
    if identity_mode:
        vendor_prefix = random.choice(VENDOR_OUIS)
        random_suffix = ":".join(f"{random.randint(0x00, 0xff):02x}" for _ in range(3))
        return f"{vendor_prefix}:{random_suffix}"
    else:
        first_octet = random.randint(0x00, 0xff)
        first_octet = (first_octet & 0b11111100) | 0b00000010
        mac_bytes = [first_octet] + [random.randint(0x00, 0xff) for _ in range(5)]
        return ':'.join(f"{b:02x}" for b in mac_bytes)

def change_mac_address(interface, new_mac):
    print(f"{COLOR_YELLOW}[*] Changing MAC address for {interface} to {new_mac}...{COLOR_RESET}")
    subprocess.call(["ip", "link", "set", interface, "down"])
    subprocess.call(["ip", "link", "set", interface, "address", new_mac])
    subprocess.call(["ip", "link", "set", interface, "up"])

def retrieve_mac_address(interface):
    try:
        output = subprocess.check_output(["ip", "link", "show", interface]).decode("utf-8")
    except subprocess.CalledProcessError:
        sys.exit(f"{COLOR_RED}[-] Network interface '{interface}' not found.{COLOR_RESET}")

    mac_search = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", output)
    if mac_search:
        try:
            mac_obj = EUI(mac_search[0])
            mac_obj.dialect = mac_unix_expanded
            return str(mac_obj)
        except Exception:
            return mac_search[0].lower()
    else:
        sys.exit(f"{COLOR_RED}[-] Could not retrieve MAC address.{COLOR_RESET}")

def backup_original_mac(interface):
    mac = retrieve_mac_address(interface)
    with open(ORIGINAL_MAC_BACKUP_FILE, "w") as f:
        f.write(mac)
    print(f"{COLOR_CYAN}[*] Original MAC address {mac} saved to backup.{COLOR_RESET}")

def restore_original_mac(interface):
    if not os.path.exists(ORIGINAL_MAC_BACKUP_FILE):
        sys.exit(f"{COLOR_RED}[-] No backup found to restore original MAC address.{COLOR_RESET}")
    with open(ORIGINAL_MAC_BACKUP_FILE, "r") as f:
        original_mac = f.read().strip()
    print(f"{COLOR_YELLOW}[*] Restoring original MAC address {original_mac}...{COLOR_RESET}")
    change_mac_address(interface, original_mac)
    current_mac = retrieve_mac_address(interface)
    if current_mac.lower() == original_mac.lower():
        print(f"{COLOR_GREEN}[+] Original MAC address restored successfully!{COLOR_RESET}")
    else:
        print(f"{COLOR_RED}[-] Failed to restore original MAC address.{COLOR_RESET}")

def print_log_table(logs):
    table = Table(title="MAC Change Log", show_lines=True)
    table.add_column("Type", style="magenta", no_wrap=True)
    table.add_column("Old Value", style="cyan")
    table.add_column("New Value", style="green")
    table.add_column("Timestamp", style="yellow")

    for entry in logs:
        table.add_row(entry["type"], entry["old"], entry["new"], entry["time"])

    console.print(table)

def main():
    check_root_privileges()
    display_banner()
    args = parse_arguments()

    if args.restore:
        restore_original_mac(args.interface)
        return

    backup_original_mac(args.interface)

    logs = []

    def log_change(type_, old_val, new_val):
        logs.append({
            "type": type_,
            "old": old_val,
            "new": new_val,
            "time": datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        })

    try:
        # Initial MAC change if requested once without interval
        if args.new_mac and not args.mac_interval:
            old_mac = retrieve_mac_address(args.interface)
            if args.new_mac.lower() == 'random':
                new_mac = generate_random_mac(identity_mode=False)
                vendor_name = get_vendor_name(new_mac)
                print(f"{COLOR_CYAN}[*] Generated random MAC address: {new_mac} ({vendor_name}){COLOR_RESET}")
            elif args.new_mac.lower() == 'identity':
                new_mac = generate_random_mac(identity_mode=True)
                vendor_name = get_vendor_name(new_mac)
                print(f"{COLOR_CYAN}[*] Generated vendor-based MAC address: {new_mac} ({vendor_name}){COLOR_RESET}")
            else:
                new_mac = args.new_mac
                vendor_name = get_vendor_name(new_mac)
                print(f"{COLOR_CYAN}[*] Using provided MAC address: {new_mac} ({vendor_name}){COLOR_RESET}")

            change_mac_address(args.interface, new_mac)
            updated_mac = retrieve_mac_address(args.interface)
            if updated_mac.lower() == new_mac.lower():
                print(f"{COLOR_GREEN}[+] MAC address changed successfully!{COLOR_RESET}")
            else:
                print(f"{COLOR_RED}[-] Failed to change MAC address.{COLOR_RESET}")
            log_change("MAC", old_mac, new_mac)

        # Interval MAC change loop
        if args.mac_interval:
            print(f"{COLOR_YELLOW}[*] Press Ctrl+C to stop and display the MAC change log.{COLOR_RESET}")
            while True:
                old_mac = retrieve_mac_address(args.interface)
                if args.new_mac and args.new_mac.lower() == 'identity':
                    new_mac = generate_random_mac(identity_mode=True)
                else:
                    new_mac = generate_random_mac(identity_mode=False)
                vendor_name = get_vendor_name(new_mac)
                print(f"{COLOR_CYAN}[*] Changing to MAC address: {new_mac} ({vendor_name}){COLOR_RESET}")
                change_mac_address(args.interface, new_mac)
                log_change("MAC", old_mac, new_mac)
                print(f"{COLOR_YELLOW}[*] Waiting {args.mac_interval} seconds before next change...{COLOR_RESET}")
                time.sleep(args.mac_interval)

    except KeyboardInterrupt:
        print(f"\n{COLOR_GREEN}[+] Exiting gracefully. Goodbye!{COLOR_RESET}")
        if logs:
            print_log_table(logs)

if __name__ == "__main__":
    main()
