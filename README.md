# EtherMask

EtherMask is a lightweight command-line tool for changing the MAC address of a network interface on Linux.  
It supports random MAC generation, vendor-based identity spoofing (using a curated list of real OUIs), periodic automatic changes, and restoring the original MAC address from a backup.

Author: **Ismail Jaber**

---

## Features

- Change MAC to a random, locally administered address  
- Generate a vendor-based (identity) MAC using predefined OUIs  
- Change MAC once or automatically at a specific time interval  
- Backup and restore the original MAC address  
- Simple and elegant CLI output using the `rich` library

---

## Requirements

- Linux with the `ip` command (`iproute2` package)  
- Python 3.8 or newer  
- Python packages: `netaddr`, `rich`  
- Root privileges (use `sudo`)

---

## Installation (from source)

```bash
git clone https://github.com/0xIsmo/EtherMask.git
cd EtherMask
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

---

## Quick Usage

```bash
# Show help
python3 EtherMask.py -h

# Change MAC to a random locally-administered address
sudo python3 EtherMask.py -i eth0 -m random

# Generate a vendor-based (identity) MAC
sudo python3 EtherMask.py -i wlan0 -m identity

# Change MAC every 60 seconds (press Ctrl + C to stop and show log)
sudo python3 EtherMask.py -i eth0 --mac-interval 60

# Restore the original MAC address from backup
sudo python3 EtherMask.py -i eth0 -r
```

---

## Notes and Warnings

EtherMask is intended for authorized and educational use only.  
Changing MAC addresses on networks you do not own or manage may violate laws or network policies.

Some network drivers or operating systems may revert the MAC address after reboot.  
The tool depends on the `ip` command, so make sure `iproute2` is installed.

---

## Files

- `EtherMask.py` — main script (single-file version)  
- `requirements.txt` — Python dependencies  
- `LICENSE` — MIT license  
- `README.md` — documentation file

---

## Contributing

Contributions, bug reports, and feature requests are welcome.  
Please open an issue or submit a pull request on GitHub.

---

## Author and Links

Ismail Jaber — [LinkedIn](https://www.linkedin.com/in/ismail-jaber-496b1631b/) — [GitHub](https://github.com/0xIsmo)

Project: EtherMask

---

## Example `requirements.txt`

```
netaddr
rich
```
