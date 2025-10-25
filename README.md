# EtherMask

EtherMask is a lightweight command-line tool for temporarily changing a network interface's MAC address on Linux. It supports random MAC generation, vendor-based identity spoofing (using a curated list of OUIs), periodic changes, and restoring the original MAC address from a backup.

**Author:** Ismail Jaber

---

## Features

* Change MAC to a random, locally administered address
* Generate a vendor-based (identity) MAC using predefined OUIs
* Change MAC once or at an interval (every N seconds)
* Backup and restore the original MAC address
* Pretty CLI help and tables using `rich`

---

## Requirements

* Linux with `ip` command (iproute2)
* Python 3.8+
* Python packages: `netaddr`, `rich`
* Root privileges (use `sudo`)

---

## Installation (from source)

```bash
git clone https://github.com/0xismo/EtherMask.git
cd EtherMask
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```


---

## Quick Usage

```bash
# EtherMask
python3 EtherMask.py -h

# EtherMask
sudo python3 EtherMask.py -i eth0 -m random

# EtherMask
sudo python3 EtherMask.py -i wlan0 -m identity

# EtherMask
sudo python3 EtherMask.py -i eth0 --mac-interval 60

# EtherMask
sudo python3 EtherMask.py -i eth0 -r
```

---

## Notes & Warnings

* EtherMask is intended for **authorized** use only. Changing MAC addresses on networks you do not own or have permission to change may violate policies or laws. Use responsibly.
* Some network drivers or OS settings may revert MAC changes after reboot or may ignore manual changes; test on your target system.
* The tool uses the `ip` command internally. Ensure `iproute2` is installed on your distribution.

---

## Files

* `EtherMask.py` — main script (single-file version)
* `requirements.txt` — Python dependencies
* `LICENSE` — MIT license
* `README.md` — this file

---

## Contributing

Contributions, bug reports and feature requests are welcome. Please open an issue or submit a pull request on GitHub.

---

## Author & Links

Ismail Jaber — [LinkedIn](https://www.linkedin.com/in/ismail-jaber-496b1631b/) — [GitHub](https://github.com/0xIsmo)

Project: EtherMask

---

## Example `requirements.txt`

```
netaddr
rich
```
