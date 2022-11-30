# Overview

This repo holds a collection of scripts for speeding up working on Hack The Box.

Conventions:
* `~/htb/xyz.htb` - directory for storing all files
* `~/htb/xyz.htb/README.md` - file for note taking
* `~/htb/xyz.htb/noteworthy.txt` - file to track notifications
* `~/htb/xyz.htb/executed.txt` - file to track recon commands completed
* `~/htb/xyz.htb/mitm.txt` - file to track requests made to .htb domains via mitmproxy

Automations:
* `python3 recon.py xyz.htb 10.10.x.y` - port scans, and for HTTP ports: screenshot, wget -r, vhost fuzz, dir & file fuzz
* `mitmdump -s hackerinthemiddle.py xyy.htb` - captures curl statements to `mitm.txt`.
* `python3 pingbackdetector.py xyz.htb` - listens for incoming pings on `tun0` (use `ping -s <size>` to distinguish between pings)
* `python3 fuzz.py xyz.htb` - watches `mitm.txt` and fuzzes to detect response variations for command injection, SQLi, NoSQLi, SSTI, and general errors (see `fuzz_wordlist.txt`)

# Setup

```bash
snap install pageres
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Also ensure seclists is installed to this path: `/usr/share/seclists`.

