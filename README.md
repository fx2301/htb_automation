# Overview

This script automates the tediuous steps with a new Hack The Box machine, as well as providing opinionated framework.

# What it does

* Add an entry for `xyz.htb` at the IP provided.
* Create a directory for your machine at `~/htb/xyz.htb`.
* Create an empty `README.md`.
* Create a `noteworthy.txt` file to collect noteworthy discoveries.
* Notify using `notify-send` for each new discovery.
* Screenshot `http://xyz.htb`.
* Recursively download c using wget.
* Fuzz for virtual hosts under `xyz.htb`.
* Fuzz for directories and files at `http://xyz.htb`. 

# Setup

```bash
snap install pageres
```

Also ensure seclists is installed to this path: `/usr/share/seclists`.

# Usage

```bash
python3 recon.py xyz.htb 10.10.x.y
```

Or, if `xyz.htb` is already in `/etc/hosts`, just:

```bash
python3 recon.py xyz.htb
```

# Related

```bash
python3 pickbackdetector.py xyz.htb
python3 fuzz.py xyz.htb
```

```bash
source venv/bin/activate
pip install -r requirements
mitmdump -s hackerinthemiddle.py
```
