import os
import re
import shlex
import subprocess
import sys

HTB_SUBDIR = os.environ.get("HTB_SUBDIR", "htb")
HOME = os.environ.get("HOME")
DATA_DIR = f"/{HOME}/{HTB_SUBDIR}"

host = sys.argv[1]
os.chdir(f'{DATA_DIR}/{host}'   )

os.system("touch executed.txt")

executed = []
with open('executed.txt', 'r') as f:
    executed = [line.strip() for line in f.readlines()]

def do_cmd(cmd, noteworthy=None, msg_format="Found {0}"):
    global executed
    if cmd in executed:
        return
    print(cmd)
    with subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE) as process:
        for line in process.stdout:
            line = re.sub(r'\n$', '', line.decode('utf-8'))
            print(line)
            line = re.sub(r'^.*\u001b\[2K', '', line, flags=re.DOTALL)
            if noteworthy:
                m = re.match(noteworthy, line)
                if m:
                    msg = msg_format.format(m[1])
                    with open('noteworthy.txt', 'a') as f:
                        f.write(msg)
                        os.system("notify-send "+(shlex.quote(msg)))
                        f.write("\n")
            else:
                print(line)


    # TODO check the exit code
    
    with open('executed.txt', 'a') as f:
        f.write(cmd)
        f.write("\n")

def noteworthy(msg):
    with open('noteworthy.txt', 'r') as f:
        for line in f.readlines():
            if line.strip() == msg:
                return True

    return False

do_cmd(f"sudo -A nmap -Pn -n -sS -p 80,443,8080 -T 5 -oA tcpscan {host} -vv",
    noteworthy=r'^Discovered open port ([0-9]+)',
    msg_format="Found port {0}"
)
for msg, scheme, port in [["Found port 80", "http", 80], ["Found port 443", "https", 443], ["Found port 8080", "http", 8080]]:
    if noteworthy(msg):
        do_cmd(
            f"pageres {scheme}://{host}:{port}",
            noteworthy=r'^✔ Generated 1 screenshot from 1 url and 1 size()$',
            msg_format=f"Screenshot generated for {scheme}://{host}:{port}{{0}}"
        )
        # --no-check-certificate is for https redirects
        do_cmd(
            f"wget --no-check-certificate -r {scheme}://{host}:{port} 2>&1",
            noteworthy=r'^Downloaded: ([0-9]+ files?)',
            msg_format="Wget downloaded {0}"
        )
do_cmd(f"sudo nmap -Pn -n -sS -p- -T 5 -oA tcpscan {host} -vv",
    noteworthy=r'^Discovered open port ([0-9]+)',
    msg_format="Found port {0}"
)
for msg, scheme, port in [["Found port 80", "http", 80], ["Found port 443", "https", 443], ["Found port 8080", "http", 8080]]:
    if noteworthy(msg):
        do_cmd(
            f"ffuf -u '{scheme}://{host}:{port}' -H 'Host: FUZZ.{host}' -w /usr/share/seclists/Discovery/DNS/bitquark-subdomains-top100000.txt -ac -t 100 -o fuzz-vhost.{port}.txt",
            noteworthy=r'^([^# ]+)\s+\[',
            msg_format="{scheme}://{{0}}.{host}"
        )
        do_cmd(
            f"ffuf -u '{scheme}://{host}:{port}/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/common.txt -ac -t 100 -o fuzz-dirs.{port}.txt",
            noteworthy=r'^([^# ]+)\s+\[',
            msg_format=f"{scheme}://{host}:{port}/{{0}}"
        )
        do_cmd(
            f"ffuf -u '{scheme}://{host}:{port}/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -ac -t 100 -o fuzz-dirs.{port}.txt",
            noteworthy=r'^([^# ]+)\s+\[',
            msg_format=f"{scheme}://{host}:{port}/{{0}}"
        )
        do_cmd(
            f"ffuf -u '{scheme}://{host}:{port}/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt -ac -t 100 -o fuzz-files.{port}.txt",
            noteworthy=r'^([^# ]+)\s+\[',
            msg_format=f"{scheme}://{host}:{port}/{{0}}"
        )

