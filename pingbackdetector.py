import os
import subprocess
import re
import sys
import shlex

HTB_SUBDIR = os.environ.get("HTB_SUBDIR", "htb")
HOME = os.environ.get("HOME")
DATA_DIR = f"/{HOME}/{HTB_SUBDIR}"

host = sys.argv[1]

os.chdir(DATA_DIR)
if not os.path.isdir(host):
    os.mkdir(host) 

os.chdir(host)

def notify(msg):
    with open('noteworthy.txt', 'a') as f:
        f.write(msg)
        os.system("notify-send "+(shlex.quote(msg)))
        f.write("\n")

with subprocess.Popen("sudo tcpdump -l -i tun0 icmp -Q in | tee /dev/null", shell=True, stdout=subprocess.PIPE) as process:
    for line in process.stdout:
        line = re.sub(r'\n$', '', line.decode('utf-8'))
        if "echo request" in line:
            length = int(line.strip().split(" ")[-1])
            msg = f"Received pingback (size {length-8})"
            print(msg)
            notify(msg)
