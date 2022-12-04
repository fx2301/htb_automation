import os
import signal
import subprocess
import sys

if os.geteuid() != 0:
    print("You must be root to run the launcher.")
    exit(1)

HTB_SUBDIR = os.environ.get("HTB_SUBDIR", "htb")
HOME = os.environ.get("HOME")
DATA_DIR = f"{HOME}/{HTB_SUBDIR}"

print(f"Subdirectory for data is {HTB_SUBDIR} (override this with HTB_SUBDIR=xyz")
print(f"Data directory is therefor {DATA_DIR}")
print()

host = sys.argv[1]

if len(sys.argv) == 3:
    ip = sys.argv[2]
else:
    ip = None

if not os.path.isdir(f"{DATA_DIR}/{host}"):
    os.mkdir(f"{DATA_DIR}/{host}") 
if not os.path.isdir(f"{DATA_DIR}/{host}/fileserve"):
    os.mkdir(f"{DATA_DIR}/{host}/fileserve") 
os.system(f"ln -s fileserve/common {DATA_DIR}/{host}/fileserve/common")

output = subprocess.run(f"grep -F '{host}' /etc/hosts", shell=True, stderr=subprocess.DEVNULL, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE).stdout.decode('utf-8')

entry = output.split("\n")[0].split(" ")[0].split("\t")[0]

if len(entry) == 0 and ip is not None:
    cmd = f"echo '{ip} {host}' | sudo tee -a /etc/hosts"
    print(cmd)
    os.system(cmd)
    
subprocess.check_output(f"ping {host} -c 1", shell=True).decode('utf-8')

try:
    processes = []
    processes.append(subprocess.Popen(f'python3 recon.py {host} 2>&1 > {DATA_DIR}/{host}/recon.log',
        shell=True, preexec_fn=os.setsid))

    processes.append(subprocess.Popen(f'bash -c "source venv/bin/activate && mitmdump -s hackerinthemiddle.py 2>&1 > {DATA_DIR}/{host}/mitm.log"',
        shell=True, preexec_fn=os.setsid))

    processes.append(subprocess.Popen(f'python3 fuzz.py {host} 2>&1 > {DATA_DIR}/{host}/fuzz.log',
        shell=True, preexec_fn=os.setsid))

    processes.append(subprocess.Popen(f'python3 pingbackdetector.py {host} 2>&1 > {DATA_DIR}/{host}/pingback.log',
        shell=True, preexec_fn=os.setsid))

    processes.append(subprocess.Popen(f'python3 -m http.server 8000 2>&1 > {DATA_DIR}/{host}/fileserve.log',
        shell=True, cwd=f"{DATA_DIR}/{host}/fileserve", preexec_fn=os.setsid))

    os.chdir(DATA_DIR)
    os.chdir(host)

    os.system("touch README.md")
    os.system("touch noteworthy.txt")
    os.system("touch mitm.txt")
    os.system("tail -f recon.log mitm.log fuzz.log pingback.log fileserve.log")
finally:
    print("Terminating processes...")
    for process in processes:
        os.killpg(os.getpgid(process.pid), signal.SIGTERM)
