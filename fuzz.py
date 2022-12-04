import os
import subprocess
import sys
import re
import optparse
import shlex
import urllib.parse
from http.client import HTTPConnection
import time

ip = subprocess.check_output("ip addr | grep tun0$", shell=True).decode('utf-8').strip().split(' ')[1].split('/')[0]

fuzzwords = ['12121']
with open('fuzz_wordlist.txt', 'r') as f:
    for line in f.readlines():
        if line.startswith('##'):
            continue
        if len(line.strip()) == 0:
            continue
        word = line[0:-1].replace("$IP", ip)
        word_decoded = urllib.parse.unquote_to_bytes(word).decode('utf-8')
        if word_decoded not in fuzzwords:
            fuzzwords.append(word_decoded)

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

def fuzz(curl_cmd):
    args = shlex.split(curl_cmd)
    assert args[0] == 'curl'

    http_method = 'GET'
    headers = []
    i = 1
    data = None
    while i < len(args):
        if args[i] == '-X':
            i += 1
            http_method = args[i]
        elif args[i] == '-H':
            i += 1
            headers.append(args[i])
        elif args[i].startswith('http'):
            url = args[i]
        elif args[i] == '--data':
            i += 1
            data = args[i]
        else:
            raise RuntimeError(f"Unrecognized curl argument: {args[i]}")
        i += 1

    fuzzes_list = [
    ]

    print(curl_cmd)
    u = urllib.parse.urlparse(url)
    # print(u)
    if u.query != '':
        q = urllib.parse.parse_qs(u.query, keep_blank_values=True, strict_parsing=True)
        for k, vs in q.items():
            for i in range(0, len(vs)):
                fuzzes = []
                fuzzes_list.append(fuzzes)
                for word in fuzzwords:
                    q2 = urllib.parse.parse_qs(u.query, keep_blank_values=True, strict_parsing=True)
                    q2[k][i] += word
                    fq = urllib.parse.urlencode(q2, doseq=True)
                    fu = f"{u.scheme}://{u.netloc}{u.path}?{fq}"
                    # print(fu)
                    fuzzes.append((http_method, fu, headers, data))
    
    header_map = {}
    for header in headers:
        k, v = header.split(': ', 1)
        assert k not in header_map
        header_map[k] = v

        if k.lower() == 'content-type' and v =='application/x-www-form-urlencoded':
            q = urllib.parse.parse_qs(data, keep_blank_values=True, strict_parsing=True)
            for k, vs in q.items():
                for i in range(0, len(vs)):
                    fuzzes = []
                    fuzzes_list.append(fuzzes)
                    for word in fuzzwords:
                        q2 = urllib.parse.parse_qs(data, keep_blank_values=True, strict_parsing=True)
                        q2[k][i] += word
                        fd = urllib.parse.urlencode(q2, doseq=True)
                        # print("--data", fd)
                        fuzzes.append((http_method, url, headers, fd))
        elif k.lower() == 'content-type':
            raise RuntimeError(f"No fuzzer for content-type: {v}")

    for fuzzes in fuzzes_list:
        expected_status = None
        expected_content_length = None
        for http_method, url, headers, data in fuzzes:
            cmd = [
                'curl',
                '-s',
                '-D',
                '/dev/stderr',
                '-X',
                http_method,
                url
            ]
            for header in headers:
                cmd.append('-H')
                cmd.append(header)
            if data is not None:
                cmd.append('--data')
                cmd.append(data)
            fuzz_cmd = shlex.join(cmd)
            print(fuzz_cmd)
            with subprocess.Popen(fuzz_cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
                content = process.stdout.read()
                response_headers = []
                response_header_map = {}
                for line in process.stderr:
                    line = line.decode('utf-8')
                    if line.startswith('HTTP/1.1 '):
                        continue
                    elif len(line.strip()) == 0:
                        continue
                    elif ": " in line:
                        response_headers.append(line.strip())
                        parts = line.strip().split(": ", 1)
                        response_header_map[parts[0].lower()] = parts[1]
                    else:
                        raise RuntimeError(f"No handler for curl output line: {line}")
                
                actual_content_length = response_header_map['content-length']
                actual_status = response_header_map['status']

                if expected_status is None and expected_content_length is None:
                    expected_content_length = actual_content_length
                    expected_status = actual_status

                if expected_content_length != actual_content_length or expected_status != actual_status:
                    notify(f"Found fuzz ({actual_status} != {expected_status} or {actual_content_length} != {expected_content_length}): {fuzz_cmd}")


with subprocess.Popen(f"tail -f -n +1 mitm.txt", shell=True, stdout=subprocess.PIPE) as process:
    for line in process.stdout:
        line = line.decode('utf-8')[0:-1]
        if line.startswith('curl'):
            curl = line
            params = {}
        elif len(line) == 0:
            if params.get('duration', '').startswith('0.0'):
                fuzz(curl)
        elif line.startswith('# '):
            m = re.match('^# (.*?) = (.*)$', line)
            params[m[1]] = m[2]
        else:
            raise RuntimeError(f"Unexpected line: {line}")