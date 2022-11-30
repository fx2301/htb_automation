from mitmproxy import http
import shlex
import os
import re

HTB_SUBDIR = os.environ.get("HTB_SUBDIR", "htb")
HOME = os.environ.get("HOME")
DATA_DIR = f"/{HOME}/{HTB_SUBDIR}"

IGNORE_HEADERS = [
    'host',
    'user-agent',
    'accept-language',
    'accept-encoding',
    'connection',
    'referer',
    'pragma',
    'cache-control',
    'upgrade-insecure-requests',
    'content-length',
    'origin'
]

def request_to_curl(flow: http.HTTPFlow) -> str:
    parts = [
        'curl'
    ]

    request = flow.request
    if request.method != 'GET':
        parts.append("-X")
        parts.append(request.method)

    parts.append(request.url)

    for k,v in request.headers.items():
        if k.lower() == 'accept' and '*' in v:
            continue
        if k.lower() not in IGNORE_HEADERS:
            parts.append("-H")
            parts.append(f"{k}: {v}")

    if len(request.content) > 0:
        parts.append("--data")
        parts.append(request.content.decode('utf-8'))

    return shlex.join(parts)

def log(flow: http.HTTPFlow, msg: str) -> None:
    if not flow.request.host.endswith(".htb"):
        return
    top_level_host = '.'.join(flow.request.host.split('.', 2)[-2:])

    with open(f'{DATA_DIR}/{top_level_host}/mitm.txt', 'a') as f:
        f.write(msg)
        f.write("\n")

def logged(flow: http.HTTPFlow, msg: str) -> None:
    if not flow.request.host.endswith(".htb"):
        return
    top_level_host = '.'.join(flow.request.host.split('.', 2)[-2:])

    with open(f'{DATA_DIR}/{top_level_host}/mitm.txt', 'r') as f:
        for line in f.readlines():
            if line == msg+"\n":
                return True

    return False

# def request(flow: http.HTTPFlow) -> None:
#     if not flow.request.host.endswith(".htb"):
#         return

def get_header_value(headers: http.Headers, name: str) -> str:
    if headers.get(name, None) is not None:
        return headers[name]
    return headers.get(name.lower(), None)
        
def response(flow: http.HTTPFlow) -> None:
    if not flow.request.host.endswith(".htb"):
        return
    if flow.request.path == '/favicon.ico':
        return

    if not logged(flow, request_to_curl(flow)):
        log(flow, request_to_curl(flow))
        log(flow, f"# status = {flow.response.status_code}")
        log(flow, f"# duration = {flow.response.timestamp_end-flow.response.timestamp_start}")
        location = get_header_value(flow.response.headers, 'Location')
        if location is not None:
            log(flow, f"# location = {location}")
        server = get_header_value(flow.response.headers, 'Server')
        if server is not None:
            log(flow, f"# server = {server}")
        x_powered_by = get_header_value(flow.response.headers, 'x-Powered-By')
        if x_powered_by is not None:
            log(flow, f"# x_powered_by = {x_powered_by}")
        content_type = get_header_value(flow.response.headers, 'Content-Type')
        if content_type is not None:
            log(flow, f"# content_type = {content_type}")
        if content_type == 'application/html':
            for link in re.findall("href=[\"'][^#\"'][^'\"]+['\"]", flow.response.content.decode('utf-8'), re.IGNORECASE):
                log(flow, f"# link = {link}")
            for comment in re.findall("<!--.*?-->", flow.response.content.decode('utf-8'), re.MULTILINE | re.DOTALL | re.IGNORECASE):
                log(flow, "# comment = "+"\n # ".join(comment.split("\n")))
        if content_type == 'application/javascript':
            for comment in re.findall("//.*$", flow.response.content.decode('utf-8'), re.MULTILINE | re.DOTALL | re.IGNORECASE):
                log(flow, "# comment = "+"\n # ".join(comment.split("\n")))
            for comment in re.findall("/\*.*?*/", flow.response.content.decode('utf-8'), re.MULTILINE | re.DOTALL | re.IGNORECASE):
                log(flow, "# comment = "+"\n # ".join(comment.split("\n")))
            for domain in re.findall("^*.htb", flow.response.content.decode('utf-8'), re.MULTILINE | re.DOTALL | re.IGNORECASE):
                log(flow, f"# domain = {domain[-20:]}")

        log(flow, '')