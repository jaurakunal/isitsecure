# Injection benchmark fixture — Python command injection, SSRF, path traversal,
# and SSTI (VULNERABLE). Sources: Flask/Django request objects.

import os
import subprocess
import urllib.request

import requests
from flask import render_template_string, request


# --- Command injection ---
def ping():
    host = request.args.get("host")
    os.system(f"ping -c 1 {host}")  # EXPECT command-injection


def run_cmd():
    cmd = request.args.get("cmd")
    subprocess.run(cmd, shell=True)  # EXPECT command-injection


def list_dir():
    path = request.args.get("path")
    os.popen("ls " + path)  # EXPECT command-injection


# --- SSRF ---
def proxy():
    url = request.args.get("url")
    return requests.get(url)  # EXPECT ssrf


def fetch():
    url = request.args.get("url")
    return urllib.request.urlopen(url)  # EXPECT ssrf


# --- Path traversal ---
def read_file():
    name = request.args.get("file")
    with open(name) as f:  # EXPECT path-traversal
        return f.read()


def read_joined():
    name = request.args.get("file")
    return open(os.path.join("/data", name)).read()  # EXPECT path-traversal


# --- Server-side template injection ---
def render():
    tmpl = request.args.get("template")
    return render_template_string(tmpl)  # EXPECT ssti
