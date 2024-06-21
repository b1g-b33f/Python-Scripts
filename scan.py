#!/usr/bin/python3

import sys
import requests
import subprocess
from datetime import date

# Validate the site input
site = sys.exit() if len(sys.argv) != 2 else sys.argv[1].replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
log = f"logs/{date.isoformat(date.today()).replace('-', '')}_{site}.log"
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
cmds = [
    f"nmap -T4 -A -vv -Pn {site}",
    f"nmap -p 443,3389 --script ssl-enum-ciphers {site}",
    f"nmap -p 443 --script http-auth,http-auth-finder {site}",
    f"nikto -p 443 -h {site}",
    f"hping3 -S {site} -c 15 -p 443",
    f"curl -k https://{site}/Images",
    f"curl -k https://{site}/images",
    f"curl -k https://{site}/asdf",
    f"nmap -p 443 --script http-sitemap-generator {site}",
    f"script -c '/home/kaliuser/scripts/bash/testssl/testssl.sh https://{site}' -q /dev/null", 
    f"gobuster vhost -u https://{site} -w /usr/share/wordlists/SecLists/Discovery/DNS/subdomains-top1million-5000.txt --proxy http://127.0.0.1:8080 -k"
]

with open(log, 'a') as f:
    for cmd in cmds:
        print(f"RUNNING: {cmd}")
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out, _ = process.communicate()
        f.write(f"\n\nRUNNING: {cmd}\n{out.decode('utf-8')}\n")

    # Make a request to the site and log headers and cookies
    resp = requests.get(f"https://{site}", proxies=proxies, verify=False)
    headers = resp.headers

    f.write("\nHEADERS\n")
    for header in headers:
        if header.upper() == 'CONTENT-SECURITY-POLICY':
            csp = headers[header].split(";")
            f.write(f"{header}\n")
            for c in csp:
                f.write(f"\t{c}\n")
        else:
            f.write(f"{header} : {headers[header]}\n")

    cookies = resp.cookies
    f.write("\nCOOKIES\n")
    for cookie in cookies.get_dict():
        f.write(f"{cookie} : {cookies.get_dict()[cookie]}\n")
