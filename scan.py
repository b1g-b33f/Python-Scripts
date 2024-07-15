#!/usr/bin/python3

import os
import subprocess
import requests
import time
import pyautogui
from datetime import date

# ANSI escape codes for colored output
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
BLUE = "\033[94m"
CYAN = "\033[96m"
BRIGHT_GREEN = "\033[92m"
BRIGHT_CYAN = "\033[96m"
RESET = "\033[0m"

# Configuration
PROXIES = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
WORDLIST = "/usr/share/wordlists/dirb/big.txt"
SUBDOMAIN_WORDLIST = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
TESTSSL_CMD_TEMPLATE = "/home/b33f/scripts/bash/testssl/testssl.sh {}://{}:{}"
CLICKJACK_CMD_TEMPLATE = "python3 /home/b33f/scripts/python/clickjack/clickjack.py {}://{}:{}"
LOG_DIR_TEMPLATE = "logs/{}"
LOG_FILE_TEMPLATE = "{}/{}_{}.log"

def run_command(desc, cmd, log_file):
    """Run a command and log its output."""
    with open(log_file, 'a') as f:
        f.write(f"\n{BRIGHT_GREEN}{'='*10} RUNNING: {desc} {'='*10}{RESET}\n")
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            out, _ = process.communicate(timeout=300)  # Timeout after 5 minutes
        except subprocess.TimeoutExpired:
            process.kill()
            out, _ = process.communicate()
            f.write(f"{RED}Command timed out.{RESET}\n")
        output = out.decode('utf-8')
        f.write(output)
        f.write(f"\n{BRIGHT_CYAN}{'='*10} COMPLETED: {desc} {'='*10}{RESET}\n\n")
    return output

def clickjack_test(cmd, log_dir, log_file):
    """Run clickjacking test and take a screenshot."""
    print(f"{YELLOW}Running Clickjacking Test and taking a screenshot in 5 seconds...{RESET}")
    with open(log_file, 'a') as f:
        f.write(f"\n{BRIGHT_GREEN}{'='*10} RUNNING: Clickjacking Test {'='*10}{RESET}\n")
    subprocess.Popen(cmd, shell=True)
    time.sleep(5)  # Wait for 5 seconds
    screenshot_path = f"{log_dir}/clickjack_screenshot.png"
    try:
        pyautogui.screenshot(screenshot_path)
        with open(log_file, 'a') as f:
            f.write(f"{GREEN}Screenshot taken and saved to {screenshot_path}{RESET}\n")
        print(f"{GREEN}Screenshot taken and saved to {screenshot_path}{RESET}")
    except Exception as e:
        error_message = f"{RED}Failed to take screenshot: {e}{RESET}"
        with open(log_file, 'a') as f:
            f.write(error_message)
        print(error_message)
    with open(log_file, 'a') as f:
        f.write(f"\n{BRIGHT_CYAN}{'='*10} COMPLETED: Clickjacking Test {'='*10}{RESET}\n\n")

def ping_target(target):
    """Ping the target to check if it is up."""
    return subprocess.call(f"ping -c 1 {target}", shell=True) == 0

def check_target_reachable(target_url):
    """Check if the target is reachable on the specified URL."""
    try:
        with requests.get(target_url, proxies=PROXIES, verify=False) as response:
            return True
    except Exception:
        return False

def gather_headers_and_cookies(target_url, log_file, proxies):
    """Gather headers and cookies from the target and log them."""
    with open(log_file, 'a') as f:
        f.write(f"\n{BRIGHT_GREEN}{'='*10} GATHERING HEADERS AND COOKIES {'='*10}{RESET}\n")
    with requests.get(target_url, proxies=PROXIES, verify=False) as resp:
        with open(log_file, 'a') as f:
            f.write("\nHEADERS\n")
            for header, value in resp.headers.items():
                if header.upper() == 'CONTENT-SECURITY-POLICY':
                    csp = value.split(";")
                    f.write(f"{header}\n")
                    for c in csp:
                        f.write(f"\t{c}\n")
                else:
                    f.write(f"{header} : {value}\n")
            f.write("\nCOOKIES\n")
            for cookie, value in resp.cookies.items():
                f.write(f"{cookie} : {value}\n")
    with open(log_file, 'a') as f:
        f.write(f"\n{BRIGHT_CYAN}{'='*10} COMPLETED: GATHERING HEADERS AND COOKIES {'='*10}{RESET}\n\n")
    print(f"{GREEN}Headers and cookies have been logged.{RESET}")

def scan_internal_subdomains(target, protocol, port, log_dir):
    """Scan for internal subdomains using a brute-force approach."""
    subdomain_list = "/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    subdomain_file = f"{log_dir}/subdomains.txt"
    with open(f"{log_dir}/subdomains_results.txt", 'w') as f:
        f.write(f"{BRIGHT_GREEN}{'='*10} SCANNING INTERNAL SUBDOMAINS {'='*10}{RESET}\n")
        cmd = f"ffuf -u {protocol}://{{}}.{target}:{port} -w {subdomain_list} -H 'Host: FUZZ.{target}' -o {subdomain_file} -x http://127.0.0.1:8080"
        process = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        try:
            out, _ = process.communicate(timeout=300)  # Timeout after 5 minutes
        except subprocess.TimeoutExpired:
            process.kill()
            out, _ = process.communicate()
            f.write(f"{RED}Command timed out.{RESET}\n")
        output = out.decode('utf-8')
        f.write(output)
        f.write(f"\n{BRIGHT_CYAN}{'='*10} COMPLETED: SCANNING INTERNAL SUBDOMAINS {'='*10}{RESET}\n\n")
    print(f"{GREEN}Internal subdomains have been scanned and saved to {subdomain_file}{RESET}")

def main():
    if os.geteuid() != 0:
        exit(f"{RED}run as sudo{RESET}")

    # Prompt user for target website and port
    target = input(f"{BLUE}Enter the target website: {RESET}").replace('http://', '').replace('https://', '').split('/')[0].split(':')[0]
    port = input(f"{BLUE}Enter the port (default is 443): {RESET}") or "443"
    protocol = input(f"{BLUE}Enter the protocol (http or https, default is https): {RESET}").lower() or "https"

    if protocol not in ["http", "https"]:
        exit(f"{RED}Invalid protocol. Please enter 'http' or 'https'.{RESET}")

    target_url = f"{protocol}://{target}:{port}"

    # Create log directory and file for the target
    log_dir = LOG_DIR_TEMPLATE.format(target)
    os.makedirs(log_dir, exist_ok=True)
    log_file = LOG_FILE_TEMPLATE.format(log_dir, date.today().strftime('%Y%m%d'), target)

    # Define the commands
    testssl_cmd = TESTSSL_CMD_TEMPLATE.format(protocol, target, port) if protocol == "https" else None
    clickjack_cmd = CLICKJACK_CMD_TEMPLATE.format(protocol, target, port)

    cmds = [
        ("Full Nmap Scan", f"nmap -T4 -A -vv -Pn {target}"),
        ("Nmap Auth Scripts", f"nmap -p {port} --script http-auth,http-auth-finder {target}"),
        ("Nmap Site Map Generator", f"nmap -p {port} --script http-sitemap-generator {target}"),
        ("Nmap Stored XSS Scan", f"nmap -p {port} --script http-stored-xss {target}"),
        ("Nikto Web Scanner", f"nikto -p {port} -h {target}"),
        ("Scan Internal Subdomains", f"ffuf -u {protocol}://{{}}.{target}:{port} -w {SUBDOMAIN_WORDLIST} -H 'Host: FUZZ.{target}' -o {log_dir}/subdomains_results.txt -x http://127.0.0.1:8080"),
        ("CURL - Check Images Directory", f"curl -k {target_url}/Images"),
        ("CURL - Check lowercase images Directory", f"curl -k {target_url}/images"),
        ("CURL - Check Random Path", f"curl -k {target_url}/asdf"),
        ("Run FFUF Directory Brute Force", f"ffuf -w {WORDLIST} -u {target_url}/FUZZ -ic -e .php,.asp,.js,.xml,.conf,.bak -recursion -recursion-depth 1 -x {PROXIES['http']} -o {log_dir}/ffuf_results.txt"),
        ("Run TESTSSL", testssl_cmd),
        ("Run Clickjacking Test", clickjack_cmd),
        ("Gather Headers and Cookies", "headers_and_cookies")
    ]

    # Display options to the user
    print(f"{YELLOW}Select the commands to run (separate choices with commas) or type 'all' to run everything:{RESET}")
    for i, (desc, _) in enumerate(cmds, start=1):
        color = CYAN if i % 2 == 0 else GREEN  # Alternate colors
        print(f"{color}{i}: {desc}{RESET}")

    selected_options = input(f"{BLUE}Your choice: {RESET}")

    # Determine which commands to run
    run_all = selected_options.lower() == "all"
    if run_all:
        skip_nikto = input(f"{YELLOW}Do you want to skip the Nikto scan? (yes/no): {RESET}").strip().lower() == "yes"
        selected_cmds = [(desc, cmd) for desc, cmd in cmds if not (skip_nikto and "Nikto" in desc)]
    else:
        selected_cmds = [(desc, cmd) for i, (desc, cmd) in enumerate(cmds, start=1) if str(i) in selected_options.split(",")]

    # Ping the target to check if it is up
    print(f"{YELLOW}Pinging the target {target}...{RESET}")
    if not ping_target(target):
        exit(f"{RED}Target is not reachable. Exiting.{RESET}")
    print(f"{GREEN}Ping successful. Target is up.{RESET}")

    # Check if the target is reachable at the given URL
    print(f"{YELLOW}Checking if the target is reachable at {target_url}...{RESET}")
    if not check_target_reachable(target_url):
        exit(f"{RED}Target is not reachable at {target_url}. Exiting.{RESET}")
    print(f"{GREEN}Target is reachable at {target_url}.{RESET}")

    # Run the selected commands
    for desc, cmd in selected_cmds:
        if desc == "Gather Headers and Cookies":
            gather_headers_and_cookies(target_url, log_file, PROXIES)
        elif desc == "Scan Internal Subdomains":
            scan_internal_subdomains(target, protocol, port, log_dir)
        elif protocol == "http" and desc == "Run TESTSSL":
            print(f"{YELLOW}Skipping {desc} because the protocol is http.{RESET}")
            continue
        else:
            print(f"{YELLOW}Running command: {desc}{RESET}")
            run_command(desc, cmd, log_file)

    # Run clickjacking test and take a screenshot
    clickjack_test(clickjack_cmd, log_dir, log_file)

if __name__ == "__main__":
    main()




