import argparse
import sys
from datetime import datetime
from termcolor import colored
from scans.ip_scan import ip_scan
from scans.domain_scan import domain_scan
from scans.url_scan import url_scan
from scans.hash_scan import hash_scan
from scans.email_scan import email_scan
from scans.account_scan import account_scan
import io
import contextlib

log_file = None

def init_logger(path):
    global log_file
    log_file = open(path, "a", encoding="utf-8")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_file.write(f"[Scan started at {timestamp}]\n\n")

def log(message):
    if log_file:
        log_file.write(message + "\n")

def close_logger():
    if log_file:
        end_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_file.write(f"\n[Scan ended at {end_time}]\n")
        log_file.close()

def print_and_log(text, color=None):
    msg = colored(text, color) if color else text
    print(msg)
    log(text)


def print_banner():
    print("")
    print(colored(' ██████╗ ███████╗██╗███╗   ██╗████████╗██████╗ ██╗   ██╗', 'red'))
    print(colored('██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝', 'red'))
    print(colored('██║   ██║███████╗██║██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝', 'red'))
    print(colored('██║   ██║╚════██║██║██║╚██╗██║   ██║   ██╔═══╝   ╚██╔╝  ', 'red'))
    print(colored('╚██████╔╝███████║██║██║ ╚████║   ██║██╗██║        ██║   ', 'red'))
    print(colored(' ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝╚═╝╚═╝        ╚═╝   ', 'red'))
    print(colored('Ver 0.4.0, Brought to you by Luke McKeever', 'blue'))
    print("")


def run_scan(args):
    if args.ip:
        ip_scan(args.ip)
    elif args.domain:
        domain_scan(args.domain)
    elif args.url:
        url_scan(args.url)
    elif args.hash:
        hash_scan(args.hash)
    elif args.email:
        email_scan(args.email)
    elif args.account:
        account_scan(args.account)
    else:
        print(colored("Please provide an IOC to scan. Use --help for options.", "yellow"))

def main():
    parser = argparse.ArgumentParser(description="IOC Scanner - OSINT Tool")
    group = parser.add_mutually_exclusive_group()

    group.add_argument('-ip', metavar='IP', help='Scan an IP address')
    group.add_argument('-domain', metavar='DOMAIN', help='Scan a domain')
    group.add_argument('-url', metavar='URL', help='Scan a full URL')
    group.add_argument('-hash', metavar='HASH', help='Scan a file hash')
    group.add_argument('-email', metavar='EMAIL', help='Scan an email address')
    group.add_argument('-account', metavar='ACCOUNT', help='Scan an account/username (coming soon)')

    parser.add_argument('-output', nargs='?', const=True, metavar='FILE', help='Save scan output to text file')

    args = parser.parse_args()

    print_banner()
    run_scan(args)

    # If --output is provided, capture and log plain output
    if args.output:
        print("")
        print('[>] Outputting Scan Results to: ', colored(args.output, 'blue'))
        if isinstance(args.output, str):
            output_file = args.output
        else:
            timestamp = datetime.now().strftime("scan_%Y-%m-%d_%H%M%S.txt")
            output_file = timestamp

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            run_scan(args)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(f"[Scan started at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}]\n\n")
            f.write(buffer.getvalue())

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(colored("\n[!] Script interrupted by user.", "yellow"))
        sys.exit(0)