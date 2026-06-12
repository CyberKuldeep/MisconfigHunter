import argparse
from core.scanner import MisconfigScanner

def banner():
    print("=" * 60)
    print("           MisconfigHunter v1.0")
    print("     Security Misconfiguration Scanner")
    print("=" * 60)

def main():
    banner()

    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    args = parser.parse_args()

    scanner = MisconfigScanner(args.url)
    scanner.run()

if __name__ == "__main__":
    main()
