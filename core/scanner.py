from modules.security_headers import SecurityHeadersScanner
from modules.open_directory import OpenDirectoryScanner
from modules.http_methods import HTTPMethodsScanner
from core.requests_handler import RequestHandler
from core.utils import (
    normalize_url,
    get_domain,
    create_output_directory,
    get_timestamp
)

class MisconfigScanner:

    def __init__(self, target):

        self.target = normalize_url(target)

        self.domain = get_domain(self.target)

        self.output_dir = create_output_directory(
            self.domain
        )

        self.request_handler = RequestHandler()

        self.findings = []

    def add_finding(
        self,
        title,
        severity,
        affected_url,
        description,
        impact,
        recommendation,
        evidence
    ):

        finding = {
            "title": title,
            "severity": severity,
            "affected_url": affected_url,
            "description": description,
            "impact": impact,
            "recommendation": recommendation,
            "evidence": evidence
        }

        self.findings.append(finding)

    def basic_connectivity_check(self):

        print(f"\n[*] Checking target: {self.target}")

        response = self.request_handler.get(
            self.target
        )

        if not response:
            print("[!] Target unreachable")
            return False

        print(
            f"[+] Connected "
            f"(HTTP {response.status_code})"
        )

        return True

    def save_raw_response(self):

        response = self.request_handler.get(
            self.target
        )

        if not response:
            return

        file_path = (
            f"{self.output_dir}/raw_response.html"
        )

        with open(
            file_path,
            "w",
            encoding="utf-8"
        ) as f:
            f.write(response.text)

        print(
            f"[+] Raw response saved: "
            f"{file_path}"
        )

    def show_summary(self):

        print("\n" + "=" * 60)
        print("SCAN SUMMARY")
        print("=" * 60)

        print(f"Target      : {self.target}")
        print(f"Scan Time   : {get_timestamp()}")
        print(f"Findings    : {len(self.findings)}")

        print("=" * 60)

    def run(self):

        print(f"\n[*] Output Directory")
        print(f"    {self.output_dir}")

        if not self.basic_connectivity_check():
            return

        self.save_raw_response()

        # Modules will be added here later
        #
        # security_headers.scan()
        # open_directory.scan()
        # cookies.scan()
        # ssl_tls.scan()
        #
        # etc.

        self.show_summary()
