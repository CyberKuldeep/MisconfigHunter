from modules.security_headers import SecurityHeadersScanner
from modules.open_directory import OpenDirectoryScanner
from modules.http_methods import HTTPMethodsScanner
from core.requests_handler import RequestHandler
from modules.cookies import CookieScanner
from modules.info_disclosure import InformationDisclosureScanner
from reports.json_report import JSONReportGenerator
from reports.html_report import HTMLReportGenerator
from reports.pdf_report import PDFReportGenerator
from core.utils import SEVERITY_SCORE
from core.utils import (
    normalize_url,
    get_domain,
    create_output_directory,
    get_timestamp
)

class MisconfigScanner:

    def __init__(self, target):

        self.html_report = (
    HTMLReportGenerator()
)

self.pdf_report = (
    PDFReportGenerator()
)

        self.security_headers = SecurityHeadersScanner()

        self.open_directory = OpenDirectoryScanner()

        self.http_methods = HTTPMethodsScanner()

        self.target = normalize_url(target)

        self.domain = get_domain(self.target)

        self.output_dir = create_output_directory(
            self.domain
        )

        self.cookies = CookieScanner()

self.info_disclosure = (
    InformationDisclosureScanner()
)

self.json_report = (
    JSONReportGenerator()
)

def generate_reports(self):

    print(
        "\n[*] Generating Reports..."
    )

    json_report = (
        self.json_report.generate(
            self.findings,
            self.target,
            self.output_dir
        )
    )

    html_report = (
        self.html_report.generate(
            self.findings,
            self.target,
            self.output_dir
        )
    )

    pdf_report = (
        self.pdf_report.generate(
            self.findings,
            self.target,
            self.output_dir
        )
    )

    print(
        f"[+] JSON : {json_report}"
    )

    print(
        f"[+] HTML : {html_report}"
    )

    print(
        f"[+] PDF  : {pdf_report}"
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

def calculate_risk_score(self):

    score = 0

    for finding in self.findings:

        score += SEVERITY_SCORE.get(
            finding["severity"],
            0
        )

    return score


    def run(self):

    print(f"\n[*] Output Directory")
    print(f"    {self.output_dir}")

    if not self.basic_connectivity_check():
        return

    self.save_raw_response()

    print("\n[*] Running Security Headers Scan")
    self.security_headers.scan(self)

    print("[*] Running Directory Listing Scan")
    self.open_directory.scan(self)

    print("[*] Running HTTP Methods Scan")
    self.http_methods.scan(self)


     def show_summary(self):

    print("\n" + "=" * 60)

    print("SCAN SUMMARY")

    print("=" * 60)

    risk_score = (
        self.calculate_risk_score()
    )

    print(
        f"Target      : "
        f"{self.target}"
    )

    print(
        f"Findings    : "
        f"{len(self.findings)}"
    )

    print(
        f"Risk Score  : "
        f"{risk_score}"
    )

    print()

    for finding in self.findings:

        print(
            f"[{finding['severity']}] "
            f"{finding['title']}"
        )

    print("=" * 60)

    self.show_summary()

    

        # Modules will be added here later
        #
        # security_headers.scan()
        # open_directory.scan()
        # cookies.scan()
        # ssl_tls.scan()
        #
        # etc.

        self.show_summary()
