class SecurityHeadersScanner:

    REQUIRED_HEADERS = {
        "X-Frame-Options":
            "Protects against clickjacking attacks.",

        "X-Content-Type-Options":
            "Prevents MIME type sniffing.",

        "Content-Security-Policy":
            "Reduces XSS and content injection risks.",

        "Strict-Transport-Security":
            "Forces HTTPS connections.",

        "Referrer-Policy":
            "Controls referrer information leakage.",

        "Permissions-Policy":
            "Restricts browser features."
    }

    def scan(self, scanner):

        response = scanner.request_handler.get(
            scanner.target
        )

        if not response:
            return

        headers = response.headers

        for header, impact in self.REQUIRED_HEADERS.items():

            if header not in headers:

                scanner.add_finding(
                    title=f"Missing {header}",
                    severity="Medium",
                    affected_url=scanner.target,
                    description=f"{header} header is missing.",
                    impact=impact,
                    recommendation=f"Configure {header} header.",
                    evidence="Header not present in HTTP response."
                )
