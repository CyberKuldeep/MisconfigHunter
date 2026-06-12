class HTTPMethodsScanner:

    DANGEROUS_METHODS = [
        "PUT",
        "DELETE",
        "TRACE",
        "CONNECT"
    ]

    def scan(self, scanner):

        response = scanner.request_handler.options(
            scanner.target
        )

        if not response:
            return

        allow_header = response.headers.get(
            "Allow",
            ""
        )

        methods = [
            m.strip().upper()
            for m in allow_header.split(",")
            if m.strip()
        ]

        for method in methods:

            if method in self.DANGEROUS_METHODS:

                scanner.add_finding(
                    title=f"Dangerous HTTP Method: {method}",
                    severity="Medium",
                    affected_url=scanner.target,
                    description=(
                        f"{method} method is allowed "
                        "by the server."
                    ),
                    impact=(
                        "Unnecessary methods can "
                        "increase attack surface."
                    ),
                    recommendation=(
                        "Disable unused HTTP methods."
                    ),
                    evidence=f"Allow: {allow_header}"
                )
