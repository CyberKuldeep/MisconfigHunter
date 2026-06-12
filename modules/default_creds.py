class DefaultCredsScanner:

    def __init__(self):

        self.panels = [
            "/admin",
            "/login",
            "/wp-admin",
            "/phpmyadmin",
            "/jenkins",
            "/grafana"
        ]

    def scan(self, scanner):

        for panel in self.panels:

            url = scanner.target.rstrip("/") + panel

            response = scanner.request_handler.get(url)

            if not response:
                continue

            if response.status_code == 200:

                scanner.add_finding(
                    title="Administrative Interface Detected",
                    severity="Info",
                    affected_url=url,
                    description="Administrative portal discovered.",
                    impact="Administrative interfaces should be reviewed.",
                    recommendation="Restrict exposure where appropriate.",
                    evidence=f"HTTP {response.status_code}"
                )
