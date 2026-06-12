class ExposedFilesScanner:

    def __init__(self):

        self.files = [
            "/robots.txt",
            "/sitemap.xml",
            "/security.txt"
        ]

    def scan(self, scanner):

        for file_path in self.files:

            url = scanner.target.rstrip("/") + file_path

            response = scanner.request_handler.get(url)

            if not response:
                continue

            if response.status_code == 200:

                scanner.add_finding(
                    title="Publicly Accessible File",
                    severity="Info",
                    affected_url=url,
                    description="Public file detected.",
                    impact="May reveal application information.",
                    recommendation="Review file contents.",
                    evidence=f"HTTP {response.status_code}"
                )
