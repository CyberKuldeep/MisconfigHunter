class OpenDirectoryScanner:

    DIRECTORY_PATTERNS = [
        "Index of /",
        "Parent Directory",
        "Directory Listing For",
        "Directory listing"
    ]

    def scan(self, scanner):

        response = scanner.request_handler.get(
            scanner.target
        )

        if not response:
            return

        body = response.text

        for pattern in self.DIRECTORY_PATTERNS:

            if pattern.lower() in body.lower():

                scanner.add_finding(
                    title="Directory Listing Enabled",
                    severity="Medium",
                    affected_url=scanner.target,
                    description=(
                        "Directory listing appears enabled."
                    ),
                    impact=(
                        "Attackers may browse files and "
                        "discover sensitive information."
                    ),
                    recommendation=(
                        "Disable directory indexing "
                        "on the web server."
                    ),
                    evidence=pattern
                )

                return
