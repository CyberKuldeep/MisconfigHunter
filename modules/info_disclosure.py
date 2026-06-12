class InformationDisclosureScanner:

    def scan(self, scanner):

        response = scanner.request_handler.get(
            scanner.target
        )

        if not response:
            return

        server = response.headers.get("Server")

        if server:

            scanner.add_finding(
                title="Server Version Disclosure",
                severity="Low",
                affected_url=scanner.target,
                description=(
                    "Server banner exposed in response."
                ),
                impact=(
                    "Technology fingerprinting becomes easier."
                ),
                recommendation=(
                    "Remove or minimize Server header."
                ),
                evidence=server
            )

        powered_by = response.headers.get(
            "X-Powered-By"
        )

        if powered_by:

            scanner.add_finding(
                title="Technology Disclosure",
                severity="Low",
                affected_url=scanner.target,
                description=(
                    "Backend technology exposed."
                ),
                impact=(
                    "May assist targeted attacks."
                ),
                recommendation=(
                    "Remove X-Powered-By header."
                ),
                evidence=powered_by
            )
