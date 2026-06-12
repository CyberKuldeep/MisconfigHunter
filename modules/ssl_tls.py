import ssl
import socket
from urllib.parse import urlparse
from datetime import datetime

class SSLTLSScanner:

    def scan(self, scanner):

        try:
            hostname = urlparse(scanner.target).hostname

            context = ssl.create_default_context()

            with socket.create_connection((hostname, 443), timeout=10) as sock:
                with context.wrap_socket(
                    sock,
                    server_hostname=hostname
                ) as ssock:

                    cert = ssock.getpeercert()

                    expire_date = datetime.strptime(
                        cert["notAfter"],
                        "%b %d %H:%M:%S %Y %Z"
                    )

                    days_left = (
                        expire_date - datetime.utcnow()
                    ).days

                    if days_left < 30:
                        scanner.add_finding(
                            title="SSL Certificate Near Expiry",
                            severity="Medium",
                            affected_url=scanner.target,
                            description="Certificate expires soon.",
                            impact="Service trust may be affected.",
                            recommendation="Renew certificate.",
                            evidence=f"{days_left} days remaining"
                        )

        except Exception as e:
            scanner.add_finding(
                title="SSL/TLS Validation Error",
                severity="Low",
                affected_url=scanner.target,
                description="Unable to validate SSL configuration.",
                impact="Manual review recommended.",
                recommendation="Verify TLS settings.",
                evidence=str(e)
            )
