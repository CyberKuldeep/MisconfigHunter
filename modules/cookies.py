class CookieScanner:

    def scan(self, scanner):

        response = scanner.request_handler.get(
            scanner.target
        )

        if not response:
            return

        cookies = response.cookies

        if not cookies:
            return

        for cookie in cookies:

            cookie_name = cookie.name

            secure = cookie.secure

            httponly = (
                "HttpOnly"
                in str(response.headers.get(
                    "Set-Cookie",
                    ""
                ))
            )

            samesite = (
                "SameSite"
                in str(response.headers.get(
                    "Set-Cookie",
                    ""
                ))
            )

            if not secure:

                scanner.add_finding(
                    title=f"Cookie Missing Secure Flag ({cookie_name})",
                    severity="Medium",
                    affected_url=scanner.target,
                    description=(
                        "Cookie transmitted without "
                        "Secure attribute."
                    ),
                    impact=(
                        "Cookie may be exposed over "
                        "unencrypted channels."
                    ),
                    recommendation=(
                        "Enable Secure flag."
                    ),
                    evidence="Secure=False"
                )

            if not httponly:

                scanner.add_finding(
                    title=f"Cookie Missing HttpOnly Flag ({cookie_name})",
                    severity="Medium",
                    affected_url=scanner.target,
                    description="HttpOnly attribute missing.",
                    impact=(
                        "Client-side scripts may access "
                        "session cookies."
                    ),
                    recommendation="Enable HttpOnly flag.",
                    evidence="HttpOnly=False"
                )

            if not samesite:

                scanner.add_finding(
                    title=f"Cookie Missing SameSite ({cookie_name})",
                    severity="Low",
                    affected_url=scanner.target,
                    description="SameSite attribute missing.",
                    impact=(
                        "Cross-site request risks may increase."
                    ),
                    recommendation="Set SameSite=Lax or Strict.",
                    evidence="SameSite=False"
                )
