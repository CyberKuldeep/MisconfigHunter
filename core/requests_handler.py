import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class RequestHandler:

    def __init__(self):
        self.headers = {
            "User-Agent":
            "MisconfigHunter/1.0 Security Scanner"
        }

        self.timeout = 10

    def get(self, url):
        try:
            response = requests.get(
                url,
                headers=self.headers,
                timeout=self.timeout,
                verify=False,
                allow_redirects=True
            )

            return response

        except Exception as e:
            print(f"[ERROR] GET {url} : {e}")
            return None

    def options(self, url):
        try:
            response = requests.options(
                url,
                headers=self.headers,
                timeout=self.timeout,
                verify=False
            )

            return response

        except Exception as e:
            print(f"[ERROR] OPTIONS {url} : {e}")
            return None

    def head(self, url):
        try:
            response = requests.head(
                url,
                headers=self.headers,
                timeout=self.timeout,
                verify=False
            )

            return response

        except Exception as e:
            print(f"[ERROR] HEAD {url} : {e}")
            return None
