from datetime import datetime
from urllib.parse import urlparse
import os

def get_timestamp():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url

def get_domain(url):
    return urlparse(url).netloc.replace(":", "_")

def create_output_directory(domain):
    path = os.path.join("output", domain)

    if not os.path.exists(path):
        os.makedirs(path)

    return path

SEVERITY_SCORE = {
    "Critical": 10,
    "High": 7,
    "Medium": 5,
    "Low": 2,
    "Info": 1
}
