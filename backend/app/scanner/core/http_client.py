"""Thin wrapper around requests with sane defaults for scanning."""
import requests

DEFAULT_HEADERS = {
    "User-Agent": "WebVAPT-Scanner/1.0 (educational-use; local-testing-only)"
}


class HttpClient:
    def __init__(self, timeout=6):
        self.session = requests.Session()
        self.session.headers.update(DEFAULT_HEADERS)
        self.timeout = timeout

    def get(self, url, **kwargs):
        return self.session.get(url, timeout=self.timeout, **kwargs)

    def post(self, url, data=None, **kwargs):
        return self.session.post(url, data=data, timeout=self.timeout, **kwargs)
