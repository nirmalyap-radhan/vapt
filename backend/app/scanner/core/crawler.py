"""Very small same-origin crawler: discovers links and HTML forms."""
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup


class Crawler:
    def __init__(self, client, base_url, max_pages=25):
        self.client = client
        self.base_url = base_url.rstrip("/")
        self.origin = urlparse(base_url).netloc
        self.max_pages = max_pages
        self.visited = set()
        self.pages = {}   # url -> response text
        self.forms = []   # list of dicts: {url, method, action, inputs}

    def _same_origin(self, url):
        return urlparse(url).netloc in ("", self.origin)

    def crawl(self, start_path="/"):
        queue = [urljoin(self.base_url, start_path)]
        while queue and len(self.visited) < self.max_pages:
            url = queue.pop(0)
            if url in self.visited:
                continue
            self.visited.add(url)
            try:
                resp = self.client.get(url)
            except Exception:
                continue
            if "text/html" not in resp.headers.get("Content-Type", ""):
                continue
            self.pages[url] = resp
            soup = BeautifulSoup(resp.text, "html.parser")

            # collect links
            for a in soup.find_all("a", href=True):
                link = urljoin(url, a["href"])
                link = link.split("#")[0]
                if self._same_origin(link) and link not in self.visited:
                    queue.append(link)

            # collect forms
            for form in soup.find_all("form"):
                action = urljoin(url, form.get("action") or url)
                method = (form.get("method") or "GET").upper()
                inputs = []
                for inp in form.find_all(["input", "textarea"]):
                    name = inp.get("name")
                    if not name:
                        continue
                    itype = inp.get("type", "text")
                    inputs.append({"name": name, "type": itype})
                self.forms.append({
                    "page": url,
                    "url": action,
                    "method": method,
                    "inputs": inputs,
                })
        return self.pages, self.forms
