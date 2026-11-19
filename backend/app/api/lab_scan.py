from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
from app.scanner.core.http_client import HttpClient
from app.scanner.core.crawler import Crawler
from app.scanner.core.finding import sort_findings
from app.scanner.checks import sqli, xss, csrf, headers as headers_check, auth, idor

router = APIRouter()


class LabScanRequest(BaseModel):
    url: str
    max_pages: int = 15


@router.post("/lab")
def run_lab_scan(payload: LabScanRequest):
    """
    Run active OWASP-style checks (SQLi, XSS, CSRF, IDOR, Headers, Auth)
    against an authorized lab/test target.

    LEGAL NOTICE: Only use against targets you own or have explicit
    written permission to test. Unauthorized scanning is illegal.
    """
    try:
        client = HttpClient(timeout=8)
        crawler = Crawler(client, payload.url, max_pages=payload.max_pages)
        pages, forms = crawler.crawl()

        all_findings = []
        all_findings += sqli.run(client, forms)
        all_findings += xss.run(client, forms)
        all_findings += auth.run(client, forms)
        all_findings += idor.run(client, pages)

        cookies_samesite_ok = True
        for url, resp in pages.items():
            all_findings += headers_check.check_headers(url, resp)
            all_findings += headers_check.check_debug_and_errors(url, resp)
            sc = resp.headers.get("Set-Cookie", "")
            if sc and "samesite" not in sc.lower():
                cookies_samesite_ok = False

        all_findings += csrf.run(client, forms, cookies_samesite_ok)

        dedup = {}
        for f in all_findings:
            dedup[(f.title, f.url)] = f
        all_findings = sort_findings(list(dedup.values()))

        severity_counts = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in all_findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        return {
            "target_url": payload.url,
            "pages_crawled": len(pages),
            "forms_tested": len(forms),
            "total_findings": len(all_findings),
            "severity_counts": severity_counts,
            "findings": [f.to_dict() for f in all_findings],
            "disclaimer": "Automated scanner results require manual verification. For authorized use only.",
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Lab scan error: {str(e)}")

