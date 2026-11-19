import os
from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import FileResponse
from sqlalchemy.orm import Session
from typing import Optional

from app.db.database import get_db
from app.db.models import ScanHistory, User
from app.schemas.scan import ScanRequest
from app.services.full_scanner import run_full_scan
from app.services.header_scanner import scan_security_headers
from app.services.cookie_scanner import scan_cookies
from app.services.ssl_scanner import scan_ssl_tls
from app.services.port_scanner import scan_open_ports
from app.services.dns_scanner import analyze_dns_security
from app.services.technology_scanner import scan_technologies
from app.services.pdf_report import generate_pdf_report
from app.core.security import decode_token
from fastapi.security import OAuth2PasswordBearer

router = APIRouter()
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/login", auto_error=False)


def get_optional_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> Optional[User]:
    if not token:
        return None
    payload = decode_token(token)
    if not payload:
        return None
    username = payload.get("sub")
    if not username:
        return None
    return db.query(User).filter(User.username == username).first()


def save_scan_to_db(db, user, url, scan_type, result):
    score_data = result.get("security_score", {})
    score = score_data.get("score") if isinstance(score_data, dict) else None
    risk_level = score_data.get("risk_level") if isinstance(score_data, dict) else None
    ai_summary = result.get("ai_analysis", {}).get("executive_summary", "")
    scan = ScanHistory(
        user_id=user.id if user else None,
        target_url=url,
        scan_type=scan_type,
        score=score,
        risk_level=risk_level,
        results={"summary": str(ai_summary)[:500]},
    )
    db.add(scan)
    db.commit()
    db.refresh(scan)
    return scan


@router.post("/full")
async def full_scan(
    payload: ScanRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    try:
        result = await run_full_scan(url=str(payload.url))
        save_scan_to_db(db, current_user, str(payload.url), "full", result)

        # Serialize pydantic objects in headers/cookies
        def serialize(obj):
            if hasattr(obj, "model_dump"):
                return obj.model_dump()
            if hasattr(obj, "dict"):
                return obj.dict()
            return obj

        result["headers"] = serialize(result["headers"])
        result["cookies"]["findings"] = [serialize(f) for f in result["cookies"]["findings"]]
        return result
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Scan error: {str(e)}")


@router.post("/headers")
async def headers_scan(payload: ScanRequest):
    try:
        result = await scan_security_headers(url=str(payload.url))
        return result.model_dump()
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/cookies")
async def cookies_scan(payload: ScanRequest):
    try:
        findings = await scan_cookies(url=str(payload.url))
        return {"target_url": str(payload.url), "findings": [f.model_dump() for f in findings]}
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/ssl")
def ssl_scan(payload: ScanRequest):
    try:
        return scan_ssl_tls(url=str(payload.url))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/ports")
def ports_scan(payload: ScanRequest):
    try:
        return scan_open_ports(url=str(payload.url))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/dns")
def dns_scan(payload: ScanRequest):
    try:
        return analyze_dns_security(url=str(payload.url))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/technologies")
async def tech_scan(payload: ScanRequest):
    try:
        return await scan_technologies(url=str(payload.url))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.post("/report")
async def generate_report(
    payload: ScanRequest,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_user),
):
    try:
        result = await run_full_scan(url=str(payload.url))
        save_scan_to_db(db, current_user, str(payload.url), "report", result)
        os.makedirs("reports", exist_ok=True)
        filename = "reports/VAPTProX_Report.pdf"
        path = generate_pdf_report(scan_data=result, filename=filename)
        return FileResponse(path, media_type="application/pdf", filename="VAPTProX_Report.pdf")
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Report error: {str(e)}")
