from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from typing import List
from app.db.database import get_db
from app.db.models import ScanHistory, User
from app.schemas.scan import ScanHistoryOut
from app.api.auth import get_current_user

router = APIRouter()

@router.get("/", response_model=List[ScanHistoryOut])
def get_history(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    return db.query(ScanHistory).filter(ScanHistory.user_id == current_user.id).order_by(ScanHistory.created_at.desc()).limit(50).all()

@router.get("/stats")
def get_stats(current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scans = db.query(ScanHistory).filter(ScanHistory.user_id == current_user.id).all()
    total = len(scans)
    if total == 0:
        return {"total_scans": 0, "avg_score": 0, "risk_distribution": {}}
    scores = [s.score for s in scans if s.score is not None]
    avg_score = round(sum(scores) / len(scores)) if scores else 0
    risk_dist = {}
    for s in scans:
        if s.risk_level:
            risk_dist[s.risk_level] = risk_dist.get(s.risk_level, 0) + 1
    return {"total_scans": total, "avg_score": avg_score, "risk_distribution": risk_dist}

@router.delete("/{scan_id}")
def delete_scan(scan_id: int, current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    scan = db.query(ScanHistory).filter(ScanHistory.id == scan_id, ScanHistory.user_id == current_user.id).first()
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    db.delete(scan)
    db.commit()
    return {"message": "Scan deleted"}
