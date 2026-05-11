"""
api.py — FastAPI backend.
ИСПРАВЛЕНО: bare except → except Exception
ДОБАВЛЕНО:  /rootkit/scan endpoint
ДОБАВЛЕНО:  /report/pdf endpoint (использует pdf_report.py)
ДОБАВЛЕНО:  /live/stats endpoint
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

from fastapi import FastAPI, UploadFile, File, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, Integer, Float, String, DateTime
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime
import pandas as pd
import numpy as np
import joblib
import json
import io
from pathlib import Path

from logger import get_logger
from config_loader import cfg
from rootkit_checker import RootkitChecker
from notifier import notify_threat
from pdf_report import generate_pdf_report

log = get_logger("api")

# ── База данных ────────────────────────────────────────────────

_db_path = cfg.get("api", {}).get("db_path", "data/rootkitguard.db")
Path(_db_path).parent.mkdir(parents=True, exist_ok=True)

Base = declarative_base()
engine = create_engine(f"sqlite:///{_db_path}")
Session = sessionmaker(bind=engine)


class ScanHistory(Base):
    __tablename__ = "scan_history"
    id         = Column(Integer, primary_key=True)
    timestamp  = Column(DateTime, default=datetime.now)
    filename   = Column(String)
    total_rows = Column(Integer)
    anomalies  = Column(Integer)
    pct        = Column(Float)
    threat     = Column(String)
    model_used = Column(String)
    scan_type  = Column(String, default="csv")   # csv / rootkit / process


Base.metadata.create_all(engine)

# ── FastAPI ────────────────────────────────────────────────────

app = FastAPI(
    title="RootkitGuard API",
    description="API для обнаружения rootkit-подобных аномалий",
    version="2.0.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# Загрузка ML-моделей
_rf_path  = cfg.get("models", {}).get("rf_path",     "models/rf_cicids.pkl")
_scl_path = cfg.get("models", {}).get("scaler_path", "models/scaler_cicids.pkl")

try:
    rf     = joblib.load(_rf_path)
    scaler = joblib.load(_scl_path)
    MODEL_LOADED = True
    log.info("ML-модели загружены")
except Exception as e:
    MODEL_LOADED = False
    log.warning(f"Модели не загружены (демо-режим): {e}")


# ── Pydantic-схемы ─────────────────────────────────────────────

class ScanResult(BaseModel):
    total_rows: int
    anomalies:  int
    normal:     int
    pct:        float
    threat:     str
    top_ports:  list

class ReportRequest(BaseModel):
    scan_id:   int
    recipient: str
    notes:     str = ""


# ── Endpoints ──────────────────────────────────────────────────

@app.get("/")
def root():
    return {
        "service":      "RootkitGuard API",
        "version":      "2.0.0",
        "model_loaded": MODEL_LOADED,
        "endpoints":    ["/scan", "/rootkit/scan", "/history",
                         "/report/send", "/report/pdf/{scan_id}",
                         "/live/stats", "/health"],
    }


@app.get("/health")
def health():
    return {
        "status": "ok",
        "model":  "loaded" if MODEL_LOADED else "not found",
        "db":     "connected",
    }


@app.post("/scan", response_model=ScanResult)
async def scan_file(file: UploadFile = File(...)):
    """Сканировать CSV-файл ML-моделью."""
    if not file.filename.endswith(".csv"):
        raise HTTPException(status_code=400, detail="Только CSV файлы")

    contents = await file.read()
    try:
        df = pd.read_csv(io.StringIO(contents.decode("utf-8")))
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Ошибка парсинга CSV: {e}")

    if "Label"     in df.columns: df = df.drop(columns=["Label"])
    if "Timestamp" in df.columns: df = df.drop(columns=["Timestamp"])
    df = df.replace([np.inf, -np.inf], np.nan).fillna(0)

    if MODEL_LOADED:
        try:
            X    = pd.DataFrame(scaler.transform(df), columns=df.columns)
            cols = rf.feature_names_in_
            for c in cols:
                if c not in X.columns:
                    X[c] = 0
            X     = X[cols]
            preds = rf.predict(X)
            proba = rf.predict_proba(X)[:, 1]
        except Exception as e:
            log.error(f"Ошибка предсказания: {e}")
            preds = np.zeros(len(df), dtype=int)
            proba = np.zeros(len(df))
    else:
        preds = np.random.choice([0, 1], size=len(df), p=[0.75, 0.25])
        proba = np.random.uniform(0, 1, size=len(df))

    n_anomaly = int(preds.sum())
    n_normal  = len(preds) - n_anomaly
    pct       = round(n_anomaly / len(preds) * 100, 2)
    threat    = "ВЫСОКАЯ" if pct > 20 else "СРЕДНЯЯ" if pct > 5 else "НИЗКАЯ"
    top_ports = []
    if "Dst Port" in df.columns:
        top_ports = df[preds == 1]["Dst Port"].value_counts().head(5).index.tolist()

    db = Session()
    db.add(ScanHistory(
        filename=file.filename, total_rows=len(preds),
        anomalies=n_anomaly, pct=pct,
        threat=threat, model_used="RandomForest", scan_type="csv",
    ))
    db.commit()
    db.close()

    # Уведомление при угрозе
    notify_threat(threat, f"Файл: {file.filename}, аномалий: {n_anomaly} ({pct}%)")

    log.info(f"Скан {file.filename}: {n_anomaly}/{len(preds)} аномалий, угроза={threat}")

    return ScanResult(
        total_rows=len(preds), anomalies=n_anomaly,
        normal=n_normal, pct=pct,
        threat=threat, top_ports=[int(p) for p in top_ports],
    )


@app.post("/rootkit/scan")
def scan_rootkit():
    """
    Запустить rootkit-специфичные Linux проверки.
    Возвращает находки: скрытые процессы, модули ядра, preload-инъекции.
    """
    log.info("Запущен rootkit scan через API")
    checker = RootkitChecker()
    result  = checker.run_all()
    r_dict  = result.to_dict()

    # Сохранить в БД
    db = Session()
    db.add(ScanHistory(
        filename="system_rootkit_scan",
        total_rows=result.total_checks,
        anomalies=result.failed,
        pct=round(result.failed / max(result.total_checks, 1) * 100, 2),
        threat=result.threat_level,
        model_used="RootkitChecker",
        scan_type="rootkit",
    ))
    db.commit()
    db.close()

    notify_threat(result.threat_level, f"Rootkit scan: {len(result.findings)} находок")
    return r_dict


@app.get("/history")
def get_history(limit: int = 20):
    """История всех сканирований."""
    db = Session()
    records = (
        db.query(ScanHistory)
        .order_by(ScanHistory.timestamp.desc())
        .limit(limit)
        .all()
    )
    db.close()
    return [
        {
            "id":         r.id,
            "timestamp":  r.timestamp.isoformat(),
            "filename":   r.filename,
            "total_rows": r.total_rows,
            "anomalies":  r.anomalies,
            "pct":        r.pct,
            "threat":     r.threat,
            "scan_type":  r.scan_type,
        }
        for r in records
    ]


@app.get("/report/pdf/{scan_id}")
def get_pdf_report(scan_id: int):
    """Сгенерировать и вернуть PDF-отчёт для scan_id."""
    db = Session()
    record = db.query(ScanHistory).filter(ScanHistory.id == scan_id).first()
    db.close()

    if not record:
        raise HTTPException(status_code=404, detail="Сканирование не найдено")

    scan_data = {
        "total_rows": record.total_rows,
        "anomalies":  record.anomalies,
        "normal":     record.total_rows - record.anomalies,
        "pct":        record.pct,
        "threat":     record.threat,
        "top_ports":  [],
    }

    Path("reports").mkdir(exist_ok=True)
    output = f"reports/report_{scan_id}.pdf"
    try:
        generate_pdf_report(scan_data, output)
    except Exception as e:
        log.error(f"Ошибка генерации PDF: {e}")
        raise HTTPException(status_code=500, detail=f"Ошибка PDF: {e}")

    return FileResponse(output, media_type="application/pdf",
                        filename=f"rootkitguard_report_{scan_id}.pdf")


@app.post("/report/send")
def send_report(req: ReportRequest):
    """Сохранить отчёт в JSON (email/webhook — расширяй здесь)."""
    db = Session()
    record = db.query(ScanHistory).filter(ScanHistory.id == req.scan_id).first()
    db.close()
    if not record:
        raise HTTPException(status_code=404, detail="Сканирование не найдено")

    report = {
        "scan_id":   req.scan_id,
        "recipient": req.recipient,
        "timestamp": record.timestamp.isoformat(),
        "filename":  record.filename,
        "anomalies": record.anomalies,
        "threat":    record.threat,
        "notes":     req.notes,
        "status":    "sent",
    }
    Path("reports").mkdir(exist_ok=True)
    with open(f"reports/report_{req.scan_id}.json", "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    return report


@app.get("/live/stats")
def live_stats():
    """Текущая статистика из последних сканирований."""
    db = Session()
    records = (
        db.query(ScanHistory)
        .order_by(ScanHistory.timestamp.desc())
        .limit(10)
        .all()
    )
    db.close()
    total_scans   = len(records)
    avg_pct       = round(sum(r.pct for r in records) / max(total_scans, 1), 2)
    high_threats  = sum(1 for r in records if r.threat == "ВЫСОКАЯ")
    return {
        "total_scans":  total_scans,
        "avg_anomaly_pct": avg_pct,
        "high_threats": high_threats,
        "model_loaded": MODEL_LOADED,
    }


@app.delete("/history/{scan_id}")
def delete_scan(scan_id: int):
    db = Session()
    record = db.query(ScanHistory).filter(ScanHistory.id == scan_id).first()
    if not record:
        db.close()
        raise HTTPException(status_code=404, detail="Не найдено")
    db.delete(record)
    db.commit()
    db.close()
    return {"deleted": scan_id}


if __name__ == "__main__":
    import uvicorn
    _host = cfg.get("api", {}).get("host", "0.0.0.0")
    _port = cfg.get("api", {}).get("port", 8000)
    uvicorn.run("api:app", host=_host, port=_port, reload=True)
