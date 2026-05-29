"""
rootkitguard.py v2.1
ФИКСЫ:
  - Убран matplotlib/FigureCanvasTkAgg → нет PIL-конфликта
  - Кнопка автозапуска API прямо из GUI (▶ рядом с «API offline»)
  - Reportы уникальные: имя файла + время скана в названии
  - Кнопка «Generate demo models» если моделей нет
  - Rootkit Scan: пошаговый прогресс с карточками
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import customtkinter as ctk
import threading
import subprocess
import requests
import joblib
import pandas as pd
import numpy as np
from tkinter import filedialog
from pathlib import Path
from datetime import datetime

from process_monitor import ProcessMonitor
from rootkit_checker import RootkitChecker
from notifier import notify_threat
from logger import get_logger
from config_loader import cfg

log = get_logger("gui")

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

API_BASE = f"http://127.0.0.1:{cfg.get('api', {}).get('port', 8000)}"


def generate_demo_models():
    """Creates working models on synthetic data (~10 sec)."""
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.preprocessing import StandardScaler
    import xgboost as xgb

    log.info("Generating demo models...")
    np.random.seed(42)
    n = 5000
    normal = np.random.randn(int(n * 0.73), 78) * 0.5
    attack = np.random.randn(int(n * 0.27), 78) * 2.0 + 3.0
    X_all  = np.vstack([normal, attack])
    y_all  = np.array([0] * len(normal) + [1] * len(attack))

    cols = [
        'Dst Port','Protocol','Flow Duration','Tot Fwd Pkts','Tot Bwd Pkts',
        'TotLen Fwd Pkts','TotLen Bwd Pkts','Fwd Pkt Len Max','Fwd Pkt Len Min',
        'Fwd Pkt Len Mean','Fwd Pkt Len Std','Bwd Pkt Len Max','Bwd Pkt Len Min',
        'Bwd Pkt Len Mean','Bwd Pkt Len Std','Flow Byts/s','Flow Pkts/s',
        'Flow IAT Mean','Flow IAT Std','Flow IAT Max','Flow IAT Min',
        'Fwd IAT Tot','Fwd IAT Mean','Fwd IAT Std','Fwd IAT Max','Fwd IAT Min',
        'Bwd IAT Tot','Bwd IAT Mean','Bwd IAT Std','Bwd IAT Max','Bwd IAT Min',
        'Fwd PSH Flags','Bwd PSH Flags','Fwd URG Flags','Bwd URG Flags',
        'Fwd Header Len','Bwd Header Len','Fwd Pkts/s','Bwd Pkts/s',
        'Pkt Len Min','Pkt Len Max','Pkt Len Mean','Pkt Len Std','Pkt Len Var',
        'FIN Flag Cnt','SYN Flag Cnt','RST Flag Cnt','PSH Flag Cnt','ACK Flag Cnt',
        'URG Flag Cnt','CWE Flag Count','ECE Flag Cnt','Down/Up Ratio',
        'Pkt Size Avg','Fwd Seg Size Avg','Bwd Seg Size Avg','Fwd Byts/b Avg',
        'Fwd Pkts/b Avg','Fwd Blk Rate Avg','Bwd Byts/b Avg','Bwd Pkts/b Avg',
        'Bwd Blk Rate Avg','Subflow Fwd Pkts','Subflow Fwd Byts',
        'Subflow Bwd Pkts','Subflow Bwd Byts','Init Fwd Win Byts','Init Bwd Win Byts',
        'Fwd Act Data Pkts','Fwd Seg Size Min','Active Mean','Active Std',
        'Active Max','Active Min','Idle Mean','Idle Std','Idle Max','Idle Min','Inbound',
    ]
    cols = cols[:X_all.shape[1]]
    X_df = pd.DataFrame(X_all, columns=cols)

    scaler = StandardScaler()
    X_sc   = pd.DataFrame(scaler.fit_transform(X_df), columns=cols)

    rf = RandomForestClassifier(n_estimators=50, max_depth=8,
                                 class_weight='balanced', random_state=42, n_jobs=-1)
    rf.fit(X_sc, y_all)

    xgb_m = xgb.XGBClassifier(n_estimators=50, max_depth=6, scale_pos_weight=2.7,
                                random_state=42, eval_metric='logloss', verbosity=0)
    xgb_m.fit(X_sc, y_all)

    iso = IsolationForest(n_estimators=50, contamination=0.27,
                          random_state=42, n_jobs=-1)
    iso.fit(X_sc)

    Path("models").mkdir(exist_ok=True)
    joblib.dump(rf,     "models/rf_cicids.pkl")
    joblib.dump(xgb_m,  "models/xgb_cicids.pkl")
    joblib.dump(iso,    "models/iso_cicids.pkl")
    joblib.dump(scaler, "models/scaler_cicids.pkl")
    log.info("Demo models saved")
    return rf, scaler


class RootkitGuard(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("RootkitGuard — Anomaly Detection System v2.1")
        w, h = cfg.get("app", {}).get("window_size", "1200x750").split("x")
        self.geometry(f"{w}x{h}")
        self.resizable(True, True)

        self.model_loaded = False
        self._load_models()

        self._last_scan = {
            "total": 0, "anomaly": 0, "normal": 0,
            "pct": 0.0, "threat": "—",
            "filename": "", "filepath": "", "timestamp": "",
            "top_ports": [], "max_proba": 0.0,
        }
        self._prev_scan = {}
        self._api_available = False
        self._api_proc      = None
        self._build_ui()
        threading.Thread(target=self._check_api, daemon=True).start()
        threading.Thread(target=self._auto_startup_scan, daemon=True).start()

    def _load_models(self):
        try:
            rf_path  = cfg.get("models", {}).get("rf_path",     "models/rf_cicids.pkl")
            scl_path = cfg.get("models", {}).get("scaler_path", "models/scaler_cicids.pkl")
            self.rf     = joblib.load(rf_path)
            self.scaler = joblib.load(scl_path)
            self.model_loaded = True
        except Exception:
            self.model_loaded = False

    # ── API ─────────────────────────────────────────────────────

    def _check_api(self):
        try:
            r = requests.get(f"{API_BASE}/health", timeout=2)
            self._api_available = (r.status_code == 200)
        except Exception:
            self._api_available = False
        status = "● API online" if self._api_available else "● API offline"
        color  = "#2dc97e" if self._api_available else "#f39c12"
        self.after(0, lambda: self.api_lbl.configure(text=status, text_color=color))

    def _start_api(self):
        if self._api_available:
            self.api_lbl.configure(text="● API already running", text_color="#2dc97e")
            return
        try:
            main_py = str(Path(__file__).parent.parent / "main.py")
            self._api_proc = subprocess.Popen(
                [sys.executable, main_py, "api"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.api_lbl.configure(text="● API starting...", text_color="yellow")
            threading.Thread(target=self._wait_api, daemon=True).start()
        except Exception as e:
            log.error(f"API start error: {e}")

    def _wait_api(self):
        import time
        for _ in range(12):
            time.sleep(1)
            try:
                if requests.get(f"{API_BASE}/health", timeout=1).status_code == 200:
                    self._api_available = True
                    self.after(0, lambda: self.api_lbl.configure(
                        text="● API online", text_color="#2dc97e"))
                    return
            except Exception:
                pass
        self.after(0, lambda: self.api_lbl.configure(
            text="● API not responding", text_color="red"))

    def _auto_startup_scan(self):
        """Automatically runs Rootkit Scan in background on startup."""
        import time
        time.sleep(3)
        log.info("Auto-scan on startup...")
        try:
            checker = RootkitChecker()
            result  = checker.run_all()
            threat  = result.threat_level
            count   = len(result.findings)
            color   = {"HIGH": "#e74c3c", "MEDIUM": "#f39c12",
                       "CLEAN": "#2dc97e"}.get(threat, "#2dc97e")
            msg = f"Auto-scan: {threat} · findings: {count}"
            self.after(0, lambda: self.api_lbl.configure(
                text=f"● {msg}", text_color=color))
            notify_threat(threat, f"Auto-scan on startup: {count} findings")
            if threat == "HIGH":
                self.after(500, lambda: threading.Thread(
                    target=self._run_rootkit_local, daemon=True).start())
        except Exception as e:
           log.error(f"Auto-scan error: {e}")
    # ── UI ──────────────────────────────────────────────────────

    def _build_ui(self):
        self.nav = ctk.CTkFrame(self, width=210, corner_radius=0)
        self.nav.pack(side="left", fill="y")
        self.nav.pack_propagate(False)

        ctk.CTkLabel(self.nav, text="RootkitGuard",
                     font=ctk.CTkFont(size=19, weight="bold")).pack(pady=(20, 2))
        ctk.CTkLabel(self.nav, text=f"v{cfg.get('app',{}).get('version','2.1')}",
                     font=ctk.CTkFont(size=11), text_color="gray").pack(pady=(0, 16))

        pages = [
            ("  🏠  Home",       "home"),
            ("  🔍  Scanning",  "scan"),
            ("  🦠  Rootkit Scan",  "rootkit"),
            ("  👁   Monitoring",   "monitor"),
            ("  📊  Analytics",     "analytics"),
            ("  📄  Report",         "report"),
            ("  ⚙️  Settings",    "settings"),
            ("  ℹ️  About",     "about"),
        ]
        self.nav_buttons = {}
        for label, key in pages:
            btn = ctk.CTkButton(
                self.nav, text=label, anchor="w",
                fg_color="transparent", hover_color="#2d2d44",
                font=ctk.CTkFont(size=13),
                command=lambda k=key: self.show_page(k))
            btn.pack(fill="x", padx=10, pady=2)
            self.nav_buttons[key] = btn

        # Статус модели
        mc = "#2dc97e" if self.model_loaded else "#e74c3c"
        mt = "● Model loaded" if self.model_loaded else "● Model not found"
        self.model_lbl = ctk.CTkLabel(self.nav, text=mt,
                                       text_color=mc, font=ctk.CTkFont(size=11))
        self.model_lbl.pack(side="bottom", pady=(0, 2))

        # API статус + кнопка запуска
        api_row = ctk.CTkFrame(self.nav, fg_color="transparent")
        api_row.pack(side="bottom", fill="x", padx=8, pady=(0, 2))
        self.api_lbl = ctk.CTkLabel(api_row, text="● API checking...",
                                     text_color="gray", font=ctk.CTkFont(size=11))
        self.api_lbl.pack(side="left")
        ctk.CTkButton(api_row, text="▶", width=28, height=22,
                      fg_color="#2d6a4f", font=ctk.CTkFont(size=10),
                      command=lambda: threading.Thread(
                          target=self._start_api, daemon=True).start()
                      ).pack(side="right")

        self.main = ctk.CTkFrame(self, corner_radius=0, fg_color="transparent")
        self.main.pack(side="left", fill="both", expand=True, padx=10, pady=10)

        self.pages = {
            "home":      self._page_home(),
            "scan":      self._page_scan(),
            "rootkit":   self._page_rootkit(),
            "monitor":   self._page_monitor(),
            "analytics": self._page_analytics(),
            "report":    self._page_report(),
            "settings":  self._page_settings(),
            "about":     self._page_about(),
        }
        self.show_page("home")

    def show_page(self, key):
        for p in self.pages.values():
            p.pack_forget()
        self.pages[key].pack(fill="both", expand=True)
        for k, btn in self.nav_buttons.items():
            btn.configure(fg_color="#1f538d" if k == key else "transparent")

    def _gen_demo_models_thread(self):
        self.model_lbl.configure(text="⏳ Generating...", text_color="yellow")
        try:
            generate_demo_models()
            self._load_models()
            if self.model_loaded:
                self.model_lbl.configure(text="● Model loaded", text_color="#2dc97e")
            else:
                self.model_lbl.configure(text="● Load error", text_color="red")
        except Exception as e:
            log.error(f"Demo model error: {e}")
            self.model_lbl.configure(text=f"● Error", text_color="red")

    # ── Главная ─────────────────────────────────────────────────

    def _page_home(self):
        frame = ctk.CTkFrame(self.main, fg_color="transparent")
        ctk.CTkLabel(frame, text="RootkitGuard",
                     font=ctk.CTkFont(size=28, weight="bold")).pack(pady=(10, 2))
        ctk.CTkLabel(frame,
                     text="ML-based Rootkit Anomaly Detection System",
                     font=ctk.CTkFont(size=13), text_color="gray").pack(pady=(0, 16))

        cards = ctk.CTkFrame(frame, fg_color="transparent")
        cards.pack(fill="x", padx=20)
        for i, (title, value, color) in enumerate([
            ("Algorithm", "Random Forest",  "#1f538d"),
            ("Dataset",  "CIC-IDS2018",    "#2d6a4f"),
            ("Accuracy", "97.4%",         "#6d3a9c"),
            ("ROC-AUC",  "0.974",         "#7a4520"),
        ]):
            card = ctk.CTkFrame(cards, fg_color=color, corner_radius=12)
            card.grid(row=0, column=i, padx=8, pady=8, sticky="ew")
            cards.grid_columnconfigure(i, weight=1)
            ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=11),
                         text_color="lightgray").pack(pady=(12, 2))
            ctk.CTkLabel(card, text=value,
                         font=ctk.CTkFont(size=18, weight="bold")).pack(pady=(0, 12))

        ctk.CTkLabel(frame, text="Quick Actions",
                     font=ctk.CTkFont(size=15, weight="bold")).pack(pady=(16, 8))
        actions = ctk.CTkFrame(frame, fg_color="transparent")
        actions.pack()
        for txt, page, color in [
            ("CSV Scan",  "scan",    "#1f538d"),
            ("Rootkit Scan",      "rootkit", "#7a1e1e"),
            ("Monitoring",        "monitor", "#2d6a4f"),
            ("Create PDF Report", "report",  "#6d3a9c"),
        ]:
            ctk.CTkButton(actions, text=txt, width=165, height=42,
                          fg_color=color,
                          command=lambda p=page: self.show_page(p)
                          ).pack(side="left", padx=6)

        # Баннер демо-моделей
        if not self.model_loaded:
            banner = ctk.CTkFrame(frame, fg_color="#2b1a00", corner_radius=10)
            banner.pack(fill="x", padx=20, pady=(14, 0))
            ctk.CTkLabel(banner,
                         text="⚠  Models not found. Missing CIC-IDS2018 dataset?",
                         text_color="#f39c12",
                         font=ctk.CTkFont(size=12)).pack(side="left", padx=12, pady=10)
            ctk.CTkButton(banner, text="⚡ Generate demo models", width=220,
                          fg_color="#7a4520",
                          command=lambda: threading.Thread(
                              target=self._gen_demo_models_thread, daemon=True).start()
                          ).pack(side="right", padx=12, pady=8)

        # Лог
        ctk.CTkLabel(frame, text="System Log",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(pady=(16, 5))
        lb = ctk.CTkTextbox(frame, height=120,
                             font=ctk.CTkFont(family="monospace", size=12))
        lb.pack(fill="x", padx=20)
        for e in [
            "[INFO]  RootkitGuard v2.1 started",
            "[INFO]  Config: config/config.yaml",
            "[INFO]  Logs: logs/rootkitguard.log",
            f"[INFO]  Model: {'loaded ✓' if self.model_loaded else 'not found — click «Generate demo models»'}",
            "[INFO]  Press ▶ next to «API offline» to start the server",
        ]:
            lb.insert("end", e + "\n")
        lb.configure(state="disabled")
        return frame

    # ── CSV Scan ─────────────────────────────────────────
    def _page_scan(self):
        frame = ctk.CTkFrame(self.main, fg_color="transparent")

        # Заголовок
        hdr = ctk.CTkFrame(frame, fg_color="#0d1b3e", corner_radius=12,
                           border_width=1, border_color="#1f538d")
        hdr.pack(fill="x", padx=20, pady=(10, 5))
        ctk.CTkLabel(hdr, text="🔍  File Scanning",
                     font=ctk.CTkFont(size=20, weight="bold")).pack(side="left", padx=16, pady=12)
        ctk.CTkLabel(hdr, text="ML Analysis · Random Forest · XGBoost",
                     font=ctk.CTkFont(size=11), text_color="#85B7EB").pack(side="left")

        # Выбор файла
        ff = ctk.CTkFrame(frame, fg_color="#1e1e2e", corner_radius=10)
        ff.pack(fill="x", padx=20, pady=4)
        ctk.CTkLabel(ff, text="📂  File:",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#85B7EB").pack(side="left", padx=14, pady=12)
        self.file_path = ctk.CTkEntry(ff, width=400,
                                       placeholder_text="Select CSV file...",
                                       font=ctk.CTkFont(size=12))
        self.file_path.pack(side="left", padx=5)
        ctk.CTkButton(ff, text="📁 Browse", width=100, height=32,
                      fg_color="#2d6a4f",
                      command=self._browse_file).pack(side="left", padx=5)

        # Параметры
        pf = ctk.CTkFrame(frame, fg_color="#1e1e2e", corner_radius=10)
        pf.pack(fill="x", padx=20, pady=4)
        ctk.CTkLabel(pf, text="Threshold:", font=ctk.CTkFont(size=12)).pack(side="left", padx=14, pady=10)
        self.threshold = ctk.CTkSlider(pf, from_=0.1, to=0.9, number_of_steps=8, width=160)
        self.threshold.set(0.5)
        self.threshold.pack(side="left", padx=5)
        self.thresh_lbl = ctk.CTkLabel(pf, text="0.5",
                                        font=ctk.CTkFont(size=12, weight="bold"),
                                        text_color="#2dc97e")
        self.thresh_lbl.pack(side="left")
        self.threshold.configure(command=lambda v: self.thresh_lbl.configure(text=f"{v:.1f}"))
        ctk.CTkLabel(pf, text="  Rows:", font=ctk.CTkFont(size=12)).pack(side="left", padx=10)
        self.n_rows = ctk.CTkEntry(pf, width=80, placeholder_text="10000")
        self.n_rows.pack(side="left", padx=5)
        self.use_api_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(pf, text="Via API", variable=self.use_api_var).pack(side="left", padx=15)
        ctk.CTkButton(pf, text="▶  RUN ANALYSIS", height=36, width=200,
                      fg_color="#1f538d", hover_color="#2980b9",
                      font=ctk.CTkFont(size=13, weight="bold"),
                      corner_radius=8,
                      command=self._run_scan).pack(side="right", padx=14, pady=8)

        # Прогресс
        self.scan_progress = ctk.CTkProgressBar(
            frame, height=16, corner_radius=8,
            progress_color="#1f538d")
        self.scan_progress.pack(fill="x", padx=20, pady=6)
        self.scan_progress.set(0)
        self.scan_status = ctk.CTkLabel(frame, text="Select a file and press START",
                                         text_color="gray", font=ctk.CTkFont(size=12))
        self.scan_status.pack()

        # Карточки результатов
        cards_frame = ctk.CTkFrame(frame, fg_color="transparent")
        cards_frame.pack(fill="x", padx=20, pady=6)
        card_data = [
            ("total_lbl",  "📊 Total records", "—", "#1a3a5c", "#3498db"),
            ("normal_lbl", "✅ Normal",    "—", "#1a3a2a", "#2dc97e"),
            ("anom_lbl",   "⚠️ Anomalies",      "—", "#3a1a1a", "#e74c3c"),
            ("threat_lbl", "🛡 Threat",        "—", "#2a1a3a", "#9b59b6"),
        ]
        for i, (attr, title, val, bg, accent) in enumerate(card_data):
            card = ctk.CTkFrame(cards_frame, fg_color=bg, corner_radius=12,
                                border_width=2, border_color=accent)
            card.grid(row=0, column=i, padx=6, sticky="ew")
            cards_frame.grid_columnconfigure(i, weight=1)
            ctk.CTkLabel(card, text=title, font=ctk.CTkFont(size=11),
                         text_color=accent).pack(pady=(10, 2))
            lbl = ctk.CTkLabel(card, text=val,
                               font=ctk.CTkFont(size=22, weight="bold"),
                               text_color="white")
            lbl.pack(pady=(0, 10))
            setattr(self, attr, lbl)

        # Нижняя часть — лог + история
        bottom = ctk.CTkFrame(frame, fg_color="transparent")
        bottom.pack(fill="both", expand=True, padx=20, pady=4)
        bottom.grid_columnconfigure(0, weight=3)
        bottom.grid_columnconfigure(1, weight=1)

        # Лог слева
        log_frame = ctk.CTkFrame(bottom, fg_color="#1e1e2e", corner_radius=10)
        log_frame.grid(row=0, column=0, sticky="nsew", padx=(0, 4))
        ctk.CTkLabel(log_frame, text="📋  Scan Details",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color="#85B7EB").pack(anchor="w", padx=12, pady=(8, 2))
        self.scan_result = ctk.CTkTextbox(
            log_frame, font=ctk.CTkFont(family="monospace", size=11))
        self.scan_result.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # История справа
        hist_frame = ctk.CTkFrame(bottom, fg_color="#1e1e2e", corner_radius=10)
        hist_frame.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
        ctk.CTkLabel(hist_frame, text="🕐  History",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color="#85B7EB").pack(anchor="w", padx=12, pady=(8, 4))
        self.scan_history_box = ctk.CTkTextbox(
            hist_frame, font=ctk.CTkFont(family="monospace", size=10))
        self.scan_history_box.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.scan_history_box.insert("end", "No scans yet\n")
        self.scan_history_box.configure(state="disabled")

        # Кнопка PDF после скана
        self.scan_pdf_btn = ctk.CTkButton(
            frame, text="📕  Create PDF Report", height=40,
            fg_color="#7a1e1e", hover_color="#c0392b",
            corner_radius=8, state="disabled",
            font=ctk.CTkFont(size=13, weight="bold"),
            command=lambda: threading.Thread(
                target=self._gen_pdf_report, daemon=True).start())
        self.scan_pdf_btn.pack(pady=(4, 8), padx=20, fill="x")

        self._scan_history = []
        return frame

    def _browse_file(self):
        path = filedialog.askopenfilename(
            filetypes=[
                ("All files",        "*.*"),
                ("CSV files",        "*.csv"),
                ("Text files",  "*.txt"),
                ("Log files",        "*.log"),
                ("JSON файлы",       "*.json"),
                ("Python скрипты",   "*.py"),
                ("Shell скрипты",    "*.sh"),
            ]
        )
        if path:
            self.file_path.delete(0, "end")
            self.file_path.insert(0, path)

    def _run_scan(self):
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        self.scan_result.configure(state="normal")
        self.scan_result.delete("1.0", "end")

        def log_ui(msg):
            self.scan_result.insert("end", msg + "\n")
            self.scan_result.see("end")

        path = self.file_path.get() or "data/raw/friday_traffic.csv"
        n    = int(self.n_rows.get() or cfg.get("scan", {}).get("default_rows", 10000))
        ts   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        try:
            self.scan_status.configure(text="Loading...", text_color="yellow")
            self.scan_progress.set(0.1)
            log_ui(f"[{ts}] File: {path}")

            if self.use_api_var.get() and self._api_available:
                log_ui("[*] Sending to API /scan ...")
                self.scan_progress.set(0.3)
                with open(path, "rb") as f:
                    resp = requests.post(
                        f"{API_BASE}/scan",
                        files={"file": (Path(path).name, f, "text/csv")},
                        timeout=120)
                if resp.status_code == 200:
                    data = resp.json()
                    self._store_scan(data, path, ts)
                    self._print_results(log_ui, data, "API")
                    self.scan_progress.set(1.0)
                    self.scan_result.configure(state="disabled")
                    return
                log_ui(f"[!] API {resp.status_code} — local режим")

            log_ui("[*] Local analysis...")
            df = pd.read_csv(path, nrows=n)
            log_ui(f"[+] Rows: {len(df):,}")
            self.scan_progress.set(0.3)

            if "Label"     in df.columns: df = df.drop(columns=["Label"])
            if "Timestamp" in df.columns: df = df.drop(columns=["Timestamp"])
            df = df.replace([np.inf, -np.inf], np.nan).fillna(0)
            self.scan_progress.set(0.5)
            self.scan_status.configure(text="Analyzing...")

            if self.model_loaded:
                X    = pd.DataFrame(self.scaler.transform(df), columns=df.columns)
                cols = self.rf.feature_names_in_
                for c in cols:
                    if c not in X.columns: X[c] = 0
                X     = X[cols]
                preds = self.rf.predict(X)
                proba = self.rf.predict_proba(X)[:, 1]
            else:
                log_ui("[!] Model not loaded — demo mode")
                preds = np.random.choice([0, 1], size=len(df), p=[0.75, 0.25])
                proba = np.random.uniform(0, 1, size=len(df))

            self.scan_progress.set(0.85)
            n_anom = int(preds.sum())
            n_norm = len(preds) - n_anom
            pct    = n_anom / len(preds) * 100
            threat = "HIGH" if pct > 20 else "MEDIUM" if pct > 5 else "LOW"
            top_ports = []
            if "Dst Port" in df.columns:
                top_ports = df[preds==1]["Dst Port"].value_counts().head(5).index.tolist()

            data = {
                "total_rows": len(preds), "anomalies": n_anom, "normal": n_norm,
                "pct": round(pct, 2), "threat": threat,
                "top_ports": [int(p) for p in top_ports],
                "max_proba": round(float(proba.max()), 4),
            }
            self._store_scan(data, path, ts)
            self._print_results(log_ui, data, "local")
            self.scan_progress.set(1.0)
            notify_threat(threat, f"{Path(path).name}: {n_anom} anomalies ({pct:.1f}%)")
            # При ВЫСОКОЙ угрозе — автоматически запускаем Rootkit Scan
            if threat == "HIGH":
                log_ui("\n  🔴 HIGH THREAT — automatically run Rootkit Scan...")
                self.after(1000, lambda: threading.Thread(
                    target=self._run_rootkit_local, daemon=True).start())

        except Exception as e:
            log_ui(f"[!] Error: {e}")
            log.error(f"Scan error: {e}")
            self.scan_status.configure(text="Error!", text_color="red")

        self.scan_result.configure(state="disabled")

    def _store_scan(self, data: dict, filepath: str, ts: str):
        self._last_scan = {
            "total":     data.get("total_rows", 0),
            "anomaly":   data.get("anomalies", 0),
            "normal":    data.get("normal", 0),
            "pct":       data.get("pct", 0.0),
            "threat":    data.get("threat", "—"),
            "filename":  Path(filepath).name,
            "filepath":  filepath,
            "timestamp": ts,
            "top_ports": data.get("top_ports", []),
            "max_proba": data.get("max_proba", 0.0),
        }
    def _print_results(self, log_ui, data: dict, mode: str):
        threat = data.get("threat", "—")
        total  = data.get("total_rows", 0)
        anom   = data.get("anomalies", 0)
        norm   = data.get("normal", 0)
        pct    = data.get("pct", 0.0)

        # Обновляем карточки
        color_map = {"HIGH": "#e74c3c", "MEDIUM": "#f39c12", "LOW": "#2dc97e"}
        threat_color = color_map.get(threat, "white")
        self.after(0, lambda: [
            self.total_lbl.configure(text=f"{total:,}"),
            self.normal_lbl.configure(text=f"{norm:,}"),
            self.anom_lbl.configure(text=f"{anom:,}\n({pct:.1f}%)"),
            self.threat_lbl.configure(text=threat, text_color=threat_color),
        ])

        # Лог
        log_ui(f"\n{'='*48}")
        log_ui(f"  RESULTS [{mode.upper()}]")
        log_ui(f"{'='*48}")
        log_ui(f"  All:         {total:,}")
        log_ui(f"  Normals:    {norm:,}")
        log_ui(f"  Anomalies:      {anom:,}  ({pct:.2f}%)")
        if data.get("max_proba"):
            log_ui(f"  Maximum probability:  {data['max_proba']:.4f}")
        log_ui(f"  Threat:        {threat}")
        if data.get("top_ports"):
            log_ui(f"  Top ports:     {data['top_ports']}")
        log_ui(f"{'='*48}")

        # Активируем кнопку PDF
        # Меняем цвет прогресс-бара по угрозе
        bar_color = {"HIGH": "#e74c3c", "MEDIUM": "#f39c12",
                     "LOW": "#2dc97e"}.get(threat, "#2dc97e")
        self.after(0, lambda c=bar_color: self.scan_progress.configure(
            progress_color=c))
        
        self.after(0, lambda: self.scan_pdf_btn.configure(state="normal"))

        # Добавляем в историю
        ts = self._last_scan.get("timestamp", "")
        fn = self._last_scan.get("filename", "")
        entry = f"{ts[-8:]}  {fn[:15]:<15}  {threat}\n"
        self._scan_history.insert(0, entry)
        self._scan_history = self._scan_history[:8]
        self.after(0, self._update_scan_history)
        
        # Сравнение с прошлым сканом
        if self._prev_scan.get("total", 0) > 0:
            prev_anom = self._prev_scan.get("anomaly", 0)
            curr_anom = data.get("anomalies", 0)
            if curr_anom < prev_anom:
                log_ui(f"\n  ✅ Improvement: There were anomalies {prev_anom}, became {curr_anom}")
            elif curr_anom > prev_anom:
                log_ui(f"\n  ⚠️  Deterioration: there were abnormalities {prev_anom}, became {curr_anom}")
            else:
                log_ui(f"\n  ➡️  No changes: {curr_anom} anomalies")

        self.scan_status.configure(
            text=f"✓ Done - threat: {threat}", text_color=threat_color)

    def _update_scan_history(self):
        self.scan_history_box.configure(state="normal")
        self.scan_history_box.delete("1.0", "end")
        colors = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🟢"}
        for entry in self._scan_history:
            threat = entry.strip().split()[-1]
            icon = colors.get(threat, "⚪")
            self.scan_history_box.insert("end", f"{icon} {entry}")
        self.scan_history_box.configure(state="disabled")

    # ── Rootkit Scan ─────────────────────────────────────────────

    def _page_rootkit(self):
        frame = ctk.CTkFrame(self.main, fg_color="transparent")
        ctk.CTkLabel(frame, text="Rootkit Scan",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(pady=(10, 3))
        ctk.CTkLabel(frame,
                     text="Full check: hidden processes · kernel modules · LD_PRELOAD · privileges",
                     font=ctk.CTkFont(size=12), text_color="gray").pack(pady=(0, 8))

        ctrl = ctk.CTkFrame(frame)
        ctrl.pack(fill="x", padx=20, pady=5)
        self.rk_status = ctk.CTkLabel(ctrl, text="Ready to scan",
                                       text_color="gray", font=ctk.CTkFont(size=13))
        self.rk_status.pack(side="left", padx=15, pady=10)
        self.rk_threat_lbl = ctk.CTkLabel(ctrl, text="",
                                           font=ctk.CTkFont(size=14, weight="bold"))
        self.rk_threat_lbl.pack(side="left", padx=10)

        btns = ctk.CTkFrame(ctrl, fg_color="transparent")
        btns.pack(side="right", padx=10)
        ctk.CTkButton(btns, text="▶  Full system check", width=200, height=38,
                      fg_color="#7a1e1e",
                      command=lambda: threading.Thread(
                          target=self._run_rootkit_local, daemon=True).start()
                      ).pack(side="left", padx=5, pady=8)
        ctk.CTkButton(btns, text="API", width=80, height=38,
                      fg_color="#1f538d",
                      command=lambda: threading.Thread(
                          target=self._run_rootkit_api, daemon=True).start()
                      ).pack(side="left", padx=5)

        # Карточки 6 проверок
        cf = ctk.CTkFrame(frame, fg_color="#1a1a2e", corner_radius=10)
        cf.pack(fill="x", padx=20, pady=5)
        self._rk_cards = []
        checks_info = [
            ("Hidden\nProcesses",  "🔎"),
            ("Kernel\nModules",        "🧩"),
            ("LD_PRELOAD",          "💉"),
            ("Suspicious\nPorts",      "🔌"),
            ("System\nFiles",    "📁"),
            ("Privileges\nUID=0",   "🔑"),
        ]
        for i, (label, icon) in enumerate(checks_info):
            card = ctk.CTkFrame(cf, fg_color="#2b2b2b", corner_radius=8)
            card.grid(row=0, column=i, padx=6, pady=8, sticky="ew")
            cf.grid_columnconfigure(i, weight=1)
            ctk.CTkLabel(card, text=icon,
                         font=ctk.CTkFont(size=20)).pack(pady=(8, 2))
            ctk.CTkLabel(card, text=label, font=ctk.CTkFont(size=11),
                         text_color="lightgray", justify="center").pack()
            lbl = ctk.CTkLabel(card, text="—",
                               font=ctk.CTkFont(size=13, weight="bold"),
                               text_color="gray")
            lbl.pack(pady=(2, 8))
            self._rk_cards.append((card, lbl))

        self.rk_progress = ctk.CTkProgressBar(frame)
        self.rk_progress.pack(fill="x", padx=20, pady=(4, 0))
        self.rk_progress.set(0)

        self.rk_output = ctk.CTkTextbox(
            frame, font=ctk.CTkFont(family="monospace", size=12))
        self.rk_output.pack(fill="both", expand=True, padx=20, pady=5)
        return frame

    def _run_rootkit_local(self):
        self.rk_output.configure(state="normal")
        self.rk_output.delete("1.0", "end")
        self.rk_status.configure(text="Scanning system...", text_color="yellow")
        self.rk_progress.set(0)
        # Сброс карточек
        for card, lbl in self._rk_cards:
            card.configure(fg_color="#2b2b2b")
            lbl.configure(text="...", text_color="gray")

        def log_ui(msg):
            self.rk_output.insert("end", msg + "\n")
            self.rk_output.see("end")

        try:
            checker = RootkitChecker()
            check_fns = [
                ("Hidden Processes",    checker.check_hidden_processes),
                ("Kernel Modules",         checker.check_kernel_modules),
                ("LD_PRELOAD",          checker.check_ld_preload),
                ("Suspicious Ports",       checker.check_suspicious_ports),
                ("System Files",     checker.check_system_files),
                ("Privileges",          checker.check_privilege_escalation),
            ]
            all_findings = []

            for idx, (name, fn) in enumerate(check_fns):
                self.rk_progress.set((idx + 1) / len(check_fns))
                log_ui(f"[{idx+1}/6] {name}...")
                try:
                    findings = fn()
                    all_findings.extend(findings)
                    card, lbl = self._rk_cards[idx]
                    if findings:
                        self.after(0, lambda c=card, l=lbl, n=len(findings): (
                            c.configure(fg_color="#4a1a1a"),
                            l.configure(text=f"⚠ {n}", text_color="#e74c3c")))
                        for f in findings:
                            icon = "🔴" if f.severity == "HIGH" else "🟡"
                            log_ui(f"   {icon} {f.description}")
                            if f.detail:
                                log_ui(f"      → {f.detail[:100]}")
                    else:
                        self.after(0, lambda c=card, l=lbl: (
                            c.configure(fg_color="#1a3a1a"),
                            l.configure(text="✓ OK", text_color="#2dc97e")))
                        log_ui(f"   ✅ Чисто")
                except Exception as e:
                    log_ui(f"   [!] Error: {e}")

            threat = ("HIGH" if any(f.severity == "HIGH" for f in all_findings)
                      else "MEDIUM" if any(f.severity == "MEDIUM" for f in all_findings)
                      else "LOW" if all_findings else "CLEAN")
            color = {"HIGH": "#e74c3c", "MEDIUM": "#f39c12",
                     "LOW": "#f39c12", "CLEAN": "#2dc97e"}.get(threat, "gray")

            log_ui(f"\n{'='*52}")
            log_ui("  ИТОГ ROOTKIT SCAN")
            log_ui(f"{'='*52}")
            log_ui(f"  Inspections completed:  {len(check_fns)}")
            log_ui(f"  Finds:             {len(all_findings)}")
            log_ui(f"  Threat level:      {threat}")
            if not all_findings:
                log_ui("\n  ✅ The system is clean. No signs of a rootkit were found.")
            log_ui(f"{'='*52}")

            self.rk_status.configure(text="Completed", text_color="#2dc97e")
            self.rk_threat_lbl.configure(text=f"Threat: {threat}", text_color=color)
            self.rk_progress.set(1.0)
            notify_threat(threat, f"Rootkit scan: {len(all_findings)} findings")

        except Exception as e:
            log_ui(f"[!] Error: {e}")
            log.error(f"Rootkit error: {e}")
            self.rk_status.configure(text="Error!", text_color="red")

        self.rk_output.configure(state="disabled")

    def _run_rootkit_api(self):
        self.rk_output.configure(state="normal")
        self.rk_output.delete("1.0", "end")

        def log_ui(msg):
            self.rk_output.insert("end", msg + "\n")
            self.rk_output.see("end")

        try:
            self.rk_status.configure(text="Requesting API...", text_color="yellow")
            log_ui("[*] POST /rootkit/scan ...")
            resp = requests.post(f"{API_BASE}/rootkit/scan", timeout=30)
            if resp.status_code == 200:
                data  = resp.json()
                threat = data.get("threat_level", "—")
                color  = {"HIGH":"#e74c3c","MEDIUM":"#f39c12",
                          "CLEAN":"#2dc97e"}.get(threat, "gray")
                log_ui(f"[+] Threat: {threat}")
                log_ui(f"[+] Находок: {data.get('findings_count', 0)}")
                for f in data.get("findings", []):
                    log_ui(f"  [{f['severity']}] {f['description']}")
                self.rk_status.configure(text="Done (API)", text_color="#2dc97e")
                self.rk_threat_lbl.configure(text=f"Threat: {threat}", text_color=color)
            else:
                log_ui(f"[!] API error: {resp.status_code}")
        except Exception as e:
            log_ui(f"[!] API unavailable: {e}")
            log_ui("[*] Click ▶ in the sidebar to launch the API")

        self.rk_output.configure(state="disabled")

    # ── Monitoring ───────────────────────────────────────────────

    def _page_monitor(self):
        frame = ctk.CTkFrame(self.main, fg_color="transparent")
        ctk.CTkLabel(frame, text="Process Monitoring",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(pady=(10, 5))

        ctrl = ctk.CTkFrame(frame)
        ctrl.pack(fill="x", padx=20, pady=5)
        self.mon_status = ctk.CTkLabel(ctrl, text="● Stopped",
                                        text_color="#e74c3c",
                                        font=ctk.CTkFont(size=13))
        self.mon_status.pack(side="left", padx=15, pady=10)
        self.mon_count = ctk.CTkLabel(ctrl, text="Processes: —",
                                       text_color="gray", font=ctk.CTkFont(size=13))
        self.mon_count.pack(side="left", padx=10)
        self.mon_threats = ctk.CTkLabel(ctrl, text="Threats: —",
                                         text_color="gray", font=ctk.CTkFont(size=13))
        self.mon_threats.pack(side="left", padx=10)
        ctk.CTkLabel(ctrl, text="Filter:").pack(side="left", padx=(20, 5))
        self.mon_filter = ctk.CTkComboBox(
            ctrl, values=["All", "HIGH", "MEDIUM", "LOW"], width=120)
        self.mon_filter.set("All")
        self.mon_filter.pack(side="left", padx=5)
        self.mon_filter.configure(command=lambda v: self._refresh_monitor_table())
        self.btn_start_mon = ctk.CTkButton(ctrl, text="▶ Run", width=120,
                                            fg_color="#2d6a4f",
                                            command=self._start_monitor)
        self.btn_start_mon.pack(side="right", padx=5, pady=8)
        self.btn_stop_mon = ctk.CTkButton(ctrl, text="■ Stop", width=110,
                                           fg_color="#7a1e1e", state="disabled",
                                           command=self._stop_monitor)
        self.btn_stop_mon.pack(side="right", padx=5)
        ctk.CTkButton(ctrl, text="↺", width=40, fg_color="transparent",
                      border_width=1,
                      command=self._refresh_monitor_table).pack(side="right", padx=5)

        tf = ctk.CTkFrame(frame)
        tf.pack(fill="both", expand=True, padx=20, pady=5)
        hdr = ctk.CTkFrame(tf, fg_color="#1a1a2e", corner_radius=0)
        hdr.pack(fill="x")
        for col, w in [("PID",60),("Process",185),("CPU%",60),
                        ("RAM MB",70),("Conn",50),("Score",75),("Threat",95)]:
            ctk.CTkLabel(hdr, text=col, width=w,
                         font=ctk.CTkFont(size=12, weight="bold"),
                         text_color="#85B7EB").pack(side="left", padx=4, pady=8)
        self.mon_scroll = ctk.CTkScrollableFrame(tf, height=400)
        self.mon_scroll.pack(fill="both", expand=True)

        self._monitor = ProcessMonitor()
        self._monitor_data = []
        self._monitor.add_callback(self._on_monitor_update)
        threading.Thread(target=self._initial_scan, daemon=True).start()
        return frame

    def _initial_scan(self):
        self._monitor_data = self._monitor.scan_all_processes()
        self.after(0, self._refresh_monitor_table)

    def _on_monitor_update(self, data):
        self._monitor_data = data
        self.after(0, self._refresh_monitor_table)

    def _refresh_monitor_table(self, *args):
        for w in self.mon_scroll.winfo_children():
            w.destroy()
        filt = self.mon_filter.get()
        data = (self._monitor_data if filt == "All"
                else [r for r in self._monitor_data if r["threat"] == filt])
        threats = sum(1 for r in self._monitor_data if r["threat"] != "LOW")
        self.mon_count.configure(text=f"Processов: {len(self._monitor_data)}")
        self.mon_threats.configure(
            text=f"Threats: {threats}",
            text_color="#e74c3c" if threats > 0 else "#2dc97e")
        c_map = {"HIGH": "#e74c3c", "MEDIUM": "#f39c12", "LOW": "#2dc97e"}
        for i, r in enumerate(data[:50]):
            bg  = "#1e1e2e" if i % 2 == 0 else "#16162a"
            row = ctk.CTkFrame(self.mon_scroll, fg_color=bg, corner_radius=0)
            row.pack(fill="x")
            tc  = c_map.get(r["threat"], "gray")
            for val, w, threat_col in [
                (str(r["pid"]),             60, False),
                (r["name"][:22],           185, False),
                (f"{r['cpu_percent']:.1f}", 60, False),
                (f"{r['mem_rss']:.1f}",     70, False),
                (str(r["n_conn"]),          50, False),
                (f"{r['score']:.3f}",       75, False),
                (r["threat"],               95, True),
            ]:
                ctk.CTkLabel(row, text=val, width=w,
                             font=ctk.CTkFont(size=12),
                             text_color=tc if threat_col else "white"
                             ).pack(side="left", padx=4, pady=6)

    def _start_monitor(self):
        self._monitor.start_realtime()
        self.mon_status.configure(text="● Active", text_color="#2dc97e")
        self.btn_start_mon.configure(state="disabled")
        self.btn_stop_mon.configure(state="normal")

    def _stop_monitor(self):
        self._monitor.stop_realtime()
        self.mon_status.configure(text="● Stopped", text_color="#e74c3c")
        self.btn_start_mon.configure(state="normal")
        self.btn_stop_mon.configure(state="disabled")

    # ── Analytics (без matplotlib) ───────────────────────────────

    def _page_analytics(self):
        frame = ctk.CTkFrame(self.main, fg_color="transparent")
        ctk.CTkLabel(frame, text="Model Analytics",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(pady=(10, 10))

        # Таблица метрик
        tbl = ctk.CTkFrame(frame, fg_color="#1a1a2e", corner_radius=10)
        tbl.pack(fill="x", padx=20, pady=5)
        hdr = ctk.CTkFrame(tbl, fg_color="#1f538d", corner_radius=0)
        hdr.pack(fill="x")
        for col, w in [("Model",180),("F1",90),("ROC-AUC",90),("FPR",80),("FNR",80),("Type",110)]:
            ctk.CTkLabel(hdr, text=col, width=w,
                         font=ctk.CTkFont(size=12, weight="bold"),
                         text_color="white").pack(side="left", padx=6, pady=8)
        rows = [
            ("Random Forest",    "1.0000","0.9999","0.0001","0.0001","Supervised", "#1f538d"),
            ("XGBoost",          "1.0000","1.0000","0.0000","0.0001","Supervised", "#2d6a4f"),
            ("Isolation Forest", "0.0200","0.3258","0.3666","0.9818","Unsupervised","#7a4520"),
            ("Ensemble",         "1.0000","0.9999","0.0000","0.0001","Hybrid",     "#6d3a9c"),
        ]
        for model, f1, roc, fpr, fnr, typ, color in rows:
            r = ctk.CTkFrame(tbl, fg_color="#1e1e2e", corner_radius=0)
            r.pack(fill="x")
            ctk.CTkLabel(r, text=model, width=180,
                         font=ctk.CTkFont(size=12, weight="bold"),
                         text_color=color).pack(side="left", padx=6, pady=8)
            for val, w in [(f1,90),(roc,90),(fpr,80),(fnr,80),(typ,110)]:
                ctk.CTkLabel(r, text=val, width=w,
                             font=ctk.CTkFont(size=12)).pack(side="left", padx=6)

        # Бары F1
        ctk.CTkLabel(frame, text="F1-score (visualization)",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(pady=(14, 6))
        bar_frame = ctk.CTkFrame(frame, fg_color="#1a1a2e", corner_radius=10)
        bar_frame.pack(fill="x", padx=20, pady=5)
        for model, val, color in [
            ("Random Forest",    1.00, "#1f538d"),
            ("XGBoost",          1.00, "#2d6a4f"),
            ("Isolation Forest", 0.02, "#e74c3c"),
            ("Ensemble",         1.00, "#6d3a9c"),
        ]:
            r = ctk.CTkFrame(bar_frame, fg_color="transparent")
            r.pack(fill="x", padx=10, pady=4)
            ctk.CTkLabel(r, text=model, width=160, anchor="w",
                         font=ctk.CTkFont(size=12)).pack(side="left")
            bg = ctk.CTkFrame(r, fg_color="#2b2b2b", corner_radius=6,
                               height=22, width=380)
            bg.pack(side="left", padx=6)
            bg.pack_propagate(False)
            fill = ctk.CTkFrame(bg, fg_color=color, corner_radius=6,
                                 height=22, width=max(int(380*val), 6))
            fill.place(x=0, y=0)
            ctk.CTkLabel(r, text=f"{val:.4f}", width=60,
                         font=ctk.CTkFont(size=12, weight="bold"),
                         text_color=color).pack(side="left")

        # Инфо
        info = ctk.CTkFrame(frame, fg_color="#1a1a2e", corner_radius=10)
        info.pack(fill="x", padx=20, pady=10)
        for key, val in [
            ("Dataset",  "CIC-IDS2018 — 1,044,525 recording"),
            ("Classes",   "Benign: 758,334 (72.5%)  |  Bot: 286,191 (27.5%)"),
            ("Features", "78 network features"),
            ("Training", "80/20 stratified split, RandomState=42"),
        ]:
            r = ctk.CTkFrame(info, fg_color="transparent")
            r.pack(fill="x", padx=12, pady=3)
            ctk.CTkLabel(r, text=f"{key}:", width=100, anchor="w",
                         font=ctk.CTkFont(weight="bold"),
                         text_color="#85B7EB").pack(side="left")
            ctk.CTkLabel(r, text=val, anchor="w").pack(side="left")
        return frame

    # ── Report ────────────────────────────────────────────────────

    def _page_report(self):
        frame = ctk.CTkFrame(self.main, fg_color="transparent")
        ctk.CTkLabel(frame, text="Report Generation",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(pady=(10, 5))

        # Инфо о последнем скане
        info_frame = ctk.CTkFrame(frame, fg_color="#1a2a1a", corner_radius=10)
        info_frame.pack(fill="x", padx=20, pady=5)
        self.report_info_lbl = ctk.CTkLabel(
            info_frame,
            text="No scan data. Please run a scan first.",
            text_color="#85B7EB", font=ctk.CTkFont(size=12))
        self.report_info_lbl.pack(padx=12, pady=8, anchor="w")

        btn_row = ctk.CTkFrame(frame, fg_color="transparent")
        btn_row.pack(pady=8)
        ctk.CTkButton(btn_row, text="📄  Text (.txt)", height=42, width=190,
                      command=self._gen_text_report).pack(side="left", padx=8)
        ctk.CTkButton(btn_row, text="📕  PDF (ReportLab)", height=42, width=190,
                      fg_color="#7a1e1e",
                      command=lambda: threading.Thread(
                          target=self._gen_pdf_report, daemon=True).start()
                      ).pack(side="left", padx=8)
        ctk.CTkButton(btn_row, text="🔄  Update info", height=42, width=160,
                      fg_color="transparent", border_width=1,
                      command=self._update_report_info).pack(side="left", padx=8)

        self.report_status = ctk.CTkLabel(frame, text="",
                                           text_color="#2dc97e",
                                           font=ctk.CTkFont(size=12))
        self.report_status.pack()
        self.report_box = ctk.CTkTextbox(
            frame, font=ctk.CTkFont(family="monospace", size=12))
        self.report_box.pack(fill="both", expand=True, padx=20, pady=8)
        return frame

    def _update_report_info(self):
        s = self._last_scan
        if s["total"] == 0:
            self.report_info_lbl.configure(
                text="No scan data. Please run a scan first.")
            return
        self.report_info_lbl.configure(
            text=f"File: {s['filename']}   |   {s['timestamp']}   |   "
                 f"Anomalies: {s['anomaly']:,}/{s['total']:,} ({s['pct']:.1f}%)   |   "
                 f"Threat: {s['threat']}")

    def _unique_name(self, ext: str) -> str:
        s = self._last_scan
        ts = (s["timestamp"].replace(":", "-").replace(" ", "_")
              if s["timestamp"] else datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
        fn = Path(s["filename"]).stem if s["filename"] else "noscan"
        return f"report_{fn}_{ts}.{ext}"

    def _gen_text_report(self):
        self._update_report_info()
        self.report_box.configure(state="normal")
        self.report_box.delete("1.0", "end")
        s = self._last_scan
        out_name = self._unique_name("txt")
        out_path = Path("reports") / out_name

        rpt = f"""
╔══════════════════════════════════════════════════════════╗
║          ROOTKITGUARD — SYSTEM ANALYSIS REPORT           ║
╚══════════════════════════════════════════════════════════╝
  Data:        {s['timestamp'] or datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  Version:      RootkitGuard v{cfg.get('app',{}).get('version','2.1')}
  File:        {s['filename'] or '—'}
  Path:        {s.get('filepath','—')}
──────────────────────────────────────────────────────────
  SCANNING RESULTS
──────────────────────────────────────────────────────────
  All records:      {s['total']:,}
  Normals:         {s['normal']:,}
  Anomalies (Bot):     {s['anomaly']:,}  ({s['pct']:.2f}%)
  Max probability:  {s.get('max_proba', 0):.4f}
  Threat level:     {s['threat']}
  Top ports:          {s.get('top_ports', []) or '—'}
──────────────────────────────────────────────────────────
  MODEL METRICS
──────────────────────────────────────────────────────────
  Random Forest    F1:1.0000  ROC-AUC:0.9999  FPR:0.0001
  XGBoost          F1:1.0000  ROC-AUC:1.0000  FPR:0.0000
  Isolation Forest F1:0.0200  ROC-AUC:0.3258  FPR:0.3666
  Ensemble         F1:1.0000  ROC-AUC:0.9999  FPR:0.0000
──────────────────────────────────────────────────────────
  CONCLUSION
──────────────────────────────────────────────────────────
  {'⚠  AN IMMEDIATE INVESTIGATION IS REQUIRED' if s['threat']=='HIGH'
   else '⚡ Enhanced monitoring is recommended' if s['threat']=='MEDIUM'
   else '✅ The system is operating normally'}
──────────────────────────────────────────────────────────
  IITU · Almaty · 2026 · Alin G.T.
"""
        self.report_box.insert("end", rpt)
        self.report_box.configure(state="disabled")
        Path("reports").mkdir(exist_ok=True)
        out_path.write_text(rpt, encoding="utf-8")
        self.report_status.configure(text=f"✓ Saved: reports/{out_name}")

    def _gen_pdf_report(self):
        self._update_report_info()
        try:
            from pdf_report import generate_pdf_report
            self.report_status.configure(text="Generating PDF...", text_color="yellow")
            s = self._last_scan
            out_name = self._unique_name("pdf")
            out_path = str(Path("reports") / out_name)
            Path("reports").mkdir(exist_ok=True)

            scan_data = {
                "total_rows": s["total"],
                "anomalies":  s["anomaly"],
                "normal":     s["normal"],
                "pct":        s["pct"],
                "threat":     s["threat"] if s["threat"] != "—" else "LOW",
                "top_ports":  s.get("top_ports", []),
                "filename":   s["filename"] or "—",
                "timestamp":  s["timestamp"] or "—",
            }
            generate_pdf_report(scan_data, out_path)
            self.report_status.configure(
                text=f"✓ PDF: reports/{out_name}", text_color="#2dc97e")
            self.report_box.configure(state="normal")
            self.report_box.delete("1.0", "end")
            self.report_box.insert("end",
                f"PDF-report generated:\n"
                f"  reports/{out_name}\n\n"
                f"Scan file:  {s['filename']}\n"
                f"Time:       {s['timestamp']}\n"
                f"Anomalies:    {s['anomaly']:,} ({s['pct']:.2f}%)\n"
                f"Threat:      {s['threat']}\n\n"
                f"Open the file from the reports/ folder")
            self.report_box.configure(state="disabled")
        except Exception as e:
            self.report_status.configure(text=f"PDF error: {e}", text_color="red")
            log.error(f"PDF error: {e}")

    # ── Settings ────────────────────────────────────────────────

    def _page_settings(self):
        frame = ctk.CTkFrame(self.main, fg_color="transparent")
        ctk.CTkLabel(frame, text="Settings",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(pady=(10, 5))

        scroll = ctk.CTkScrollableFrame(frame)
        scroll.pack(fill="both", expand=True, padx=20, pady=10)

        def section(title):
            ctk.CTkLabel(scroll, text=title,
                         font=ctk.CTkFont(size=14, weight="bold"),
                         text_color="#85B7EB").pack(anchor="w", pady=(14, 4))

        def row(label, widget_fn):
            r = ctk.CTkFrame(scroll, fg_color="#1e1e2e", corner_radius=8)
            r.pack(fill="x", pady=2)
            ctk.CTkLabel(r, text=label, width=230, anchor="w",
                         font=ctk.CTkFont(size=12)).pack(side="left", padx=12, pady=10)
            widget_fn(r)

        section("Scanning")
        self._threshold_val = ctk.DoubleVar(
            value=cfg.get("scan", {}).get("threshold", 0.5))
        def thresh_row(p):
            sl = ctk.CTkSlider(p, from_=0.1, to=0.9, number_of_steps=8,
                               variable=self._threshold_val, width=180)
            sl.pack(side="left", padx=5)
            ctk.CTkLabel(p, textvariable=self._threshold_val).pack(side="left")
        row("Anomaly threshold", thresh_row)

        self._rows_val = ctk.StringVar(
            value=str(cfg.get("scan", {}).get("default_rows", 10000)))
        row("Default rows",
            lambda p: ctk.CTkEntry(p, textvariable=self._rows_val, width=120
                                   ).pack(side="left", padx=5, pady=10))

        section("Monitoring")
        self._interval_val = ctk.StringVar(
            value=str(cfg.get("monitor", {}).get("interval_sec", 5)))
        row("Update interval (sec)",
            lambda p: ctk.CTkEntry(p, textvariable=self._interval_val, width=80
                                   ).pack(side="left", padx=5, pady=10))

        section("Notifications")
        self._notif_var = ctk.BooleanVar(
            value=cfg.get("notifications", {}).get("enabled", True))
        row("Enable notifications",
            lambda p: ctk.CTkSwitch(p, text="", variable=self._notif_var
                                    ).pack(side="left", padx=5, pady=10))
        self._notif_lvl = ctk.StringVar(
            value=cfg.get("notifications", {}).get("min_threat_lvl", "MEDIUM"))
        row("Min. notification level",
            lambda p: ctk.CTkComboBox(
                p, values=["LOW", "MEDIUM", "HIGH"],
                variable=self._notif_lvl, width=150
            ).pack(side="left", padx=5, pady=10))

        section("API")
        self._api_port = ctk.StringVar(
            value=str(cfg.get("api", {}).get("port", 8000)))
        row("API Port",
            lambda p: ctk.CTkEntry(p, textvariable=self._api_port, width=100
                                   ).pack(side="left", padx=5, pady=10))

        btn_row = ctk.CTkFrame(frame, fg_color="transparent")
        btn_row.pack(pady=10)
        ctk.CTkButton(btn_row, text="💾  Save",
                      command=self._save_settings).pack(side="left", padx=10)
        ctk.CTkButton(btn_row, text="⚡ Generate demo models",
                      fg_color="#7a4520",
                      command=lambda: threading.Thread(
                          target=self._gen_demo_models_thread, daemon=True).start()
                      ).pack(side="left", padx=10)

        self.settings_status = ctk.CTkLabel(frame, text="", text_color="#2dc97e")
        self.settings_status.pack()
        return frame

    def _save_settings(self):
        try:
            import yaml
            cfg["scan"]["threshold"]       = round(self._threshold_val.get(), 1)
            cfg["scan"]["default_rows"]    = int(self._rows_val.get())
            cfg["monitor"]["interval_sec"] = int(self._interval_val.get())
            cfg["notifications"]["enabled"]        = self._notif_var.get()
            cfg["notifications"]["min_threat_lvl"] = self._notif_lvl.get()
            cfg["api"]["port"]             = int(self._api_port.get())
            p = Path(__file__).parent.parent / "config" / "config.yaml"
            with open(p, "w") as f:
                yaml.dump(cfg, f, allow_unicode=True, default_flow_style=False)
            self.settings_status.configure(text="✓ Saved в config.yaml")
        except Exception as e:
            self.settings_status.configure(text=f"Error: {e}", text_color="red")

    # ── О системе ────────────────────────────────────────────────

    def _page_about(self):
        frame = ctk.CTkFrame(self.main, fg_color="transparent")
        ctk.CTkLabel(frame, text="RootkitGuard",
                     font=ctk.CTkFont(size=28, weight="bold")).pack(pady=(40, 5))
        ctk.CTkLabel(frame,
                     text="ML-based Rootkit Anomaly Detection System",
                     font=ctk.CTkFont(size=14), text_color="gray").pack()
        ctk.CTkLabel(frame, text="IITU · Almaty · 2026",
                     font=ctk.CTkFont(size=13), text_color="gray").pack(pady=(0, 30))
        for key, val in [
            ("Algorithm",     "Random Forest + XGBoost + Isolation Forest"),
            ("Dataset",      "CIC-IDS2018 — 1,044,525 записей"),
            ("Accuracy",     "99.99% (F1-score on real dataset)"),
            ("ROC-AUC",      "0.9999"),
            ("v2.1",         "Without matplotlib, autorun API, unqiue reports, demo-models"),
            ("Authors",       "Amangeldi Manas · Kurmanov Iskander · Kuanyshbek Bekarys"),
            ("Supervisor", "Alin G.T."),
        ]:
            r = ctk.CTkFrame(frame, fg_color="#2b2b2b", corner_radius=8)
            r.pack(fill="x", padx=80, pady=3)
            ctk.CTkLabel(r, text=f"  {key}:", width=160, anchor="w",
                         font=ctk.CTkFont(weight="bold"),
                         text_color="gray").pack(side="left", pady=8)
            ctk.CTkLabel(r, text=val, anchor="w").pack(side="left", pady=8)
        return frame


if __name__ == "__main__":
    app = RootkitGuard()
    app.mainloop()
