"""
rootkitguard.py v2.1
ФИКСЫ:
  - Убран matplotlib/FigureCanvasTkAgg → нет PIL-конфликта
  - Кнопка автозапуска API прямо из GUI (▶ рядом с «API offline»)
  - Отчёты уникальные: имя файла + время скана в названии
  - Кнопка «Сгенерировать демо-модели» если моделей нет
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
from i18n import t, set_lang, get_lang

log = get_logger("gui")

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

API_BASE = f"http://127.0.0.1:{cfg.get('api', {}).get('port', 8000)}"


def generate_demo_models():
    """Создаёт рабочие модели на синтетических данных (~10 сек)."""
    from sklearn.ensemble import RandomForestClassifier, IsolationForest
    from sklearn.preprocessing import StandardScaler
    import xgboost as xgb

    log.info("Генерация демо-моделей...")
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
    log.info("Демо-модели сохранены")
    return rf, scaler


class RootkitGuard(ctk.CTk):
    def __init__(self, username: str = "admin"):
        super().__init__()
        self.username = username
        self.title(f"RootkitGuard — {self.username} — Система обнаружения аномалий v2.1")
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
            self.api_lbl.configure(text="● API уже запущен", text_color="#2dc97e")
            return
        try:
            main_py = str(Path(__file__).parent.parent / "main.py")
            self._api_proc = subprocess.Popen(
                [sys.executable, main_py, "api"],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            self.api_lbl.configure(text="● API запускается...", text_color="yellow")
            threading.Thread(target=self._wait_api, daemon=True).start()
        except Exception as e:
            log.error(f"API запуск: {e}")

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
            text="● API не отвечает", text_color="red"))

    def _auto_startup_scan(self):
        """При запуске автоматически делает Rootkit Scan в фоне."""
        import time
        time.sleep(3)
        log.info("Авто-сканирование при запуске...")
        try:
            checker = RootkitChecker()
            result  = checker.run_all()
            threat  = result.threat_level
            count   = len(result.findings)
            color   = {"ВЫСОКАЯ": "#e74c3c", "СРЕДНЯЯ": "#f39c12",
                       "ЧИСТАЯ": "#2dc97e"}.get(threat, "#2dc97e")
            msg = f"{t('auto_scan')}: {threat} · {t('findings')}: {count}"
            self._last_autoscan = (threat, count)
            self.after(0, lambda m=msg, c=color: self.api_lbl.configure(
                text=f"● {m}", text_color=c))
            notify_threat(threat, f"Авто-сканирование при запуске: {count} находок")
            if threat == "ВЫСОКАЯ":
                self.after(500, lambda: threading.Thread(
                    target=self._run_rootkit_local, daemon=True).start())
        except Exception as e:
           log.error(f"Авто-скан ошибка: {e}")
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
            ("  🏠  Главная",       "home"),
            ("  🔍  Сканирование",  "scan"),
            ("  🦠  Rootkit Scan",  "rootkit"),
            ("  👁   Мониторинг",   "monitor"),
            ("  📊  Аналитика",     "analytics"),
            ("  📄  Отчёт",         "report"),
            ("  ⚙️  Настройки",    "settings"),
            ("  ℹ️  О системе",     "about"),
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
        mt = "● Модель загружена" if self.model_loaded else "● Модель не найдена"
        self.model_lbl = ctk.CTkLabel(self.nav, text=mt,
                                       text_color=mc, font=ctk.CTkFont(size=11))
        self.model_lbl.pack(side="bottom", pady=(0, 2))

        # Переключатель языка
        lang_frame = ctk.CTkFrame(self.nav, fg_color="transparent")
        lang_frame.pack(side="bottom", fill="x", padx=8, pady=(0, 4))
        for lang, label in [("ru", "РУС"), ("en", "ENG"), ("kz", "ҚАЗ")]:
            ctk.CTkButton(lang_frame, text=label, width=55, height=22,
                          fg_color="#1e293b", hover_color="#2d3748",
                          font=ctk.CTkFont(size=10),
                          command=lambda l=lang: self._switch_lang(l)
                          ).pack(side="left", padx=2)
            

        # API статус + кнопка запуска
        api_row = ctk.CTkFrame(self.nav, fg_color="transparent")
        api_row.pack(side="bottom", fill="x", padx=8, pady=(0, 2))
        self.api_lbl = ctk.CTkLabel(api_row, text="● API проверка...",
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

    def _switch_lang(self, lang: str):
        set_lang(lang)
        # Пересоздаём все страницы
        for p in self.pages.values():
            p.destroy()
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
        # Обновляем навигацию
        pages_nav = [
            (t("home"),         "home"),
            (t("scan"),         "scan"),
            (t("rootkit_scan"), "rootkit"),
            (t("monitor"),      "monitor"),
            (t("analytics"),    "analytics"),
            (t("report"),       "report"),
            (t("settings"),     "settings"),
            (t("about"),        "about"),
        ]
        icons = ["🏠","🔍","🦠","👁","📊","📄","⚙️","ℹ️"]
        for (label, key), icon in zip(pages_nav, icons):
            if key in self.nav_buttons:
                self.nav_buttons[key].configure(text=f"  {icon}  {label}")
        # Обновляем статусы внизу панели
        mc = "#2dc97e" if self.model_loaded else "#e74c3c"
        mt = t("model_loaded") if self.model_loaded else t("model_not_found")
        self.model_lbl.configure(text=mt, text_color=mc)
        # Обновляем текст авто-скана если уже был
        if hasattr(self, '_last_autoscan'):
            threat, count = self._last_autoscan
            color = {"ВЫСОКАЯ": "#e74c3c", "СРЕДНЯЯ": "#f39c12",
                     "ЧИСТАЯ": "#2dc97e"}.get(threat, "#2dc97e")
            msg = f"{t('auto_scan')}: {threat} · {t('findings')}: {count}"
            self.api_lbl.configure(text=f"● {msg}", text_color=color)
        self.show_page("home")
        
    def _gen_demo_models_thread(self):
        self.model_lbl.configure(text="⏳ Генерация...", text_color="yellow")
        try:
            generate_demo_models()
            self._load_models()
            if self.model_loaded:
                self.model_lbl.configure(text="● Модель загружена", text_color="#2dc97e")
            else:
                self.model_lbl.configure(text="● Ошибка загрузки", text_color="red")
        except Exception as e:
            log.error(f"Demo model error: {e}")
            self.model_lbl.configure(text=f"● Ошибка", text_color="red")

    # ── Главная ─────────────────────────────────────────────────

    


    def _page_home(self):
        import time
        from pathlib import Path
    
        frame = ctk.CTkFrame(self.main, fg_color="transparent")
    
        # ── Топ-бар ───────────────────────────────────────────────
        topbar = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=12,
                              border_width=1, border_color="#1e293b", height=52)
        topbar.pack(fill="x", padx=16, pady=(8, 6))
        topbar.pack_propagate(False)
    
        ctk.CTkLabel(topbar, text="⬡  ROOTKITGUARD",
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#00d4ff").pack(side="left", padx=16, pady=10)
    
        # Разделитель
        ctk.CTkFrame(topbar, fg_color="#1e293b", width=1).pack(side="left", fill="y", pady=8)
    
        ctk.CTkLabel(topbar, text=f"  👤 {self.username}",
                     font=ctk.CTkFont(size=12),
                     text_color="#94a3b8").pack(side="left", padx=12)
    
        ctk.CTkFrame(topbar, fg_color="#1e293b", width=1).pack(side="left", fill="y", pady=8)
    
        self.home_time_lbl = ctk.CTkLabel(topbar, text="",
                                           font=ctk.CTkFont(size=12),
                                           text_color="#64748b")
        self.home_time_lbl.pack(side="left", padx=12)
    
        # Статус API справа
        self.home_api_lbl = ctk.CTkLabel(topbar, text="● API offline",
                                          font=ctk.CTkFont(size=11),
                                          text_color="#f39c12")
        self.home_api_lbl.pack(side="right", padx=16)
    
        def update_time():
            from datetime import datetime
            now = datetime.now().strftime("%d.%m.%Y  %H:%M:%S")
            try:
                self.home_time_lbl.configure(text=f"🕐  {now}")
                api_txt = "● API online" if self._api_available else "● API offline"
                api_col = "#00ff88" if self._api_available else "#f39c12"
                self.home_api_lbl.configure(text=api_txt, text_color=api_col)
                self.after(1000, update_time)
            except Exception:
                pass
        self.after(100, update_time)
    
        # ── Выбор модели ──────────────────────────────────────────
        ctk.CTkLabel(frame, text=t("choose_model"),
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="#475569").pack(anchor="w", padx=20, pady=(4, 6))
    
        models_frame = ctk.CTkFrame(frame, fg_color="transparent")
        models_frame.pack(fill="x", padx=16)
    
        model_data = [
            {
                "name":  "Random Forest",
                "short": "RF",
                "type":  "Supervised",
                "f1":    "1.0000",
                "auc":   "0.9999",
                "speed": "●●●●○",
                "desc":  t("rf_desc"),
                "color": "#0ea5e9",
                "bg":    "#0c1929",
            },
            {
                "name":  "XGBoost",
                "short": "XGB",
                "type":  "Supervised",
                "f1":    "1.0000",
                "auc":   "1.0000",
                "speed": "●●●○○",
                "desc":  t("xgb_desc"),
                "color": "#a855f7",
                "bg":    "#160d29",
            },
            {
                "name":  "Isolation Forest",
                "short": "ISO",
                "type":  "Unsupervised",
                "f1":    "0.0200",
                "auc":   "0.3258",
                "speed": "●●●●●",
                "desc":  t("iso_desc"),
                "color": "#f59e0b",
                "bg":    "#1a1200",
            },
            {
                "name":  t("ensemble"),
                "short": "ALL",
                "type":  "Hybrid",
                "f1":    "1.0000",
                "auc":   "0.9999",
                "speed": "●●○○○",
                "desc":  t("all_desc"),
                "color": "#00ff88",
                "bg":    "#001a0d",
            },
        ]
    
        self._selected_model = ctk.StringVar(value="Random Forest")
        self._model_cards = {}
    
        for i, m in enumerate(model_data):
            models_frame.grid_columnconfigure(i, weight=1)
            card = ctk.CTkFrame(models_frame, fg_color=m["bg"], corner_radius=12,
                                border_width=1, border_color="#1e293b",
                                cursor="hand2")
            card.grid(row=0, column=i, padx=5, sticky="ew")
    
            # Индикатор выбора
            indicator = ctk.CTkFrame(card, fg_color=m["color"], height=3,
                                      corner_radius=0)
            indicator.pack(fill="x")
            indicator.pack_forget()  # скрыт по умолчанию
    
            # Контент
            inner = ctk.CTkFrame(card, fg_color="transparent")
            inner.pack(fill="both", expand=True, padx=12, pady=10)
    
            # Шапка
            top = ctk.CTkFrame(inner, fg_color="transparent")
            top.pack(fill="x")
            ctk.CTkLabel(top, text=m["short"],
                         font=ctk.CTkFont(size=20, weight="bold"),
                         text_color=m["color"]).pack(side="left")
            ctk.CTkLabel(top, text=m["type"],
                         font=ctk.CTkFont(size=9),
                         text_color="#475569").pack(side="right", pady=(4, 0))
    
            ctk.CTkLabel(inner, text=m["name"],
                         font=ctk.CTkFont(size=11, weight="bold"),
                         text_color="#94a3b8", anchor="w").pack(anchor="w", pady=(2, 6))
    
            ctk.CTkLabel(inner, text=m["desc"],
                         font=ctk.CTkFont(size=10),
                         text_color="#64748b", justify="left", anchor="w").pack(anchor="w")
    
            # Метрики
            metrics = ctk.CTkFrame(inner, fg_color="transparent")
            metrics.pack(fill="x", pady=(8, 4))
            for label, val in [("F1", m["f1"]), ("AUC", m["auc"])]:
                mf = ctk.CTkFrame(metrics, fg_color="#0a0e1a", corner_radius=6)
                mf.pack(side="left", padx=(0, 4))
                ctk.CTkLabel(mf, text=label,
                             font=ctk.CTkFont(size=9),
                             text_color="#475569").pack(padx=6, pady=(4, 0))
                ctk.CTkLabel(mf, text=val,
                             font=ctk.CTkFont(size=11, weight="bold"),
                             text_color=m["color"]).pack(padx=6, pady=(0, 4))
    
            ctk.CTkLabel(inner, text=f"{t('speed')} {m['speed']}",
                         font=ctk.CTkFont(size=10),
                         text_color="#475569", anchor="w").pack(anchor="w")
    
            self._model_cards[m["name"]] = (card, indicator)
    
            def on_click(name=m["name"]):
                self._selected_model.set(name)
                self._highlight_model(name)
                # Синхронизируем с выбором на странице сканирования
                if hasattr(self, 'model_choice'):
                    self.model_choice.set(name)
    
            card.bind("<Button-1>", lambda e, n=m["name"]: on_click(n))
            for w in card.winfo_children():
                w.bind("<Button-1>", lambda e, n=m["name"]: on_click(n))
    
        # Подсветить RF по умолчанию
        self.after(200, lambda: self._highlight_model("Random Forest"))
    
        # ── Drag & Drop зона ──────────────────────────────────────
        ctk.CTkLabel(frame, text=t("load_dataset"),
                     font=ctk.CTkFont(size=11, weight="bold"),
                     text_color="#475569").pack(anchor="w", padx=20, pady=(14, 6))
    
        drop_zone = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=12,
                                  border_width=1, border_color="#1e293b",
                                  height=90, cursor="hand2")
        drop_zone.pack(fill="x", padx=16)
        drop_zone.pack_propagate(False)
    
        drop_inner = ctk.CTkFrame(drop_zone, fg_color="transparent")
        drop_inner.place(relx=0.5, rely=0.5, anchor="center")
    
        self.drop_icon = ctk.CTkLabel(drop_inner, text="📂",
                                       font=ctk.CTkFont(size=24))
        self.drop_icon.pack(side="left", padx=(0, 10))
    
        drop_text_frame = ctk.CTkFrame(drop_inner, fg_color="transparent")
        drop_text_frame.pack(side="left")
    
        self.drop_lbl = ctk.CTkLabel(drop_text_frame,
                                      text=t("drag_drop"),
                                      font=ctk.CTkFont(size=12, weight="bold"),
                                      text_color="#94a3b8")
        self.drop_lbl.pack(anchor="w")
    
        self.drop_sub = ctk.CTkLabel(drop_text_frame,
                                      text=t("supported_files"),
                                      font=ctk.CTkFont(size=10),
                                      text_color="#475569")
        self.drop_sub.pack(anchor="w")
    
        def on_drop_click(e=None):
            from tkinter import filedialog
            path = filedialog.askopenfilename(filetypes=[
                ("Все файлы", "*.*"),
                ("CSV", "*.csv"),
                ("Логи", "*.log"),
                ("Текст", "*.txt"),
            ])
            if path:
                fname = Path(path).name
                self.drop_lbl.configure(text=f"✓  {fname}", text_color="#00ff88")
                self.drop_sub.configure(text=path, text_color="#475569")
                self.drop_icon.configure(text="✅")
                drop_zone.configure(border_color="#00ff88")
                # Передаём в сканирование
                if hasattr(self, 'file_path'):
                    self.file_path.delete(0, "end")
                    self.file_path.insert(0, path)
                self._home_selected_file = path
    
        drop_zone.bind("<Button-1>", on_drop_click)
        drop_inner.bind("<Button-1>", on_drop_click)
        for w in drop_inner.winfo_children():
            w.bind("<Button-1>", on_drop_click)
    
        # ── Кнопка запуска ────────────────────────────────────────
        launch_frame = ctk.CTkFrame(frame, fg_color="transparent")
        launch_frame.pack(fill="x", padx=16, pady=(10, 6))
        launch_frame.grid_columnconfigure(0, weight=3)
        launch_frame.grid_columnconfigure(1, weight=1)
        launch_frame.grid_columnconfigure(2, weight=1)
    
        def launch_scan():
            if hasattr(self, '_home_selected_file'):
                self.show_page("scan")
                self.after(100, self._run_scan)
            else:
                self.show_page("scan")
    
        ctk.CTkButton(launch_frame,
                      text=t("run_analysis"),
                      height=46, corner_radius=10,
                      fg_color="#00d4ff", hover_color="#00b8d9",
                      text_color="#000000",
                      font=ctk.CTkFont(size=14, weight="bold"),
                      command=launch_scan
                      ).grid(row=0, column=0, padx=(0, 6), sticky="ew")
    
        ctk.CTkButton(launch_frame,
                      text=t("rootkit_scan_btn"),
                      height=46, corner_radius=10,
                      fg_color="#1e293b", hover_color="#2d3748",
                      text_color="#e2e8f0",
                      font=ctk.CTkFont(size=13),
                      command=lambda: self.show_page("rootkit")
                      ).grid(row=0, column=1, padx=(0, 6), sticky="ew")
    
        ctk.CTkButton(launch_frame,
                      text=t("analytics_btn"),
                      height=46, corner_radius=10,
                      fg_color="#1e293b", hover_color="#2d3748",
                      text_color="#e2e8f0",
                      font=ctk.CTkFont(size=13),
                      command=lambda: self.show_page("analytics")
                      ).grid(row=0, column=2, sticky="ew")
    
        # ── Системный журнал ──────────────────────────────────────
        log_frame = ctk.CTkFrame(frame, fg_color="#0d1117", corner_radius=12,
                                  border_width=1, border_color="#1e293b")
        log_frame.pack(fill="both", expand=True, padx=16, pady=(6, 10))
    
        log_hdr = ctk.CTkFrame(log_frame, fg_color="transparent")
        log_hdr.pack(fill="x", padx=12, pady=(8, 4))
        ctk.CTkLabel(log_hdr, text=t("system_log"),
                     font=ctk.CTkFont(size=10, weight="bold"),
                     text_color="#475569").pack(side="left")
        self.log_dot = ctk.CTkLabel(log_hdr, text="●",
                                     font=ctk.CTkFont(size=10),
                                     text_color="#00ff88")
        self.log_dot.pack(side="right")
    
        lb = ctk.CTkTextbox(log_frame,
                             font=ctk.CTkFont(family="monospace", size=11),
                             fg_color="transparent",
                             text_color="#64748b")
        lb.pack(fill="both", expand=True, padx=8, pady=(0, 8))
    
        for e in [
            f"[BOOT]   {t('boot_msg')}",
            f"[AUTH]   {t('auth_msg')}: {self.username}",
            f"[CONFIG] {t('config_msg')}",
            f"[ML]     {t('ml_loaded') if self.model_loaded else t('model_not_found')}",
            f"[SCAN]   {t('scan_started')}",
            f"[READY]  {t('ready_msg')}",
        ]:
            lb.insert("end", e + "\n")
        lb.configure(state="disabled")
    
        return frame
    
    
    def _highlight_model(self, name: str):
        """Подсветить выбранную модель."""
        for mname, (card, indicator) in self._model_cards.items():
            if mname == name:
                card.configure(border_color={
                    "Random Forest":    "#0ea5e9",
                    "XGBoost":          "#a855f7",
                    "Isolation Forest": "#f59e0b",
                    "Ансамбль":         "#00ff88",
                }.get(name, "#00d4ff"))
                indicator.pack(fill="x", before=card.winfo_children()[1]
                              if len(card.winfo_children()) > 1 else card.winfo_children()[0])
            else:
                card.configure(border_color="#1e293b")
                indicator.pack_forget()
    
            # ── CSV Сканирование ─────────────────────────────────────────
    def _page_scan(self):
        frame = ctk.CTkFrame(self.main, fg_color="transparent")

        # Заголовок
        hdr = ctk.CTkFrame(frame, fg_color="#0d1b3e", corner_radius=12,
                           border_width=1, border_color="#1f538d")
        hdr.pack(fill="x", padx=20, pady=(10, 5))
        ctk.CTkLabel(hdr, text="🔍  Сканирование файлов",
                     font=ctk.CTkFont(size=20, weight="bold")).pack(side="left", padx=16, pady=12)
        ctk.CTkLabel(hdr, text="ML-анализ · Random Forest · XGBoost",
                     font=ctk.CTkFont(size=11), text_color="#85B7EB").pack(side="left")

        # Выбор файла
        ff = ctk.CTkFrame(frame, fg_color="#1e1e2e", corner_radius=10)
        ff.pack(fill="x", padx=20, pady=4)
        ctk.CTkLabel(ff, text=t("file_label"),
                     font=ctk.CTkFont(size=13, weight="bold"),
                     text_color="#85B7EB").pack(side="left", padx=14, pady=12)
        self.file_path = ctk.CTkEntry(ff, width=400,
                                       placeholder_text="Выбери CSV файл...",
                                       font=ctk.CTkFont(size=12))
        self.file_path.pack(side="left", padx=5)
        ctk.CTkButton(ff, text="📁 Обзор", width=100, height=32,
                      fg_color="#2d6a4f",
                      command=self._browse_file).pack(side="left", padx=5)

        # Параметры
        pf = ctk.CTkFrame(frame, fg_color="#1e1e2e", corner_radius=10)
        pf.pack(fill="x", padx=20, pady=4)
        ctk.CTkLabel(pf, text="Порог:", font=ctk.CTkFont(size=12)).pack(side="left", padx=14, pady=10)
        self.threshold = ctk.CTkSlider(pf, from_=0.1, to=0.9, number_of_steps=8, width=160)
        self.threshold.set(0.5)
        self.threshold.pack(side="left", padx=5)
        self.thresh_lbl = ctk.CTkLabel(pf, text="0.5",
                                        font=ctk.CTkFont(size=12, weight="bold"),
                                        text_color="#2dc97e")
        self.thresh_lbl.pack(side="left")
        self.threshold.configure(command=lambda v: self.thresh_lbl.configure(text=f"{v:.1f}"))
        ctk.CTkLabel(pf, text="  Строк:", font=ctk.CTkFont(size=12)).pack(side="left", padx=10)
        self.n_rows = ctk.CTkEntry(pf, width=80, placeholder_text="10000")
        self.n_rows.pack(side="left", padx=5)
        self.use_api_var = ctk.BooleanVar(value=True)
        ctk.CTkCheckBox(pf, text=t("via_api"), variable=self.use_api_var).pack(side="left", padx=15)
        ctk.CTkButton(pf, text="▶  ЗАПУСТИТЬ АНАЛИЗ", height=36, width=200,
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
        self.scan_status = ctk.CTkLabel(frame, text=t("waiting"),
                                         text_color="gray", font=ctk.CTkFont(size=12))
        self.scan_status.pack()

        # Карточки результатов
        cards_frame = ctk.CTkFrame(frame, fg_color="transparent")
        cards_frame.pack(fill="x", padx=20, pady=6)
        card_data = [
            ("total_lbl",  "📊 Всего записей", "—", "#1a3a5c", "#3498db"),
            ("normal_lbl", "✅ Нормальных",    "—", "#1a3a2a", "#2dc97e"),
            ("anom_lbl",   "⚠️ Аномалий",      "—", "#3a1a1a", "#e74c3c"),
            ("threat_lbl", "🛡 Угроза",        "—", "#2a1a3a", "#9b59b6"),
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
        ctk.CTkLabel(log_frame, text=t("scan_details"),
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color="#85B7EB").pack(anchor="w", padx=12, pady=(8, 2))
        self.scan_result = ctk.CTkTextbox(
            log_frame, font=ctk.CTkFont(family="monospace", size=11))
        self.scan_result.pack(fill="both", expand=True, padx=8, pady=(0, 8))

        # История справа
        hist_frame = ctk.CTkFrame(bottom, fg_color="#1e1e2e", corner_radius=10)
        hist_frame.grid(row=0, column=1, sticky="nsew", padx=(4, 0))
        ctk.CTkLabel(hist_frame, text=t("history"),
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color="#85B7EB").pack(anchor="w", padx=12, pady=(8, 4))
        self.scan_history_box = ctk.CTkTextbox(
            hist_frame, font=ctk.CTkFont(family="monospace", size=10))
        self.scan_history_box.pack(fill="both", expand=True, padx=8, pady=(0, 8))
        self.scan_history_box.insert("end", t("no_scans") + "\n")
        self.scan_history_box.configure(state="disabled")

        # Кнопка PDF после скана
        self.scan_pdf_btn = ctk.CTkButton(
            frame, text=t("create_pdf"), height=40,
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
                ("Все файлы",        "*.*"),
                ("CSV файлы",        "*.csv"),
                ("Текстовые файлы",  "*.txt"),
                ("Лог файлы",        "*.log"),
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
            self.scan_status.configure(text="Загрузка...", text_color="yellow")
            self.scan_progress.set(0.1)
            log_ui(f"[{ts}] Файл: {path}")

            if self.use_api_var.get() and self._api_available:
                log_ui("[*] Отправка в API /scan ...")
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
                log_ui(f"[!] API {resp.status_code} — локальный режим")

            log_ui("[*] Локальный анализ...")
            df = pd.read_csv(path, nrows=n)
            log_ui(f"[+] Строк: {len(df):,}")
            self.scan_progress.set(0.3)

            if "Label"     in df.columns: df = df.drop(columns=["Label"])
            if "Timestamp" in df.columns: df = df.drop(columns=["Timestamp"])
            df = df.replace([np.inf, -np.inf], np.nan).fillna(0)
            self.scan_progress.set(0.5)
            self.scan_status.configure(text="Анализ моделью...")

            if self.model_loaded:
                X    = pd.DataFrame(self.scaler.transform(df), columns=df.columns)
                cols = self.rf.feature_names_in_
                for c in cols:
                    if c not in X.columns: X[c] = 0
                X     = X[cols]
                preds = self.rf.predict(X)
                proba = self.rf.predict_proba(X)[:, 1]
            else:
                log_ui("[!] Модель не загружена — демо-режим")
                preds = np.random.choice([0, 1], size=len(df), p=[0.75, 0.25])
                proba = np.random.uniform(0, 1, size=len(df))

            self.scan_progress.set(0.85)
            n_anom = int(preds.sum())
            n_norm = len(preds) - n_anom
            pct    = n_anom / len(preds) * 100
            threat = "ВЫСОКАЯ" if pct > 20 else "СРЕДНЯЯ" if pct > 5 else "НИЗКАЯ"
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
            self._print_results(log_ui, data, "локальный")
            self.scan_progress.set(1.0)
            notify_threat(threat, f"{Path(path).name}: {n_anom} аномалий ({pct:.1f}%)")
            # При ВЫСОКОЙ угрозе — автоматически запускаем Rootkit Scan
            if threat == "ВЫСОКАЯ":
                log_ui("\n  🔴 ВЫСОКАЯ УГРОЗА — автоматически запускаю Rootkit Scan...")
                self.after(1000, lambda: threading.Thread(
                    target=self._run_rootkit_local, daemon=True).start())

        except Exception as e:
            log_ui(f"[!] Ошибка: {e}")
            log.error(f"Scan error: {e}")
            self.scan_status.configure(text="Ошибка!", text_color="red")

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
        color_map = {"ВЫСОКАЯ": "#e74c3c", "СРЕДНЯЯ": "#f39c12", "НИЗКАЯ": "#2dc97e"}
        threat_color = color_map.get(threat, "white")
        self.after(0, lambda: [
            self.total_lbl.configure(text=f"{total:,}"),
            self.normal_lbl.configure(text=f"{norm:,}"),
            self.anom_lbl.configure(text=f"{anom:,}\n({pct:.1f}%)"),
            self.threat_lbl.configure(text=threat, text_color=threat_color),
        ])

        # Лог
        log_ui(f"\n{'='*48}")
        log_ui(f"  РЕЗУЛЬТАТЫ [{mode.upper()}]")
        log_ui(f"{'='*48}")
        log_ui(f"  Всего:         {total:,}")
        log_ui(f"  Нормальных:    {norm:,}")
        log_ui(f"  Аномалий:      {anom:,}  ({pct:.2f}%)")
        if data.get("max_proba"):
            log_ui(f"  Макс. вер-ть:  {data['max_proba']:.4f}")
        log_ui(f"  Угроза:        {threat}")
        if data.get("top_ports"):
            log_ui(f"  Топ порты:     {data['top_ports']}")
        log_ui(f"{'='*48}")

        # Активируем кнопку PDF
        # Меняем цвет прогресс-бара по угрозе
        bar_color = {"ВЫСОКАЯ": "#e74c3c", "СРЕДНЯЯ": "#f39c12",
                     "НИЗКАЯ": "#2dc97e"}.get(threat, "#2dc97e")
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
                log_ui(f"\n  ✅ Улучшение: аномалий было {prev_anom}, стало {curr_anom}")
            elif curr_anom > prev_anom:
                log_ui(f"\n  ⚠️  Ухудшение: аномалий было {prev_anom}, стало {curr_anom}")
            else:
                log_ui(f"\n  ➡️  Без изменений: {curr_anom} аномалий")

        self.scan_status.configure(
            text=f"✓ Готово — угроза: {threat}", text_color=threat_color)

    def _update_scan_history(self):
        self.scan_history_box.configure(state="normal")
        self.scan_history_box.delete("1.0", "end")
        colors = {"ВЫСОКАЯ": "🔴", "СРЕДНЯЯ": "🟡", "НИЗКАЯ": "🟢"}
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
                     text="Полная проверка: скрытые процессы · модули ядра · LD_PRELOAD · привилегии",
                     font=ctk.CTkFont(size=12), text_color="gray").pack(pady=(0, 8))

        ctrl = ctk.CTkFrame(frame)
        ctrl.pack(fill="x", padx=20, pady=5)
        self.rk_status = ctk.CTkLabel(ctrl, text="Готов к сканированию",
                                       text_color="gray", font=ctk.CTkFont(size=13))
        self.rk_status.pack(side="left", padx=15, pady=10)
        self.rk_threat_lbl = ctk.CTkLabel(ctrl, text="",
                                           font=ctk.CTkFont(size=14, weight="bold"))
        self.rk_threat_lbl.pack(side="left", padx=10)

        btns = ctk.CTkFrame(ctrl, fg_color="transparent")
        btns.pack(side="right", padx=10)
        ctk.CTkButton(btns, text="▶  Полная проверка системы", width=200, height=38,
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
            ("Скрытые\nпроцессы",  "🔎"),
            ("Модули\nядра",        "🧩"),
            ("LD_PRELOAD",          "💉"),
            ("Подозр.\nпорты",      "🔌"),
            ("Системные\nфайлы",    "📁"),
            ("Привилегии\nUID=0",   "🔑"),
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
        self.rk_status.configure(text="Сканирование системы...", text_color="yellow")
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
                ("Скрытые процессы",    checker.check_hidden_processes),
                ("Модули ядра",         checker.check_kernel_modules),
                ("LD_PRELOAD",          checker.check_ld_preload),
                ("Подозр. порты",       checker.check_suspicious_ports),
                ("Системные файлы",     checker.check_system_files),
                ("Привилегии",          checker.check_privilege_escalation),
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
                            icon = "🔴" if f.severity == "ВЫСОКАЯ" else "🟡"
                            log_ui(f"   {icon} {f.description}")
                            if f.detail:
                                log_ui(f"      → {f.detail[:100]}")
                    else:
                        self.after(0, lambda c=card, l=lbl: (
                            c.configure(fg_color="#1a3a1a"),
                            l.configure(text="✓ OK", text_color="#2dc97e")))
                        log_ui(f"   ✅ Чисто")
                except Exception as e:
                    log_ui(f"   [!] Ошибка: {e}")

            threat = ("ВЫСОКАЯ" if any(f.severity == "ВЫСОКАЯ" for f in all_findings)
                      else "СРЕДНЯЯ" if any(f.severity == "СРЕДНЯЯ" for f in all_findings)
                      else "НИЗКАЯ" if all_findings else "ЧИСТАЯ")
            color = {"ВЫСОКАЯ": "#e74c3c", "СРЕДНЯЯ": "#f39c12",
                     "НИЗКАЯ": "#f39c12", "ЧИСТАЯ": "#2dc97e"}.get(threat, "gray")

            log_ui(f"\n{'='*52}")
            log_ui("  ИТОГ ROOTKIT SCAN")
            log_ui(f"{'='*52}")
            log_ui(f"  Проверок выполнено:  {len(check_fns)}")
            log_ui(f"  Находок:             {len(all_findings)}")
            log_ui(f"  Уровень угрозы:      {threat}")
            if not all_findings:
                log_ui("\n  ✅ Система чиста. Признаков rootkit не обнаружено.")
            log_ui(f"{'='*52}")

            self.rk_status.configure(text="Завершено", text_color="#2dc97e")
            self.rk_threat_lbl.configure(text=f"Угроза: {threat}", text_color=color)
            self.rk_progress.set(1.0)
            notify_threat(threat, f"Rootkit scan: {len(all_findings)} находок")

        except Exception as e:
            log_ui(f"[!] Ошибка: {e}")
            log.error(f"Rootkit error: {e}")
            self.rk_status.configure(text="Ошибка!", text_color="red")

        self.rk_output.configure(state="disabled")

    def _run_rootkit_api(self):
        self.rk_output.configure(state="normal")
        self.rk_output.delete("1.0", "end")

        def log_ui(msg):
            self.rk_output.insert("end", msg + "\n")
            self.rk_output.see("end")

        try:
            self.rk_status.configure(text="Запрос к API...", text_color="yellow")
            log_ui("[*] POST /rootkit/scan ...")
            resp = requests.post(f"{API_BASE}/rootkit/scan", timeout=30)
            if resp.status_code == 200:
                data  = resp.json()
                threat = data.get("threat_level", "—")
                color  = {"ВЫСОКАЯ":"#e74c3c","СРЕДНЯЯ":"#f39c12",
                          "ЧИСТАЯ":"#2dc97e"}.get(threat, "gray")
                log_ui(f"[+] Угроза: {threat}")
                log_ui(f"[+] Находок: {data.get('findings_count', 0)}")
                for f in data.get("findings", []):
                    log_ui(f"  [{f['severity']}] {f['description']}")
                self.rk_status.configure(text="Готово (API)", text_color="#2dc97e")
                self.rk_threat_lbl.configure(text=f"Угроза: {threat}", text_color=color)
            else:
                log_ui(f"[!] API ошибка: {resp.status_code}")
        except Exception as e:
            log_ui(f"[!] API недоступен: {e}")
            log_ui("[*] Нажми ▶ в боковой панели чтобы запустить API")

        self.rk_output.configure(state="disabled")

    # ── Мониторинг ───────────────────────────────────────────────

    def _page_monitor(self):
        frame = ctk.CTkFrame(self.main, fg_color="transparent")
        ctk.CTkLabel(frame, text="Мониторинг процессов",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(pady=(10, 5))

        ctrl = ctk.CTkFrame(frame)
        ctrl.pack(fill="x", padx=20, pady=5)
        self.mon_status = ctk.CTkLabel(ctrl, text="● Остановлен",
                                        text_color="#e74c3c",
                                        font=ctk.CTkFont(size=13))
        self.mon_status.pack(side="left", padx=15, pady=10)
        self.mon_count = ctk.CTkLabel(ctrl, text="Процессов: —",
                                       text_color="gray", font=ctk.CTkFont(size=13))
        self.mon_count.pack(side="left", padx=10)
        self.mon_threats = ctk.CTkLabel(ctrl, text="Угроз: —",
                                         text_color="gray", font=ctk.CTkFont(size=13))
        self.mon_threats.pack(side="left", padx=10)
        ctk.CTkLabel(ctrl, text="Фильтр:").pack(side="left", padx=(20, 5))
        self.mon_filter = ctk.CTkComboBox(
            ctrl, values=["Все", "ВЫСОКАЯ", "СРЕДНЯЯ", "НИЗКАЯ"], width=120)
        self.mon_filter.set("Все")
        self.mon_filter.pack(side="left", padx=5)
        self.mon_filter.configure(command=lambda v: self._refresh_monitor_table())
        self.btn_start_mon = ctk.CTkButton(ctrl, text="▶ Запустить", width=120,
                                            fg_color="#2d6a4f",
                                            command=self._start_monitor)
        self.btn_start_mon.pack(side="right", padx=5, pady=8)
        self.btn_stop_mon = ctk.CTkButton(ctrl, text="■ Стоп", width=110,
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
        for col, w in [("PID",60),("Процесс",185),("CPU%",60),
                        ("RAM MB",70),("Conn",50),("Score",75),("Угроза",95)]:
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
        data = (self._monitor_data if filt == "Все"
                else [r for r in self._monitor_data if r["threat"] == filt])
        threats = sum(1 for r in self._monitor_data if r["threat"] != "НИЗКАЯ")
        self.mon_count.configure(text=f"Процессов: {len(self._monitor_data)}")
        self.mon_threats.configure(
            text=f"Угроз: {threats}",
            text_color="#e74c3c" if threats > 0 else "#2dc97e")
        c_map = {"ВЫСОКАЯ": "#e74c3c", "СРЕДНЯЯ": "#f39c12", "НИЗКАЯ": "#2dc97e"}
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
        self.mon_status.configure(text="● Активен", text_color="#2dc97e")
        self.btn_start_mon.configure(state="disabled")
        self.btn_stop_mon.configure(state="normal")

    def _stop_monitor(self):
        self._monitor.stop_realtime()
        self.mon_status.configure(text="● Остановлен", text_color="#e74c3c")
        self.btn_start_mon.configure(state="normal")
        self.btn_stop_mon.configure(state="disabled")

    # ── Аналитика (без matplotlib) ───────────────────────────────

    def _page_analytics(self):
        frame = ctk.CTkFrame(self.main, fg_color="transparent")
        ctk.CTkLabel(frame, text="Аналитика моделей",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(pady=(10, 10))

        # Таблица метрик
        tbl = ctk.CTkFrame(frame, fg_color="#1a1a2e", corner_radius=10)
        tbl.pack(fill="x", padx=20, pady=5)
        hdr = ctk.CTkFrame(tbl, fg_color="#1f538d", corner_radius=0)
        hdr.pack(fill="x")
        for col, w in [("Модель",180),("F1",90),("ROC-AUC",90),("FPR",80),("FNR",80),("Тип",110)]:
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
        ctk.CTkLabel(frame, text="F1-score (визуализация)",
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
            ("Датасет",  "CIC-IDS2018 — 1,044,525 записей"),
            ("Классы",   "Benign: 758,334 (72.5%)  |  Bot: 286,191 (27.5%)"),
            ("Признаки", "78 сетевых признаков"),
            ("Обучение", "80/20 stratified split, RandomState=42"),
        ]:
            r = ctk.CTkFrame(info, fg_color="transparent")
            r.pack(fill="x", padx=12, pady=3)
            ctk.CTkLabel(r, text=f"{key}:", width=100, anchor="w",
                         font=ctk.CTkFont(weight="bold"),
                         text_color="#85B7EB").pack(side="left")
            ctk.CTkLabel(r, text=val, anchor="w").pack(side="left")
        return frame

    # ── Отчёт ────────────────────────────────────────────────────

    def _page_report(self):
        frame = ctk.CTkFrame(self.main, fg_color="transparent")
        ctk.CTkLabel(frame, text="Генерация отчёта",
                     font=ctk.CTkFont(size=22, weight="bold")).pack(pady=(10, 5))

        # Инфо о последнем скане
        info_frame = ctk.CTkFrame(frame, fg_color="#1a2a1a", corner_radius=10)
        info_frame.pack(fill="x", padx=20, pady=5)
        self.report_info_lbl = ctk.CTkLabel(
            info_frame,
            text="Последний скан: нет данных. Сначала выполни сканирование.",
            text_color="#85B7EB", font=ctk.CTkFont(size=12))
        self.report_info_lbl.pack(padx=12, pady=8, anchor="w")

        btn_row = ctk.CTkFrame(frame, fg_color="transparent")
        btn_row.pack(pady=8)
        ctk.CTkButton(btn_row, text="📄  Текстовый (.txt)", height=42, width=190,
                      command=self._gen_text_report).pack(side="left", padx=8)
        ctk.CTkButton(btn_row, text="📕  PDF (ReportLab)", height=42, width=190,
                      fg_color="#7a1e1e",
                      command=lambda: threading.Thread(
                          target=self._gen_pdf_report, daemon=True).start()
                      ).pack(side="left", padx=8)
        ctk.CTkButton(btn_row, text="🔄  Обновить инфо", height=42, width=160,
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
                text="Последний скан: нет данных. Сначала выполни сканирование.")
            return
        self.report_info_lbl.configure(
            text=f"Файл: {s['filename']}   |   {s['timestamp']}   |   "
                 f"Аномалий: {s['anomaly']:,}/{s['total']:,} ({s['pct']:.1f}%)   |   "
                 f"Угроза: {s['threat']}")

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
║          ROOTKITGUARD — ОТЧЁТ АНАЛИЗА СИСТЕМЫ           ║
╚══════════════════════════════════════════════════════════╝
  Дата:        {s['timestamp'] or datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
  Версия:      RootkitGuard v{cfg.get('app',{}).get('version','2.1')}
  Файл:        {s['filename'] or '—'}
  Путь:        {s.get('filepath','—')}
──────────────────────────────────────────────────────────
  РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ
──────────────────────────────────────────────────────────
  Всего записей:      {s['total']:,}
  Нормальных:         {s['normal']:,}
  Аномалий (Bot):     {s['anomaly']:,}  ({s['pct']:.2f}%)
  Макс. вероятность:  {s.get('max_proba', 0):.4f}
  Уровень угрозы:     {s['threat']}
  Топ порты:          {s.get('top_ports', []) or '—'}
──────────────────────────────────────────────────────────
  МЕТРИКИ МОДЕЛЕЙ
──────────────────────────────────────────────────────────
  Random Forest    F1:1.0000  ROC-AUC:0.9999  FPR:0.0001
  XGBoost          F1:1.0000  ROC-AUC:1.0000  FPR:0.0000
  Isolation Forest F1:0.0200  ROC-AUC:0.3258  FPR:0.3666
  Ensemble         F1:1.0000  ROC-AUC:0.9999  FPR:0.0000
──────────────────────────────────────────────────────────
  ЗАКЛЮЧЕНИЕ
──────────────────────────────────────────────────────────
  {'⚠  НЕМЕДЛЕННОЕ РАССЛЕДОВАНИЕ ТРЕБУЕТСЯ' if s['threat']=='ВЫСОКАЯ'
   else '⚡ Рекомендуется усиленный мониторинг' if s['threat']=='СРЕДНЯЯ'
   else '✅ Система работает в штатном режиме'}
──────────────────────────────────────────────────────────
  МУИТ · Алматы · 2026 · Alin G.T.
"""
        self.report_box.insert("end", rpt)
        self.report_box.configure(state="disabled")
        Path("reports").mkdir(exist_ok=True)
        out_path.write_text(rpt, encoding="utf-8")
        self.report_status.configure(text=f"✓ Сохранено: reports/{out_name}")

    def _gen_pdf_report(self):
        self._update_report_info()
        try:
            from pdf_report import generate_pdf_report
            self.report_status.configure(text="Генерация PDF...", text_color="yellow")
            s = self._last_scan
            out_name = self._unique_name("pdf")
            out_path = str(Path("reports") / out_name)
            Path("reports").mkdir(exist_ok=True)

            scan_data = {
                "total_rows": s["total"],
                "anomalies":  s["anomaly"],
                "normal":     s["normal"],
                "pct":        s["pct"],
                "threat":     s["threat"] if s["threat"] != "—" else "НИЗКАЯ",
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
                f"PDF-отчёт сгенерирован:\n"
                f"  reports/{out_name}\n\n"
                f"Файл скана:  {s['filename']}\n"
                f"Время:       {s['timestamp']}\n"
                f"Аномалий:    {s['anomaly']:,} ({s['pct']:.2f}%)\n"
                f"Угроза:      {s['threat']}\n\n"
                f"Открой файл из папки reports/")
            self.report_box.configure(state="disabled")
        except Exception as e:
            self.report_status.configure(text=f"Ошибка PDF: {e}", text_color="red")
            log.error(f"PDF error: {e}")

    # ── Настройки ────────────────────────────────────────────────

    def _page_settings(self):
        frame = ctk.CTkFrame(self.main, fg_color="transparent")
        ctk.CTkLabel(frame, text="Настройки",
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

        section("Сканирование")
        self._threshold_val = ctk.DoubleVar(
            value=cfg.get("scan", {}).get("threshold", 0.5))
        def thresh_row(p):
            sl = ctk.CTkSlider(p, from_=0.1, to=0.9, number_of_steps=8,
                               variable=self._threshold_val, width=180)
            sl.pack(side="left", padx=5)
            ctk.CTkLabel(p, textvariable=self._threshold_val).pack(side="left")
        row("Порог аномалии", thresh_row)

        self._rows_val = ctk.StringVar(
            value=str(cfg.get("scan", {}).get("default_rows", 10000)))
        row("Строк по умолчанию",
            lambda p: ctk.CTkEntry(p, textvariable=self._rows_val, width=120
                                   ).pack(side="left", padx=5, pady=10))

        section("Мониторинг")
        self._interval_val = ctk.StringVar(
            value=str(cfg.get("monitor", {}).get("interval_sec", 5)))
        row("Интервал обновления (сек)",
            lambda p: ctk.CTkEntry(p, textvariable=self._interval_val, width=80
                                   ).pack(side="left", padx=5, pady=10))

        section("Уведомления")
        self._notif_var = ctk.BooleanVar(
            value=cfg.get("notifications", {}).get("enabled", True))
        row("Включить уведомления",
            lambda p: ctk.CTkSwitch(p, text="", variable=self._notif_var
                                    ).pack(side="left", padx=5, pady=10))
        self._notif_lvl = ctk.StringVar(
            value=cfg.get("notifications", {}).get("min_threat_lvl", "СРЕДНЯЯ"))
        row("Мин. уровень уведомления",
            lambda p: ctk.CTkComboBox(
                p, values=["НИЗКАЯ", "СРЕДНЯЯ", "ВЫСОКАЯ"],
                variable=self._notif_lvl, width=150
            ).pack(side="left", padx=5, pady=10))

        section("API")
        self._api_port = ctk.StringVar(
            value=str(cfg.get("api", {}).get("port", 8000)))
        row("Порт API",
            lambda p: ctk.CTkEntry(p, textvariable=self._api_port, width=100
                                   ).pack(side="left", padx=5, pady=10))

        btn_row = ctk.CTkFrame(frame, fg_color="transparent")
        btn_row.pack(pady=10)
        ctk.CTkButton(btn_row, text="💾  Сохранить",
                      command=self._save_settings).pack(side="left", padx=10)
        ctk.CTkButton(btn_row, text="⚡ Сгенерировать демо-модели",
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
            self.settings_status.configure(text="✓ Сохранено в config.yaml")
        except Exception as e:
            self.settings_status.configure(text=f"Ошибка: {e}", text_color="red")

    # ── О системе ────────────────────────────────────────────────

    def _page_about(self):
        frame = ctk.CTkFrame(self.main, fg_color="transparent")
        ctk.CTkLabel(frame, text="RootkitGuard",
                     font=ctk.CTkFont(size=28, weight="bold")).pack(pady=(40, 5))
        ctk.CTkLabel(frame,
                     text="Система обнаружения rootkit-подобных аномалий на основе ML",
                     font=ctk.CTkFont(size=14), text_color="gray").pack()
        ctk.CTkLabel(frame, text="МУИТ · Алматы · 2026",
                     font=ctk.CTkFont(size=13), text_color="gray").pack(pady=(0, 30))
        for key, val in [
            ("Алгоритм",     "Random Forest + XGBoost + Isolation Forest"),
            ("Датасет",      "CIC-IDS2018 — 1,044,525 записей"),
            ("Точность",     "99.99% (F1-score на реальном датасете)"),
            ("ROC-AUC",      "0.9999"),
            ("v2.1",         "Без matplotlib, автозапуск API, уникальные отчёты, демо-модели"),
            ("Авторы",       "Амангелды Манас · Курманов Искандер · Куанышбек Бекарыс"),
            ("Руководитель", "Alin G.T."),
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
