"""
process_monitor.py — мониторинг процессов через psutil.
ИСПРАВЛЕНО: proc.connections() → proc.net_connections() (psutil 6.0+)
ИСПРАВЛЕНО: except без типа → except Exception
"""
import psutil
import pandas as pd
import numpy as np
import joblib
import threading
import time
from datetime import datetime
from pathlib import Path

try:
    from logger import get_logger
    from config_loader import cfg
    _INTERVAL = cfg.get("monitor", {}).get("interval_sec", 5)
    _SUSP_PORTS = set(cfg.get("monitor", {}).get("suspicious_ports", [4444, 1337, 31337]))
except Exception:
    import logging
    def get_logger(n): return logging.getLogger(n)
    _INTERVAL   = 5
    _SUSP_PORTS = {4444, 1337, 31337, 8080, 9999}

log = get_logger("process_monitor")


class ProcessMonitor:
    def __init__(self,
                 model_path:  str = "models/rf_cicids.pkl",
                 scaler_path: str = "models/scaler_cicids.pkl"):
        self.running   = False
        self.results   = []
        self.callbacks = []

        try:
            self.model          = joblib.load(model_path)
            self.scaler         = joblib.load(scaler_path)
            self.model_features = list(self.model.feature_names_in_)
            self.model_loaded   = True
            log.info("Модель ProcessMonitor загружена")
        except Exception as e:
            log.warning(f"Модель не загружена (демо-режим): {e}")
            self.model_loaded = False

    # ── Сбор признаков одного процесса ──────────────────────

    def get_process_features(self, proc) -> dict:
        try:
            with proc.oneshot():
                cpu = proc.cpu_percent(interval=0.05)
                mem = proc.memory_info()

                # ИСПРАВЛЕНО: net_connections() вместо connections()
                try:
                    try:
                        connections = proc.net_connections()   # psutil >= 6.0
                    except AttributeError:
                        connections = proc.connections()       # psutil < 6.0
                    n_conn   = len(connections)
                    ports    = [c.laddr.port for c in connections if c.laddr] or [0]
                    dst_port = max(ports)
                except Exception:
                    n_conn   = 0
                    dst_port = 0

                try:
                    threads = proc.num_threads()
                except Exception:
                    threads = 1
                try:
                    fds = proc.num_fds()
                except Exception:
                    fds = 0
                try:
                    children = len(proc.children())
                except Exception:
                    children = 0
                try:
                    cmdline = " ".join(proc.cmdline())
                    cmd_len = len(cmdline)
                except Exception:
                    cmd_len = 0

                return {
                    "pid":         proc.pid,
                    "name":        proc.name(),
                    "cpu_percent": cpu,
                    "mem_rss":     mem.rss / 1024 / 1024,
                    "mem_vms":     mem.vms / 1024 / 1024,
                    "status":      proc.status(),
                    "n_threads":   threads,
                    "n_fds":       fds,
                    "n_children":  children,
                    "n_conn":      n_conn,
                    "dst_port":    dst_port,
                    "cmd_len":     cmd_len,
                }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return None

    # ── Оценка процесса ─────────────────────────────────────

    def score_process(self, features: dict) -> float:
        if not self.model_loaded:
            score = 0.0
            if features["dst_port"] in _SUSP_PORTS:     score += 0.4
            if features["n_conn"]   > 20:               score += 0.2
            if features["cmd_len"]  > 200:              score += 0.2
            if features["cpu_percent"] > 80:            score += 0.1
            if features["n_children"]  > 10:            score += 0.1
            return min(score, 1.0)

        row     = {f: 0.0 for f in self.model_features}
        mapping = {
            "Dst Port":       features["dst_port"],
            "Flow Pkts/s":    features["n_conn"] * 10,
            "Fwd Pkts/s":     features["cpu_percent"],
            "Flow Duration":  features["mem_rss"],
            "Fwd Header Len": features["n_threads"],
            "Pkt Len Mean":   features["mem_vms"],
        }
        for k, v in mapping.items():
            if k in row:
                row[k] = v

        X = pd.DataFrame([row])
        try:
            X_scaled = pd.DataFrame(
                self.scaler.transform(X), columns=X.columns
            )
            return float(self.model.predict_proba(X_scaled)[0][1])
        except Exception as e:
            log.debug(f"score_process ошибка: {e}")
            return 0.0

    # ── Сканирование всех процессов ─────────────────────────

    def scan_all_processes(self) -> list:
        results = []
        for proc in psutil.process_iter(["pid", "name"]):
            features = self.get_process_features(proc)
            if features is None:
                continue
            score = self.score_process(features)
            level = (
                "ВЫСОКАЯ" if score > 0.7 else
                "СРЕДНЯЯ" if score > 0.4 else
                "НИЗКАЯ"
            )
            results.append({
                **features,
                "score":  round(score, 4),
                "threat": level,
                "time":   datetime.now().strftime("%H:%M:%S"),
            })
        return sorted(results, key=lambda x: x["score"], reverse=True)

    # ── Фоновый мониторинг ──────────────────────────────────

    def start_realtime(self, interval: int = _INTERVAL):
        self.running = True
        def loop():
            while self.running:
                try:
                    results = self.scan_all_processes()
                    self.results = results
                    for cb in self.callbacks:
                        try:
                            cb(results)
                        except Exception as e:
                            log.error(f"Callback ошибка: {e}")
                except Exception as e:
                    log.error(f"Monitor loop ошибка: {e}")
                time.sleep(interval)
        threading.Thread(target=loop, daemon=True).start()
        log.info(f"Реальный мониторинг запущен (интервал {interval}с)")

    def stop_realtime(self):
        self.running = False
        log.info("Мониторинг остановлен")

    def add_callback(self, fn):
        self.callbacks.append(fn)


if __name__ == "__main__":
    monitor = ProcessMonitor()
    print("Сканирование процессов...\n")
    results = monitor.scan_all_processes()
    print(f"{'PID':>6} {'Имя':<25} {'CPU%':>6} {'RAM MB':>8} {'Conn':>5} {'Score':>7} {'Угроза'}")
    print("-" * 72)
    for r in results[:20]:
        print(
            f"{r['pid']:>6} {r['name']:<25} {r['cpu_percent']:>6.1f} "
            f"{r['mem_rss']:>8.1f} {r['n_conn']:>5} "
            f"{r['score']:>7.4f} {r['threat']}"
        )
