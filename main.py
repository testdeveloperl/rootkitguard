#!/usr/bin/env python3
"""
main.py — единая точка входа RootkitGuard.

Использование:
  python main.py gui          # Запустить GUI
  python main.py api          # Запустить FastAPI сервер
  python main.py scan FILE    # Сканировать CSV файл
  python main.py rootkit      # Rootkit-проверки системы
  python main.py monitor      # Мониторинг процессов в консоли
"""
import sys
import os

# Добавляем src/ в путь
SRC = os.path.join(os.path.dirname(__file__), "src")
sys.path.insert(0, SRC)


def cmd_gui():
    """Запустить графический интерфейс."""
    from rootkitguard import RootkitGuard
    app = RootkitGuard()
    app.mainloop()


def cmd_api():
    """Запустить FastAPI сервер."""
    import uvicorn
    from config_loader import cfg
    host = cfg.get("api", {}).get("host", "0.0.0.0")
    port = cfg.get("api", {}).get("port", 8000)
    print(f"[*] Запуск API на http://{host}:{port}")
    print(f"[*] Документация: http://localhost:{port}/docs")
    uvicorn.run("api:app", host=host, port=port, reload=False)


def cmd_scan(filepath: str, n_rows: int = 10000):
    """Сканировать CSV файл (консольный режим)."""
    from pathlib import Path
    import pandas as pd
    import numpy as np

    if not Path(filepath).exists():
        print(f"[!] Файл не найден: {filepath}")
        sys.exit(1)

    print(f"[*] Загружаем: {filepath}")
    df = pd.read_csv(filepath, nrows=n_rows)
    print(f"[+] Строк: {len(df)}")

    if "Label"     in df.columns: df = df.drop(columns=["Label"])
    if "Timestamp" in df.columns: df = df.drop(columns=["Timestamp"])
    df = df.replace([np.inf, -np.inf], np.nan).fillna(0)

    try:
        import joblib
        from config_loader import cfg
        rf     = joblib.load(cfg["models"]["rf_path"])
        scaler = joblib.load(cfg["models"]["scaler_path"])
        X      = pd.DataFrame(scaler.transform(df), columns=df.columns)
        cols   = rf.feature_names_in_
        for c in cols:
            if c not in X.columns: X[c] = 0
        X = X[cols]
        preds = rf.predict(X)
        proba = rf.predict_proba(X)[:, 1]
        print("[+] Модель загружена")
    except Exception as e:
        print(f"[!] Модель не загружена ({e}), демо-режим")
        preds = np.random.choice([0, 1], size=len(df), p=[0.75, 0.25])
        proba = np.random.uniform(0, 1, size=len(df))

    n_anom = int(preds.sum())
    n_norm = len(preds) - n_anom
    pct    = n_anom / len(preds) * 100
    threat = "ВЫСОКАЯ" if pct > 20 else "СРЕДНЯЯ" if pct > 5 else "НИЗКАЯ"

    print(f"\n{'='*50}")
    print("  РЕЗУЛЬТАТЫ СКАНИРОВАНИЯ")
    print(f"{'='*50}")
    print(f"  Всего записей:   {len(preds):,}")
    print(f"  Нормальных:      {n_norm:,}")
    print(f"  Аномалий:        {n_anom:,}  ({pct:.2f}%)")
    print(f"  Угроза:          {threat}")
    print(f"{'='*50}\n")

    from notifier import notify_threat
    notify_threat(threat, f"scan {filepath}: {n_anom} аномалий")


def cmd_rootkit():
    """Запустить rootkit-проверки."""
    from rootkit_checker import RootkitChecker
    print("=== RootkitGuard — Rootkit Checker ===\n")
    checker = RootkitChecker()
    result  = checker.run_all()
    print(f"\nУровень угрозы:  {result.threat_level}")
    print(f"Проверок:        {result.total_checks}")
    print(f"Пройдено:        {result.passed}")
    print(f"Находок:         {len(result.findings)}\n")
    if result.findings:
        for f in result.findings:
            print(f"  [{f.severity}] {f.category}")
            print(f"     {f.description}")
            if f.detail:
                print(f"     → {f.detail[:120]}")
    else:
        print("  ✅ Признаков rootkit не обнаружено")

    from notifier import notify_threat
    notify_threat(result.threat_level, f"Rootkit scan: {len(result.findings)} находок")


def cmd_monitor(n: int = 20):
    """Мониторинг процессов в консоли."""
    from process_monitor import ProcessMonitor
    monitor = ProcessMonitor()
    print("Сканирование процессов...\n")
    results = monitor.scan_all_processes()
    print(f"{'PID':>6} {'Имя':<25} {'CPU%':>6} {'RAM MB':>8} {'Conn':>5} {'Score':>7} {'Угроза'}")
    print("-" * 72)
    for r in results[:n]:
        print(
            f"{r['pid']:>6} {r['name']:<25} {r['cpu_percent']:>6.1f} "
            f"{r['mem_rss']:>8.1f} {r['n_conn']:>5} "
            f"{r['score']:>7.4f} {r['threat']}"
        )


def print_help():
    print(__doc__)
    print("Примеры:")
    print("  python main.py gui")
    print("  python main.py api")
    print("  python main.py scan data/raw/friday_traffic.csv")
    print("  python main.py rootkit")
    print("  python main.py monitor")


if __name__ == "__main__":
    args = sys.argv[1:]

    if not args or args[0] in ("-h", "--help"):
        print_help()
        sys.exit(0)

    cmd = args[0].lower()

    if cmd == "gui":
        cmd_gui()
    elif cmd == "api":
        cmd_api()
    elif cmd == "scan":
        if len(args) < 2:
            print("[!] Укажи путь к файлу: python main.py scan FILE.csv")
            sys.exit(1)
        n = int(args[2]) if len(args) > 2 else 10000
        cmd_scan(args[1], n)
    elif cmd == "rootkit":
        cmd_rootkit()
    elif cmd == "monitor":
        n = int(args[1]) if len(args) > 1 else 20
        cmd_monitor(n)
    else:
        print(f"[!] Неизвестная команда: {cmd}")
        print_help()
        sys.exit(1)
