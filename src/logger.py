"""
logger.py — центральное логирование с ротацией файлов.
Используй: from logger import get_logger
           log = get_logger(__name__)
"""
import logging
import logging.handlers
from pathlib import Path

_initialized = False

def get_logger(name: str = "rootkitguard") -> logging.Logger:
    global _initialized

    try:
        from config_loader import cfg
        log_cfg   = cfg.get("logging", {})
        level     = getattr(logging, log_cfg.get("level", "INFO"))
        log_file  = log_cfg.get("file", "logs/rootkitguard.log")
        max_bytes = log_cfg.get("max_bytes", 10_485_760)
        backups   = log_cfg.get("backup_count", 3)
    except Exception:
        level     = logging.INFO
        log_file  = "logs/rootkitguard.log"
        max_bytes = 10_485_760
        backups   = 3

    if not _initialized:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)

        fmt = logging.Formatter(
            "%(asctime)s  %(levelname)-8s  %(name)s — %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        )

        root = logging.getLogger()
        root.setLevel(level)

        # Консоль
        ch = logging.StreamHandler()
        ch.setFormatter(fmt)
        root.addHandler(ch)

        # Файл с ротацией
        fh = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=max_bytes, backupCount=backups, encoding="utf-8"
        )
        fh.setFormatter(fmt)
        root.addHandler(fh)

        _initialized = True

    return logging.getLogger(name)
