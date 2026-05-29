"""
notifier.py — десктопные уведомления Ubuntu через notify-send (libnotify).
Вызывается при СРЕДНЕЙ / ВЫСОКОЙ угрозе автоматически.
"""
import subprocess
from pathlib import Path

try:
    from logger import get_logger
except ImportError:
    import logging
    def get_logger(n): return logging.getLogger(n)

log = get_logger("notifier")

ICON_PATH = str(Path(__file__).parent.parent / "assets" / "icon.png")


def notify(title: str, body: str, urgency: str = "normal") -> bool:
    """
    Отправить уведомление через notify-send.
    urgency: "low" | "normal" | "critical"
    Возвращает True если успешно.
    """
    try:
        icon = ICON_PATH if Path(ICON_PATH).exists() else "dialog-warning"
        subprocess.run(
            ["notify-send", "--urgency", urgency, "--icon", icon, title, body],
            timeout=5, check=True, capture_output=True
        )
        log.info(f"Notification sent: {title}")
        return True
    except FileNotFoundError:
        log.debug("notify-send not found (download libnotify-bin)")
        return False
    except subprocess.CalledProcessError as e:
        log.debug(f"notify-send returned an error: {e}")
        return False
    except Exception as e:
        log.debug(f"Notification error: {e}")
        return False


def notify_threat(threat_level: str, details: str = "") -> None:
    """Отправить уведомление об угрозе в зависимости от уровня."""
    config_min = "MEDIUM"
    try:
        from config_loader import cfg
        config_min = cfg.get("notifications", {}).get("min_threat_lvl", "MEDIUM")
        if not cfg.get("notifications", {}).get("enabled", True):
            return
    except Exception:
        pass

    order = {"LOW": 0, "MEDIUM": 1, "HIGH": 2}
    if order.get(threat_level, 0) < order.get(config_min, 1):
        return

    urgency_map = {"LOW": "low", "MEDIUM": "normal", "HIGH": "critical"}
    urgency = urgency_map.get(threat_level, "normal")

    title = f"⚠ RootkitGuard — threat: {threat_level}"
    body  = details[:200] if details else "Suspicious activity has been detected"

    notify(title, body, urgency)
