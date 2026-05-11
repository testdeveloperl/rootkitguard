"""
config_loader.py — загружает config/config.yaml.
Используй: from config_loader import cfg
"""
import yaml
from pathlib import Path

_CONFIG_PATH = Path(__file__).parent.parent / "config" / "config.yaml"

def load_config(path: Path = _CONFIG_PATH) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

cfg = load_config()
