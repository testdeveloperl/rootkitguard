"""
auth.py — система авторизации RootkitGuard.
Дефолтный аккаунт: admin / admin123
"""
import json
import hashlib
from pathlib import Path

DB_PATH = Path(__file__).parent.parent / "data" / "users.json"

def _hash(password: str) -> str:
    return hashlib.sha256(password.encode()).hexdigest()

def _load() -> dict:
    if not DB_PATH.exists():
        DB_PATH.parent.mkdir(exist_ok=True)
        # Дефолтный admin
        users = {"admin": {"password": _hash("admin123"), "role": "admin"}}
        DB_PATH.write_text(json.dumps(users, indent=2))
        return users
    return json.loads(DB_PATH.read_text())

def _save(users: dict):
    DB_PATH.write_text(json.dumps(users, indent=2, ensure_ascii=False))

def login(username: str, password: str) -> bool:
    users = _load()
    if username in users:
        return users[username]["password"] == _hash(password)
    return False

def register(username: str, password: str) -> tuple:
    if not username or not password:
        return False, "Заполни все поля"
    if len(username) < 3:
        return False, "Имя минимум 3 символа"
    if len(password) < 6:
        return False, "Пароль минимум 6 символов"
    users = _load()
    if username in users:
        return False, "Пользователь уже существует"
    users[username] = {"password": _hash(password), "role": "user"}
    _save(users)
    return True, "Успешно зарегистрирован"

def get_role(username: str) -> str:
    users = _load()
    return users.get(username, {}).get("role", "user")
