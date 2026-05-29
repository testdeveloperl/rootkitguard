# RootkitGuard v2.0

**Система обнаружения rootkit-подобных аномалий на основе машинного обучения**

МУИТ · Алматы · 2026 | Научный руководитель: Alin G.T.

Авторы: Амангелды Манас · Курманов Искандер · Куанышбек Бекарыс

---

## Быстрый старт (Ubuntu 24 / VirtualBox)

```bash
# 1. Установить зависимости и зарегистрировать в меню Ubuntu
chmod +x install.sh
./install.sh

# 2. Запустить GUI
python3 main.py gui

# 3. Запустить API (в отдельном терминале)
python3 main.py api
# → http://localhost:8000/docs
```

---

## Команды CLI

| Команда | Описание |
|---------|----------|
| `python3 main.py gui` | Графический интерфейс |
| `python3 main.py api` | FastAPI сервер (порт 8000) |
| `python3 main.py scan data/raw/file.csv` | Сканировать CSV |
| `python3 main.py rootkit` | Rootkit-проверки системы |
| `python3 main.py monitor` | Мониторинг процессов |

---

## Структура проекта

```
rootkitguard/
├── main.py                  ← Единая точка входа (NEW)
├── install.sh               ← Установщик Ubuntu 24
├── requirements.txt
├── docker-compose.yml
├── config/
│   └── config.yaml          ← Все настройки (NEW)
├── src/
│   ├── rootkitguard.py      ← GUI (обновлён)
│   ├── api.py               ← FastAPI (обновлён)
│   ├── rootkit_checker.py   ← Linux rootkit checks (NEW)
│   ├── process_monitor.py   ← Мониторинг процессов (исправлен)
│   ├── notifier.py          ← Desktop уведомления (NEW)
│   ├── logger.py            ← Логирование с ротацией (NEW)
│   ├── config_loader.py     ← Загрузчик конфига (NEW)
│   ├── pdf_report.py        ← PDF отчёты
│   ├── feature_extractor.py
│   ├── preprocessor.py
│   ├── train_cicids.py
│   └── train_models.py
├── models/                  ← rf_cicids.pkl, scaler_cicids.pkl
├── data/raw/                ← friday_traffic.csv
├── reports/                 ← PDF / JSON отчёты
├── logs/                    ← rootkitguard.log
└── assets/
    └── icon.png
```

---

## Что нового в v2.0

### Rootkit Checker (src/rootkit_checker.py)
Linux-специфичные проверки для темы диплома:
- **Скрытые процессы** — сравнение /proc vs `ps`
- **Модули ядра** — `lsmod` vs `/proc/modules` (расхождения = rootkit!)
- **LD_PRELOAD инъекция** — `/etc/ld.so.preload`
- **Подозрительные порты** — `/proc/net/tcp` напрямую
- **Системные файлы** — проверка владельца и baseline hash
- **Привилегии** — UID=0 у не-root пользователей

### Интеграция GUI → API
- Страница «Сканирование» отправляет файл в `/scan` endpoint
- Checkbox «Через API» / fallback на локальный режим
- Страница «Отчёт» генерирует настоящий PDF через pdf_report.py

### Настройки в GUI
- Порог аномалии, интервал мониторинга, уведомления — всё через UI
- Сохраняется в `config/config.yaml`

### Исправленные баги
- `proc.connections()` → `proc.net_connections()` (psutil 6.0+)
- `except:` → `except Exception:` везде

---

## Обучение моделей

```bash
# Скачай датасет CIC-IDS2018, положи в data/raw/friday_traffic.csv
python3 src/train_cicids.py
# Модели сохранятся в models/
```

---

## Docker (только API)

```bash
docker-compose up -d
# GUI запускается отдельно на хосте
python3 main.py gui
```

---

## API Endpoints

| Endpoint | Метод | Описание |
|----------|-------|----------|
| `/scan` | POST | Сканировать CSV файл |
| `/rootkit/scan` | POST | Rootkit-проверки системы |
| `/history` | GET | История сканирований |
| `/report/pdf/{id}` | GET | Скачать PDF отчёт |
| `/live/stats` | GET | Текущая статистика |
| `/health` | GET | Статус сервера |
| `/docs` | GET | Swagger UI |
