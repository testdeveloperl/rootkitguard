"""
i18n.py — поддержка языков: русский, английский, казахский.
"""

TRANSLATIONS = {
    "ru": {
        "app_title":      "Система обнаружения аномалий",
        "login":          "Вход",
        "register":       "Регистрация",
        "username":       "Имя пользователя",
        "password":       "Пароль",
        "enter_username": "Введи имя пользователя",
        "enter_password": "Введи пароль",
        "login_btn":      "ВОЙТИ",
        "register_btn":   "ЗАРЕГИСТРИРОВАТЬСЯ",
        "wrong_creds":    "✗ Неверный логин или пароль",
        "fill_fields":    "✗ Заполни все поля",
        "success_login":  "✓ Вход выполнен",
        "success_reg":    "✓ Успешно зарегистрирован",
        "home":           "Главная",
        "scan":           "Сканирование",
        "rootkit_scan":   "Rootkit Scan",
        "monitor":        "Мониторинг",
        "analytics":      "Аналитика",
        "report":         "Отчёт",
        "settings":       "Настройки",
        "about":          "О системе",
        "choose_model":   "Выбери модель",
        "load_dataset":   "Загрузи датасет",
        "drag_drop":      "Перетащи CSV файл сюда или нажми для выбора",
        "run_analysis":   "▶  ЗАПУСТИТЬ АНАЛИЗ",
        "system_log":     "СИСТЕМНЫЙ ЖУРНАЛ",
        "threat_high":    "ВЫСОКАЯ",
        "threat_mid":     "СРЕДНЯЯ",
        "threat_low":     "НИЗКАЯ",
        "threat_clean":   "ЧИСТАЯ",
        "anomalies":      "Аномалий",
        "normal":         "Нормальных",
        "total":          "Всего",
        "threat":         "Угроза",
        "model":          "Модель",
        "supported_files": "Поддерживаются: .csv, .txt, .log, .json, .py, .sh",
        "model_loaded":     "● Модель загружена",
        "model_not_found":  "● Модель не найдена",
        "auto_scan":        "Авто-скан",
        "findings":         "находок",
        "speed":            "Скорость:",
        "rf_desc":          "100 деревьев решений.\nЛучший баланс точности\nи скорости.",
        "xgb_desc":         "Градиентный бустинг.\nМаксимальная точность\nна табличных данных.",
        "iso_desc":         "Не требует меток.\nОбнаруживает аномалии\nбез обучения.",
        "all_desc":         "RF + XGBoost + ISO.\nГолосование большинством.\nМаксимальная надёжность.",
        "ensemble":         "Ансамбль",
    },
    "en": {
        "speed":            "Speed:",
        "rf_desc":          "100 decision trees.\nBest balance of accuracy\nand speed.",
        "xgb_desc":         "Gradient boosting.\nMaximum accuracy\non tabular data.",
        "iso_desc":         "No labels required.\nDetects anomalies\nwithout training.",
        "all_desc":         "RF + XGBoost + ISO.\nMajority voting.\nMaximum reliability.",
        "ensemble":         "Ensemble",
        "model_loaded":     "● Model loaded",
        "model_not_found":  "● Model not found",
        "auto_scan":        "Auto-scan",
        "findings":         "findings",
        "app_title":      "Anomaly Detection System",
        "login":          "Login",
        "register":       "Register",
        "username":       "Username",
        "password":       "Password",
        "enter_username": "Enter username",
        "enter_password": "Enter password",
        "login_btn":      "LOGIN",
        "register_btn":   "REGISTER",
        "wrong_creds":    "✗ Invalid username or password",
        "fill_fields":    "✗ Fill in all fields",
        "success_login":  "✓ Login successful",
        "success_reg":    "✓ Successfully registered",
        "home":           "Home",
        "scan":           "Scan",
        "rootkit_scan":   "Rootkit Scan",
        "monitor":        "Monitor",
        "analytics":      "Analytics",
        "report":         "Report",
        "settings":       "Settings",
        "about":          "About",
        "choose_model":   "Choose model",
        "load_dataset":   "Load dataset",
        "drag_drop":      "Drag & drop CSV file here or click to browse",
        "run_analysis":   "▶  RUN ANALYSIS",
        "system_log":     "SYSTEM LOG",
        "threat_high":    "HIGH",
        "threat_mid":     "MEDIUM",
        "threat_low":     "LOW",
        "threat_clean":   "CLEAN",
        "anomalies":      "Anomalies",
        "normal":         "Normal",
        "total":          "Total",
        "threat":         "Threat",
        "model":          "Model",
        "supported_files": "Supported: .csv, .txt, .log, .json, .py, .sh",
    },
    "kz": {
        "speed":            "Жылдамдық:",
        "rf_desc":          "100 шешім ағашы.\nДәлдік пен жылдамдықтың\nең жақсы балансы.",
        "xgb_desc":         "Градиенттік бустинг.\nКестелік деректерде\nмаксималды дәлдік.",
        "iso_desc":         "Белгілер қажет емес.\nОқытусыз аномалияларды\nанықтайды.",
        "all_desc":         "RF + XGBoost + ISO.\nКөпшілік дауыс беру.\nМаксималды сенімділік.",
        "ensemble":         "Ансамбль",
        "model_loaded":     "● Модель жүктелді",
        "model_not_found":  "● Модель табылмады",
        "auto_scan":        "Авто-скан",
        "findings":         "табылды",
        "app_title":      "Аномалияларды анықтау жүйесі",
        "login":          "Кіру",
        "register":       "Тіркелу",
        "username":       "Пайдаланушы аты",
        "password":       "Құпия сөз",
        "enter_username": "Пайдаланушы атын енгізіңіз",
        "enter_password": "Құпия сөзді енгізіңіз",
        "login_btn":      "КІРУ",
        "register_btn":   "ТІРКЕЛУ",
        "wrong_creds":    "✗ Қате логин немесе құпия сөз",
        "fill_fields":    "✗ Барлық өрістерді толтырыңыз",
        "success_login":  "✓ Кіру сәтті орындалды",
        "success_reg":    "✓ Тіркелу сәтті орындалды",
        "home":           "Басты бет",
        "scan":           "Сканерлеу",
        "rootkit_scan":   "Rootkit Scan",
        "monitor":        "Мониторинг",
        "analytics":      "Аналитика",
        "report":         "Есеп",
        "settings":       "Баптаулар",
        "about":          "Жүйе туралы",
        "choose_model":   "Модельді таңдаңыз",
        "load_dataset":   "Деректер жинағын жүктеңіз",
        "drag_drop":      "CSV файлды осында сүйреңіз немесе таңдау үшін басыңыз",
        "run_analysis":   "▶  ТАЛДАУДЫ ІСКЕ ҚОСУ",
        "system_log":     "ЖҮЙЕЛІК ЖУРНАЛ",
        "threat_high":    "ЖОҒАРЫ",
        "threat_mid":     "ОРТАША",
        "threat_low":     "ТӨМЕН",
        "threat_clean":   "ТАЗА",
        "anomalies":      "Аномалиялар",
        "normal":         "Қалыпты",
        "total":          "Барлығы",
        "threat":         "Қауіп",
        "model":          "Модель",
        "supported_files": "Қолданылады: .csv, .txt, .log, .json, .py, .sh",
    },
}

_current_lang = "ru"

def set_lang(lang: str):
    global _current_lang
    if lang in TRANSLATIONS:
        _current_lang = lang

def get_lang() -> str:
    return _current_lang

def t(key: str) -> str:
    return TRANSLATIONS.get(_current_lang, {}).get(key, key)

# Добавляем недостающие ключи
import sys
_add = {
    "ru": {"boot_msg": "RootkitGuard v2.1 запущен", "auth_msg": "Пользователь авторизован", "config_msg": "Конфигурация загружена: config/config.yaml", "ml_loaded": "Модель загружена: rf_cicids.pkl ✓", "scan_started": "Авто-сканирование системы запущено в фоне", "ready_msg": "Система готова к работе"},
    "en": {"boot_msg": "RootkitGuard v2.1 started", "auth_msg": "User authorized", "config_msg": "Configuration loaded: config/config.yaml", "ml_loaded": "Model loaded: rf_cicids.pkl ✓", "scan_started": "Auto-scan started in background", "ready_msg": "System ready"},
    "kz": {"boot_msg": "RootkitGuard v2.1 іске қосылды", "auth_msg": "Пайдаланушы авторизацияланды", "config_msg": "Конфигурация жүктелді: config/config.yaml", "ml_loaded": "Модель жүктелді: rf_cicids.pkl ✓", "scan_started": "Авто-сканерлеу фонда іске қосылды", "ready_msg": "Жүйе жұмысқа дайын"},
}
for lang, keys in _add.items():
    TRANSLATIONS[lang].update(keys)

_extra = {
    "ru": {"rootkit_scan_btn": "🦠  Rootkit Scan", "analytics_btn": "📊  Аналитика"},
    "en": {"rootkit_scan_btn": "🦠  Rootkit Scan", "analytics_btn": "📊  Analytics"},
    "kz": {"rootkit_scan_btn": "🦠  Rootkit Scan", "analytics_btn": "📊  Аналитика"},
}
for lang, keys in _extra.items():
    TRANSLATIONS[lang].update(keys)

_scan_keys = {
    "ru": {
        "file_label": "📂  Файл:", "via_api": "Через API",
        "waiting": "Выбери файл и нажми ЗАПУСТИТЬ",
        "scan_details": "📋  Детали сканирования", "history": "🕐  История",
        "no_scans": "Нет сканирований", "create_pdf": "📕  Создать PDF отчёт",
        "run_scan": "▶  ЗАПУСТИТЬ АНАЛИЗ",
    },
    "en": {
        "file_label": "📂  File:", "via_api": "Via API",
        "waiting": "Select file and press RUN",
        "scan_details": "📋  Scan Details", "history": "🕐  History",
        "no_scans": "No scans yet", "create_pdf": "📕  Create PDF Report",
        "run_scan": "▶  RUN ANALYSIS",
    },
    "kz": {
        "file_label": "📂  Файл:", "via_api": "API арқылы",
        "waiting": "Файлды таңдап ІСКЕ ҚОСУ батырмасын басыңыз",
        "scan_details": "📋  Сканерлеу мәліметтері", "history": "🕐  Тарих",
        "no_scans": "Сканерлеу жоқ", "create_pdf": "📕  PDF есеп жасау",
        "run_scan": "▶  ТАЛДАУДЫ ІСКЕ ҚОСУ",
    },
}
for lang, keys in _scan_keys.items():
    TRANSLATIONS[lang].update(keys)

_extra2 = {
    "ru": {"threshold": "Порог", "default_rows": "Строк", "browse": "Обзор"},
    "en": {"threshold": "Threshold", "default_rows": "Rows", "browse": "Browse"},
    "kz": {"threshold": "Шек", "default_rows": "Жолдар", "browse": "Шолу"},
}
for lang, keys in _extra2.items():
    TRANSLATIONS[lang].update(keys)


_ai_keys = {

    "ru": {"🤖  Спросить AI": "✦  AI Анализ", "ai_analyzing": "Анализирую...", "ai_error": "Ошибка AI"},

    "en": {"🤖  Спросить AI": "✦  AI Analysis", "ai_analyzing": "Analyzing...", "ai_error": "AI Error"},

    "kz": {"🤖  Спросить AI": "✦  AI Талдау", "ai_analyzing": "Талдауда...", "ai_error": "AI Қатесі"},

}

for lang, keys in _ai_keys.items():

    TRANSLATIONS[lang].update(keys)


_rk_keys = {
    "ru": {
        "ask_ai": "✦  AI Анализ",
        "ai_analyzing": "Анализирую...",
        "ai_error": "Ошибка AI",
        "rk_run": "▶  Запустить",
        "rk_done": "Завершено",
        "rk_ready": "Готов к сканированию",
        "rk_scanning": "Сканирование...",
        "security_score": "Security Score",
        "system_dna": "System DNA",
        "new_baseline": "Новый baseline",
        "no_changes": "Изменений не обнаружено — система стабильна ✓",
        "first_snapshot": "✓ Первый снимок системы создан",
        "recommendations": "🛡  Рекомендации по устранению",
        "rk_clean": "✅ Система чиста",
    },
    "en": {
        "ask_ai": "✦  AI Analysis",
        "ai_analyzing": "Analyzing...",
        "ai_error": "AI Error",
        "rk_run": "▶  Run Scan",
        "rk_done": "Completed",
        "rk_ready": "Ready to scan",
        "rk_scanning": "Scanning...",
        "security_score": "Security Score",
        "system_dna": "System DNA",
        "new_baseline": "New baseline",
        "no_changes": "No changes detected — system stable ✓",
        "first_snapshot": "✓ First system snapshot created",
        "recommendations": "🛡  Remediation Steps",
        "rk_clean": "✅ System is clean",
    },
    "kz": {
        "ask_ai": "✦  AI Талдау",
        "ai_analyzing": "Талдауда...",
        "ai_error": "AI Қатесі",
        "rk_run": "▶  Іске қосу",
        "rk_done": "Аяқталды",
        "rk_ready": "Сканерлеуге дайын",
        "rk_scanning": "Сканерлеуде...",
        "security_score": "Қауіпсіздік балы",
        "system_dna": "Жүйе ДНҚ",
        "new_baseline": "Жаңа baseline",
        "no_changes": "Өзгерістер жоқ — жүйе тұрақты ✓",
        "first_snapshot": "✓ Жүйенің бірінші суреті жасалды",
        "recommendations": "🛡  Жою бойынша ұсыныстар",
        "rk_clean": "✅ Жүйе таза",
    },
}
for lang, keys in _rk_keys.items():
    TRANSLATIONS[lang].update(keys)

_analytics_keys = {
    "ru": {
        "analytics_title":  "АНАЛИТИКА МОДЕЛЕЙ",
        "best_model":       "Лучшая модель",
        "dataset":          "Датасет",
        "accuracy":         "Точность",
        "features":         "Признаков",
        "net_features":     "сетевых признаков",
        "f1_viz":           "F1-score",
        "when_to_use":      "Когда использовать каждую модель",
        "rf_when":          "Универсальный выбор. Быстро, точно, стабильно.",
        "xgb_when":         "Когда важна максимальная точность и есть время.",
        "iso_when":         "Когда нет меток. Новые неизвестные угрозы.",
        "all_when":         "Критические системы где нельзя ошибиться.",
    },
    "en": {
        "analytics_title":  "MODEL ANALYTICS",
        "best_model":       "Best model",
        "dataset":          "Dataset",
        "accuracy":         "Accuracy",
        "features":         "Features",
        "net_features":     "network features",
        "f1_viz":           "F1-score",
        "when_to_use":      "When to use each model",
        "rf_when":          "Universal choice. Fast, accurate, stable.",
        "xgb_when":         "When maximum accuracy matters and time allows.",
        "iso_when":         "When no labels available. New unknown threats.",
        "all_when":         "Critical systems where errors are unacceptable.",
    },
    "kz": {
        "analytics_title":  "МОДЕЛЬ АНАЛИТИКАСЫ",
        "best_model":       "Үздік модель",
        "dataset":          "Деректер жинағы",
        "accuracy":         "Дәлдік",
        "features":         "Белгілер",
        "net_features":     "желілік белгілер",
        "f1_viz":           "F1-score",
        "when_to_use":      "Әр модельді қашан қолдану керек",
        "rf_when":          "Әмбебап таңдау. Жылдам, дәл, тұрақты.",
        "xgb_when":         "Максималды дәлдік қажет болғанда.",
        "iso_when":         "Белгілер жоқ кезде. Жаңа белгісіз қауіптер.",
        "all_when":         "Қателікке жол берілмейтін маңызды жүйелер.",
    },
}
for lang, keys in _analytics_keys.items():
    TRANSLATIONS[lang].update(keys)
