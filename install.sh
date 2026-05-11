#!/bin/bash
# install.sh — установка RootkitGuard на Ubuntu 24
# Запуск: chmod +x install.sh && ./install.sh

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $1"; }
success() { echo -e "${GREEN}[OK]${NC}    $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

INSTALL_DIR="$HOME/.local/share/rootkitguard"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo ""
echo -e "${BLUE}╔══════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║   RootkitGuard — Установщик Ubuntu 24   ║${NC}"
echo -e "${BLUE}╚══════════════════════════════════════════╝${NC}"
echo ""

# ── 1. Системные зависимости ────────────────────────────────
info "Установка системных пакетов..."
sudo apt-get update -qq
sudo apt-get install -y -qq \
    python3 python3-pip python3-tk \
    libnotify-bin \
    fonts-dejavu-core \
    xdg-utils \
    2>/dev/null || warn "Некоторые пакеты не установились (продолжаем)"
success "Системные пакеты установлены"

# ── 2. Python зависимости ───────────────────────────────────
info "Установка Python зависимостей..."
pip install -r "$SCRIPT_DIR/requirements.txt" \
    --break-system-packages -q \
    || pip install -r "$SCRIPT_DIR/requirements.txt" -q
success "Python зависимости установлены"

# ── 3. Копирование файлов ───────────────────────────────────
info "Копирование файлов в $INSTALL_DIR ..."
mkdir -p "$INSTALL_DIR"
cp -r "$SCRIPT_DIR"/* "$INSTALL_DIR/"
mkdir -p "$INSTALL_DIR"/{models,data/raw,reports,logs,config}
success "Файлы скопированы"

# ── 4. Launcher скрипт ──────────────────────────────────────
info "Создание launcher..."
LAUNCHER="$HOME/.local/bin/rootkitguard"
mkdir -p "$HOME/.local/bin"
cat > "$LAUNCHER" << EOF
#!/bin/bash
cd "$INSTALL_DIR"
python3 main.py "\$@"
EOF
chmod +x "$LAUNCHER"
success "Launcher создан: $LAUNCHER"

# ── 5. .desktop файл (иконка в меню Ubuntu) ─────────────────
info "Регистрация .desktop файла..."
DESKTOP_DIR="$HOME/.local/share/applications"
mkdir -p "$DESKTOP_DIR"

ICON_PATH="$INSTALL_DIR/assets/icon.png"
[ -f "$ICON_PATH" ] || ICON_PATH="dialog-warning"

cat > "$DESKTOP_DIR/rootkitguard.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=RootkitGuard
GenericName=Rootkit Detector
Comment=Система обнаружения rootkit-подобных аномалий на основе ML
Exec=python3 $INSTALL_DIR/main.py gui
Icon=$ICON_PATH
Terminal=false
Categories=Security;System;
Keywords=rootkit;security;anomaly;ml;
StartupNotify=true
StartupWMClass=RootkitGuard
EOF

chmod +x "$DESKTOP_DIR/rootkitguard.desktop"
update-desktop-database "$DESKTOP_DIR" 2>/dev/null || true
success ".desktop файл создан (ищи в меню приложений Ubuntu)"

# ── 6. PATH ────────────────────────────────────────────────
PROFILE="$HOME/.bashrc"
if ! grep -q "/.local/bin" "$PROFILE" 2>/dev/null; then
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$PROFILE"
    warn "Добавлен ~/.local/bin в PATH. Перезапусти терминал или: source ~/.bashrc"
fi

# ── 7. Результат ────────────────────────────────────────────
echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║   ✅  RootkitGuard успешно установлен!       ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════╝${NC}"
echo ""
echo "  Запуск GUI:        python3 $INSTALL_DIR/main.py gui"
echo "  Запуск API:        python3 $INSTALL_DIR/main.py api"
echo "  Rootkit check:     python3 $INSTALL_DIR/main.py rootkit"
echo "  Сканировать CSV:   python3 $INSTALL_DIR/main.py scan data/raw/file.csv"
echo ""
echo "  Или из меню Ubuntu: найди 'RootkitGuard' в Applications"
echo ""
echo -e "  Документация API:  ${BLUE}http://localhost:8000/docs${NC}"
echo ""
