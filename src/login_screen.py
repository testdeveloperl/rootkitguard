"""
login_screen.py — экран входа/регистрации RootkitGuard.
Security Dashboard стиль.
"""
import sys, os
sys.path.insert(0, os.path.dirname(__file__))

import customtkinter as ctk
from PIL import Image
from pathlib import Path
from auth import login, register

LOGO_PATH = Path(__file__).parent.parent / "assets" / "logo.png"

BG     = "#0a0e1a"
CARD   = "#111827"
ACCENT = "#00d4ff"
GREEN  = "#00ff88"
RED    = "#ff3b3b"
TEXT   = "#e2e8f0"
GRAY   = "#4a5568"


class LoginScreen(ctk.CTk):
    def __init__(self, on_success):
        super().__init__()
        self.on_success = on_success
        self.title("RootkitGuard — Вход")
        self.configure(fg_color=BG)
        self.resizable(True, True)
        self.minsize(420, 560)

        # Центрируем окно
        self.update_idletasks()
        sw = self.winfo_screenwidth()
        sh = self.winfo_screenheight()
        x  = (sw - 480) // 2
        y  = (sh - 640) // 2
        self.geometry(f"480x640+{x}+{y}")

        # Анимация появления
        self.attributes("-alpha", 0.0)
        self.after(30, self._fade_in)

        self._show_pwd = False
        self._build()

    def _fade_in(self, alpha=0.0):
        alpha = min(alpha + 0.06, 1.0)
        self.attributes("-alpha", alpha)
        if alpha < 1.0:
            self.after(15, lambda: self._fade_in(alpha))

    def _build(self):
        # Центральный контейнер
        container = ctk.CTkFrame(self, fg_color="transparent")
        container.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.88)

        # Логотип — только иконка без текста
        try:
            img = ctk.CTkImage(
                light_image=Image.open(LOGO_PATH),
                dark_image=Image.open(LOGO_PATH),
                size=(130, 130))
            ctk.CTkLabel(container, image=img, text="").pack(pady=(0, 12))
        except Exception:
            ctk.CTkLabel(container, text="🛡",
                         font=ctk.CTkFont(size=70)).pack(pady=(0, 12))

        # Заголовок
        ctk.CTkLabel(container, text="RootkitGuard",
                     font=ctk.CTkFont(size=28, weight="bold"),
                     text_color=ACCENT).pack()
        ctk.CTkLabel(container,
                     text="Система обнаружения rootkit-подобных аномалий",
                     font=ctk.CTkFont(size=11),
                     text_color=GRAY).pack(pady=(2, 20))

        # Карточка
        card = ctk.CTkFrame(container, fg_color=CARD, corner_radius=16,
                            border_width=1, border_color="#1e293b")
        card.pack(fill="x")

        # Табы
        tabs = ctk.CTkFrame(card, fg_color="transparent")
        tabs.pack(fill="x", padx=20, pady=(20, 16))

        self.mode = ctk.StringVar(value="login")

        self.btn_login = ctk.CTkButton(
            tabs, text="Вход", height=38, width=150,
            fg_color=ACCENT, text_color="#000000",
            font=ctk.CTkFont(size=13, weight="bold"),
            corner_radius=8,
            command=lambda: self._switch("login"))
        self.btn_login.pack(side="left", padx=(0, 6))

        self.btn_reg = ctk.CTkButton(
            tabs, text="Регистрация", height=38, width=150,
            fg_color="#1e293b", text_color=TEXT,
            font=ctk.CTkFont(size=13),
            corner_radius=8,
            command=lambda: self._switch("register"))
        self.btn_reg.pack(side="left")

        # Поля ввода
        fields = ctk.CTkFrame(card, fg_color="transparent")
        fields.pack(fill="x", padx=20)

        # Имя пользователя
        ctk.CTkLabel(fields, text="Имя пользователя",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=GRAY, anchor="w").pack(fill="x")
        self.username = ctk.CTkEntry(
            fields, height=44, corner_radius=8,
            fg_color="#1e293b", border_color="#2d3748",
            border_width=1,
            text_color=TEXT, font=ctk.CTkFont(size=13),
            placeholder_text="Введи имя пользователя")
        self.username.pack(fill="x", pady=(4, 14))

        # Пароль
        ctk.CTkLabel(fields, text="Пароль",
                     font=ctk.CTkFont(size=12, weight="bold"),
                     text_color=GRAY, anchor="w").pack(fill="x")

        pwd_row = ctk.CTkFrame(fields, fg_color="transparent")
        pwd_row.pack(fill="x", pady=(4, 0))

        self.password = ctk.CTkEntry(
            pwd_row, height=44, corner_radius=8,
            fg_color="#1e293b", border_color="#2d3748",
            border_width=1,
            text_color=TEXT, font=ctk.CTkFont(size=13),
            placeholder_text="Введи пароль",
            show="●")
        self.password.pack(side="left", fill="x", expand=True)
        self.password.bind("<Return>", lambda e: self._submit())

        self.eye_btn = ctk.CTkButton(
            pwd_row, text="👁", width=44, height=44,
            fg_color="#1e293b", hover_color="#2d3748",
            border_color="#2d3748", border_width=1,
            corner_radius=8,
            command=self._toggle_password)
        self.eye_btn.pack(side="left", padx=(6, 0))

        # Статус ошибки
        self.status_lbl = ctk.CTkLabel(
            card, text="",
            font=ctk.CTkFont(size=12),
            text_color=RED)
        self.status_lbl.pack(pady=(10, 0))

        # Кнопка войти
        self.submit_btn = ctk.CTkButton(
            card, text="ВОЙТИ", height=46,
            fg_color=ACCENT, hover_color="#00b8d9",
            text_color="#000000",
            font=ctk.CTkFont(size=14, weight="bold"),
            corner_radius=10,
            command=self._submit)
        self.submit_btn.pack(fill="x", padx=20, pady=(8, 20))

    def _toggle_password(self):
        self._show_pwd = not self._show_pwd
        self.password.configure(show="" if self._show_pwd else "●")

    def _switch(self, mode):
        self.mode.set(mode)
        if mode == "login":
            self.btn_login.configure(fg_color=ACCENT, text_color="#000000")
            self.btn_reg.configure(fg_color="#1e293b", text_color=TEXT)
            self.submit_btn.configure(text="ВОЙТИ")
        else:
            self.btn_reg.configure(fg_color=ACCENT, text_color="#000000")
            self.btn_login.configure(fg_color="#1e293b", text_color=TEXT)
            self.submit_btn.configure(text="ЗАРЕГИСТРИРОВАТЬСЯ")
        self.status_lbl.configure(text="")

    def _submit(self):
        user = self.username.get().strip()
        pwd  = self.password.get().strip()

        if not user or not pwd:
            self.status_lbl.configure(text="✗ Заполни все поля", text_color=RED)
            return

        if self.mode.get() == "login":
            if login(user, pwd):
                self.status_lbl.configure(text="✓ Вход выполнен", text_color=GREEN)
                self.after(600, lambda: self._open_main(user))
            else:
                self.status_lbl.configure(
                    text="✗ Неверный логин или пароль", text_color=RED)
        else:
            ok, msg = register(user, pwd)
            if ok:
                self.status_lbl.configure(text=f"✓ {msg}", text_color=GREEN)
                self.after(1000, lambda: self._switch("login"))
            else:
                self.status_lbl.configure(text=f"✗ {msg}", text_color=RED)

    def _open_main(self, username):
        self.destroy()
        self.on_success(username)