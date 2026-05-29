"""
rootkit_checker.py — Linux-специфичные проверки на rootkit.
Тема диплома: «обнаружение rootkit-подобных аномалий».

Проверки:
1. Скрытые процессы (ps vs /proc — classic rootkit trick)
2. Подозрительные модули ядра (lsmod / /proc/modules)
3. /etc/ld.so.preload — preload-инъекция
4. /proc/modules vs lsmod расхождения
5. Изменения системных бинарей (hash check)
"""
import os
import re
import subprocess
import hashlib
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional

try:
    from logger import get_logger
except ImportError:
    import logging
    def get_logger(n): return logging.getLogger(n)

log = get_logger("rootkit_checker")

# ── Структуры данных ───────────────────────────────────────────

@dataclass
class RootkitFinding:
    category:    str          # "hidden_process", "kernel_module", "preload", "sysfile"
    severity:    str          # "HIGH", "MEDIUM", "LOW"
    description: str
    detail:      str = ""
    timestamp:   str = field(default_factory=lambda: datetime.now().isoformat())

@dataclass
class RootkitScanResult:
    findings:     List[RootkitFinding] = field(default_factory=list)
    checked_at:   str = field(default_factory=lambda: datetime.now().isoformat())
    total_checks: int = 0
    passed:       int = 0
    failed:       int = 0

    @property
    def threat_level(self) -> str:
        if any(f.severity == "HIGH" for f in self.findings):
            return "HIGH"
        if any(f.severity == "MEDIUM" for f in self.findings):
            return "MEDIUM"
        if self.findings:
            return "LOW"
        return "CLEAN"

    def to_dict(self) -> dict:
        return {
            "threat_level":  self.threat_level,
            "checked_at":    self.checked_at,
            "total_checks":  self.total_checks,
            "passed":        self.passed,
            "failed":        self.failed,
            "findings_count": len(self.findings),
            "findings": [
                {
                    "category":    f.category,
                    "severity":    f.severity,
                    "description": f.description,
                    "detail":      f.detail,
                    "timestamp":   f.timestamp,
                }
                for f in self.findings
            ],
        }


# ── Вспомогательные функции ────────────────────────────────────

def _run(cmd: str) -> str:
    """Запустить команду и вернуть stdout (или '' при ошибке)."""
    try:
        result = subprocess.run(
            cmd, shell=True, capture_output=True,
            text=True, timeout=10
        )
        return result.stdout.strip()
    except Exception as e:
        log.debug(f"_run({cmd!r}) failed: {e}")
        return ""


def _file_md5(path: str) -> Optional[str]:
    try:
        h = hashlib.md5()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None


# ── Проверки ───────────────────────────────────────────────────

class RootkitChecker:
    """
    Набор Linux-специфичных проверок на наличие rootkit-активности.
    Работает без root (часть проверок) и с root (полный режим).
    """

    # Эталонные MD5 системных бинарей Ubuntu 24 (заполни после clean install)
    _BASELINE_HASHES: dict = {}

    # Подозрительные паттерны в именах модулей ядра
    _SUSPICIOUS_MOD_PATTERNS = [
        r"rootkit", r"r0otkit", r"hide", r"stealth",
        r"hook", r"inject", r"syscall_table",
        r"diamorphine", r"reptile", r"azazel",
        r"kbeast", r"suterusu",
    ]

    def __init__(self):
        self.is_root = (os.geteuid() == 0)
        log.info(f"RootkitChecker init (root={self.is_root})")

    # ── 1. Скрытые процессы ───────────────────────────────────

    def check_hidden_processes(self) -> List[RootkitFinding]:
        """
        Сравниваем PID-ы из /proc с выводом `ps -e`.
        Классический rootkit скрывает себя из ps, но /proc остаётся.
        """
        findings = []
        log.info("Checking hide processes...")

        # PIDs из /proc
        try:
            proc_pids = set(
                int(p) for p in os.listdir("/proc")
                if p.isdigit()
            )
        except Exception as e:
            log.warning(f"No access to /proc: {e}")
            return findings

        # PIDs из ps
        ps_out = _run("ps -e -o pid --no-headers")
        ps_pids = set()
        for line in ps_out.splitlines():
            line = line.strip()
            if line.isdigit():
                ps_pids.add(int(line))

        hidden = proc_pids - ps_pids
        # Убрать служебные «не-процессные» записи /proc
        hidden = {
            pid for pid in hidden
            if Path(f"/proc/{pid}/exe").exists()
        }

        if hidden:
            for pid in sorted(hidden):
                try:
                    name = Path(f"/proc/{pid}/comm").read_text().strip()
                except Exception:
                    name = "unknown"

                findings.append(RootkitFinding(
                    category    = "hidden_process",
                    severity    = "HIGH",
                    description = f"Hidden process found: PID {pid} ({name})",
                    detail      = f"PID {pid} have in /proc but is missing in ps",
                ))
                log.warning(f"HIDDEN PROCESS: PID={pid} name={name}")
        else:
            log.info("Hidden process not found")

        return findings

    # ── 2. Подозрительные модули ядра ─────────────────────────

    def check_kernel_modules(self) -> List[RootkitFinding]:
        """
        Проверяем загруженные модули ядра через lsmod и /proc/modules.
        Rootkit-модули часто имеют характерные имена.
        """
        findings = []
        log.info("Checking kernel modules...")

        # /proc/modules (более надёжный источник)
        proc_modules = set()
        try:
            for line in Path("/proc/modules").read_text().splitlines():
                mod_name = line.split()[0]
                proc_modules.add(mod_name)
        except Exception as e:
            log.warning(f"/proc/modules unavailable: {e}")

        # lsmod
        lsmod_modules = set()
        lsmod_out = _run("lsmod")
        for line in lsmod_out.splitlines()[1:]:
            parts = line.split()
            if parts:
                lsmod_modules.add(parts[0])

        # Расхождение между lsmod и /proc/modules — признак rootkit!
        only_in_proc = proc_modules - lsmod_modules
        only_in_proc = {m for m in only_in_proc if m}  # убрать пустые

        if only_in_proc:
            findings.append(RootkitFinding(
                category    = "kernel_module",
                severity    = "HIGH",
                description = "Modules are hidden from lsmod (have in /proc/modules, but not in lsmod)",
                detail      = ", ".join(sorted(only_in_proc)),
            ))
            log.warning(f"Hidden module: {only_in_proc}")

        # Проверяем имена на подозрительные паттерны
        all_modules = proc_modules | lsmod_modules
        for mod in all_modules:
            for pattern in self._SUSPICIOUS_MOD_PATTERNS:
                if re.search(pattern, mod, re.IGNORECASE):
                    findings.append(RootkitFinding(
                        category    = "kernel_module",
                        severity    = "HIGH",
                        description = f"Suspicious kernel module: {mod}",
                        detail      = f"Match to pattern: {pattern}",
                    ))
                    log.warning(f"Suspicious module: {mod}")
                    break

        if not findings:
            log.info(f"Kernel modules clear ({len(all_modules)} checked)")

        return findings

    # ── 3. /etc/ld.so.preload ─────────────────────────────────

    def check_ld_preload(self) -> List[RootkitFinding]:
        """
        /etc/ld.so.preload — любая запись здесь = ПОДОЗРИТЕЛЬНО.
        Rootkit использует этот файл для перехвата системных вызовов.
        """
        findings = []
        log.info("Checking /etc/ld.so.preload...")

        preload = Path("/etc/ld.so.preload")

        if preload.exists():
            try:
                content = preload.read_text().strip()
                if content:
                    findings.append(RootkitFinding(
                        category    = "preload",
                        severity    = "HIGH",
                        description = "/etc/ld.so.preload contains entries — preload injection is possible",
                        detail      = f"Content: {content[:200]}",
                    ))
                    log.warning(f"/etc/ld.so.preload: {content[:100]}")
                else:
                    log.info("/etc/ld.so.preload empty (normal)")

                # Проверяем права доступа
                stat = preload.stat()
                if oct(stat.st_mode)[-3:] not in ("600", "644"):
                    findings.append(RootkitFinding(
                        category    = "preload",
                        severity    = "MEDIUM",
                        description = f"/etc/ld.so.preload has special privileges: {oct(stat.st_mode)[-4:]}",
                        detail      = "Normal privileges: 644",
                    ))
            except PermissionError:
                log.debug("/etc/ld.so.preload: not privileges to read")
        else:
            log.info("/etc/ld.so.preload does not exist (normal)")

        return findings

    # ── 4. Проверка /proc/net/tcp (подозрительные порты) ──────

    def check_suspicious_ports(self) -> List[RootkitFinding]:
        """
        Парсим /proc/net/tcp напрямую.
        Rootkit может скрывать соединения от netstat, но /proc остаётся.
        """
        findings = []
        log.info("Checking /proc/net/tcp...")

        # Известные C&C порты
        suspicious_ports = {4444, 1337, 31337, 8080, 9999, 6666, 5555, 12345, 54321}

        try:
            content = Path("/proc/net/tcp").read_text()
            active_ports = set()

            for line in content.splitlines()[1:]:
                parts = line.split()
                if len(parts) < 4:
                    continue
                # local_address в формате hex:port
                local = parts[1]
                if ":" in local:
                    port_hex = local.split(":")[1]
                    port = int(port_hex, 16)
                    active_ports.add(port)

            found_suspicious = active_ports & suspicious_ports
            if found_suspicious:
                findings.append(RootkitFinding(
                    category    = "suspicious_port",
                    severity    = "MEDIUM",
                    description = "Active connections have been detected on suspicious ports",
                    detail      = f"Ports: {sorted(found_suspicious)}",
                ))
                log.warning(f"Suspicious ports: {found_suspicious}")
            else:
                log.info("No suspicious ports were detected")

        except Exception as e:
            log.debug(f"Reading error /proc/net/tcp: {e}")

        return findings

    # ── 5. Проверка системных файлов ──────────────────────────

    def check_system_files(self) -> List[RootkitFinding]:
        """
        Проверяем целостность ключевых системных файлов.
        Сравниваем с baseline хешами (если заданы).
        """
        findings = []
        log.info("Checking system files...")

        # Файлы которые rootkit часто подменяет
        critical_files = [
            "/bin/ls", "/bin/ps", "/bin/netstat",
            "/usr/bin/lsmod", "/sbin/lsmod",
            "/bin/ss", "/usr/bin/ss",
        ]

        for filepath in critical_files:
            p = Path(filepath)
            if not p.exists():
                continue

            # Проверка: файл должен принадлежать root
            try:
                stat = p.stat()
                if stat.st_uid != 0:
                    findings.append(RootkitFinding(
                        category    = "sysfile",
                        severity    = "HIGH",
                        description = f"The system file does not belong to root: {filepath}",
                        detail      = f"UID owner: {stat.st_uid}",
                    ))
                    log.warning(f"Suspicious owner у {filepath}: uid={stat.st_uid}")
            except Exception:
                pass

            # Проверка по baseline (если есть)
            if filepath in self._BASELINE_HASHES:
                current_md5 = _file_md5(filepath)
                expected_md5 = self._BASELINE_HASHES[filepath]
                if current_md5 and current_md5 != expected_md5:
                    findings.append(RootkitFinding(
                        category    = "sysfile",
                        severity    = "HIGH",
                        description = f"System file changed: {filepath}",
                        detail      = f"Expected: {expected_md5}, received: {current_md5}",
                    ))
                    log.warning(f"Changed {filepath}: {current_md5} != {expected_md5}")

        if not findings:
            log.info(f"System files are in order ({len(critical_files)} checked)")

        return findings

    # ── 6. Проверка /etc/passwd и /etc/sudoers ─────────────────

    def check_privilege_escalation(self) -> List[RootkitFinding]:
        """
        Ищем подозрительные записи в /etc/passwd (uid=0 у не-root),
        и нестандартные записи в sudoers.
        """
        findings = []
        log.info("Verification of privileged accounts...")

        try:
            passwd = Path("/etc/passwd").read_text()
            for line in passwd.splitlines():
                parts = line.split(":")
                if len(parts) < 4:
                    continue
                username = parts[0]
                uid = int(parts[2]) if parts[2].isdigit() else -1
                # UID=0 у не-root пользователя = ВЫСОКАЯ угроза
                if uid == 0 and username != "root":
                    findings.append(RootkitFinding(
                        category    = "privilege_escalation",
                        severity    = "HIGH",
                        description = f"User {username!r} have UID=0 (root-privileges)",
                        detail      = line,
                    ))
                    log.warning(f"UID=0 at user: {username}")
        except Exception as e:
            log.debug(f"Reading error /etc/passwd: {e}")

        return findings

    # ── Главный метод — запустить все проверки ─────────────────

    def run_all(self) -> RootkitScanResult:
        """Запустить все проверки и вернуть сводный результат."""
        result = RootkitScanResult()
        checks = [
            ("Hidden processes",     self.check_hidden_processes),
            ("Kernel modules",          self.check_kernel_modules),
            ("LD_PRELOAD injection",  self.check_ld_preload),
            ("Suspicious ports", self.check_suspicious_ports),
            ("System files",      self.check_system_files),
            ("Priveleges",           self.check_privilege_escalation),
        ]

        for name, check_fn in checks:
            result.total_checks += 1
            try:
                findings = check_fn()
                if findings:
                    result.findings.extend(findings)
                    result.failed += 1
                    log.warning(f"Checking «{name}»: {len(findings)} finds")
                else:
                    result.passed += 1
                    log.info(f"Checking «{name}»: CLEAR")
            except Exception as e:
                log.error(f"Error in checking «{name}»: {e}")
                result.total_checks -= 1

        log.info(
            f"Rootkit scan completed: threat={result.threat_level}, "
            f"finds={len(result.findings)}, "
            f"passed={result.passed}/{result.total_checks}"
        )
        return result


# ── CLI тест ────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== RootkitGuard — Rootkit Checker ===\n")
    checker = RootkitChecker()
    result  = checker.run_all()

    print(f"\nThreat level: {result.threat_level}")
    print(f"Result passed: {result.passed}/{result.total_checks}")
    print(f"Finds: {len(result.findings)}\n")

    if result.findings:
        for f in result.findings:
            print(f"  [{f.severity}] {f.category}: {f.description}")
            if f.detail:
                print(f"           → {f.detail[:100]}")
    else:
        print("  Everything looks good. No signs of a rootkit were found.")
