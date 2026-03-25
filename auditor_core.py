import argparse
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

CHECK_DIRS = [
    "/etc",
    "/var",
    "/home",
    "/opt",
    "/srv",
    "/tmp",
    "/usr/local",
]

SKIP_DIRS = {
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/snap",
    "/mnt",
    "/media",
    "/lost+found",
}

NORMAL_WORLD_WRITABLE_DIRS = {"/tmp", "/var/tmp", "/dev/shm"}

CRON_LOCATIONS = [
    "/etc/crontab",
    "/etc/cron.d",
    "/etc/cron.daily",
    "/etc/cron.hourly",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
    "/var/spool/cron",
    "/var/spool/cron/crontabs",
]

SUSPICIOUS_NAMES = [
    "shadow",
    "passwd",
    "secret",
    "token",
    "key",
    ".env",
    "id_rsa",
    "config",
    "backup",
    "bak",
    "sql",
]

PORT_INFO = {
    21: ("FTP", "high", "FTP передаёт данные без шифрования.", "sudo iptables -A INPUT -p tcp --dport 21 -j DROP"),
    23: ("Telnet", "high", "Telnet передаёт логины и команды в открытом виде.", "sudo iptables -A INPUT -p tcp --dport 23 -j DROP"),
    69: ("TFTP", "high", "TFTP не использует аутентификацию и шифрование.", "sudo iptables -A INPUT -p tcp --dport 69 -j DROP"),
    80: ("HTTP", "medium", "Веб-служба доступна по сети и требует отдельной проверки.", "sudo iptables -A INPUT -p tcp --dport 80 -j DROP"),
    111: ("rpcbind", "medium", "rpcbind увеличивает поверхность атаки и часто нужен только вместе с другими службами.", "sudo iptables -A INPUT -p tcp --dport 111 -j DROP"),
    139: ("NetBIOS", "high", "Сетевой доступ к NetBIOS лучше ограничивать внутренней сетью.", "sudo iptables -A INPUT -p tcp --dport 139 -j DROP"),
    445: ("SMB", "high", "Открытый SMB требует жёсткого контроля доступа.", "sudo iptables -A INPUT -p tcp --dport 445 -j DROP"),
    3306: ("MySQL/MariaDB", "high", "СУБД доступна по сети.", "sudo iptables -A INPUT -p tcp --dport 3306 -j DROP"),
    5432: ("PostgreSQL", "high", "СУБД доступна по сети.", "sudo iptables -A INPUT -p tcp --dport 5432 -j DROP"),
    5900: ("VNC", "high", "VNC часто оставляют без достаточной защиты.", "sudo iptables -A INPUT -p tcp --dport 5900 -j DROP"),
    6379: ("Redis", "high", "Redis не должен быть открыт во внешнюю сеть без защиты.", "sudo iptables -A INPUT -p tcp --dport 6379 -j DROP"),
    8080: ("HTTP-alt", "medium", "На этом порту часто работают тестовые сервисы и панели.", "sudo iptables -A INPUT -p tcp --dport 8080 -j DROP"),
    8443: ("HTTPS-alt", "medium", "На нестандартном HTTPS-порту нередко работают служебные интерфейсы.", "sudo iptables -A INPUT -p tcp --dport 8443 -j DROP"),
    9200: ("Elasticsearch", "high", "Elasticsearch без защиты может раскрывать данные.", "sudo iptables -A INPUT -p tcp --dport 9200 -j DROP"),
    11211: ("Memcached", "high", "Memcached не должен быть доступен извне.", "sudo iptables -A INPUT -p tcp --dport 11211 -j DROP"),
    27017: ("MongoDB", "high", "MongoDB, открытая по сети, требует обязательной аутентификацию.", "sudo iptables -A INPUT -p tcp --dport 27017 -j DROP"),
}

CRON_PATTERNS = [
    (r"/tmp/", "В cron используется путь из /tmp.", "Перенесите скрипт в постоянный каталог и проверьте права доступа."),
    (r"/var/tmp/", "В cron используется путь из /var/tmp.", "Проверьте, кто может изменять этот файл."),
    (r"chmod\s+777", "В cron найден chmod 777.", "Замените права 777 на минимально необходимые."),
    (r"chmod\s+666", "В cron найден chmod 666.", "Замените права 666 на более строгие."),
    (r"\bcurl\b", "Cron скачивает данные через curl.", "Проверьте источник и необходимость сетевой загрузки."),
    (r"\bwget\b", "Cron скачивает данные через wget.", "Проверьте источник и по возможности уберите сетевую загрузку."),
    (r"\bnc\b", "В cron используется netcat.", "Проверьте задачу вручную."),
    (r"\bnetcat\b", "В cron используется netcat.", "Проверьте задачу вручную."),
    (r"\bbash\s+-c\b", "Cron запускает команду через bash -c.", "Лучше вынести команду в отдельный скрипт и проверьте его права."),
    (r"\bsh\s+-c\b", "Cron запускает команду через sh -c.", "Лучше вынести команду в отдельный скрипт и проверьте его права."),
]


def run_command(cmd):
    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            check=False,
        )
    except OSError:
        return ""
    return result.stdout or ""


def skip_path(path):
    path = os.path.abspath(path)
    for item in SKIP_DIRS:
        if path == item or path.startswith(item + os.sep):
            return True
    return False


def add_item(items, section, level, obj, problem, description, recommendation, details=None):
    entry = {
        "section": section,
        "level": level,
        "object": obj,
        "problem": problem,
        "description": description,
        "recommendation": recommendation,
        "details": details or {},
    }
    items.append(entry)


def unique_items(items):
    result = []
    seen = set()
    for item in items:
        key = (
            item["section"],
            item["level"],
            item["object"],
            item["problem"],
            item["description"],
            item["recommendation"],
            tuple(sorted(item["details"].items())),
        )
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def level_name(level):
    if level == "high":
        return "HIGH"
    if level == "medium":
        return "MEDIUM"
    return "LOW"


def looks_sensitive(path):
    name = os.path.basename(path).lower()
    for part in SUSPICIOUS_NAMES:
        if part in name:
            return True
    return False


def walk_paths():
    for base in CHECK_DIRS:
        if not os.path.exists(base) or skip_path(base):
            continue
        for root, dirs, files in os.walk(base, topdown=True, followlinks=False):
            dirs[:] = [d for d in dirs if not skip_path(os.path.join(root, d))]
            for dirname in dirs:
                yield os.path.join(root, dirname), True
            for filename in files:
                yield os.path.join(root, filename), False


def check_permissions():
    items = []

    for path, is_dir in walk_paths():
        try:
            mode = stat.S_IMODE(os.lstat(path).st_mode)
        except OSError:
            continue

        mode_text = oct(mode)

        if is_dir:
            if mode & 0o002:
                sticky_bit = bool(mode & stat.S_ISVTX)
                level = "medium"
                if path not in NORMAL_WORLD_WRITABLE_DIRS and not sticky_bit:
                    level = "high"
                add_item(
                    items,
                    "permissions",
                    level,
                    path,
                    "Каталог открыт на запись для всех",
                    "Каталог может изменять любой пользователь системы.",
                    f"sudo chmod 755 '{path}'",
                    {"Права": mode_text},
                )
            continue

        if mode == 0o777:
            add_item(
                items,
                "permissions",
                "high",
                path,
                "Файл с правами 777",
                "Файл доступен всем на чтение, запись и выполнение.",
                f"sudo chmod 644 '{path}'",
                {"Права": mode_text},
            )
        elif mode == 0o666:
            add_item(
                items,
                "permissions",
                "high",
                path,
                "Файл с правами 666",
                "Файл доступен всем на чтение и запись.",
                f"sudo chmod 644 '{path}'",
                {"Права": mode_text},
            )
        elif mode & 0o002:
            add_item(
                items,
                "permissions",
                "high",
                path,
                "Файл открыт на запись для всех",
                "Обычный файл имеет признак world-writable.",
                f"sudo chmod o-w '{path}'",
                {"Права": mode_text},
            )

        if (mode & 0o004) and looks_sensitive(path):
            add_item(
                items,
                "permissions",
                "medium",
                path,
                "Подозрительный файл доступен на чтение всем",
                "Имя файла похоже на конфигурационный, ключевой или резервный.",
                f"sudo chmod 600 '{path}'",
                {"Права": mode_text},
            )

    return unique_items(items)


def check_ports():
    items = []
    data = run_command(["ss", "-tulpn"])
    if not data:
        data = run_command(["netstat", "-tulpn"])

    for line in data.splitlines():
        low = line.lower()
        if "listen" not in low and not low.startswith("udp"):
            continue

        match = re.search(r":(\d+)(?:\s|$)", line)
        if not match:
            continue

        port = int(match.group(1))
        proc = "не определён"
        proc_match = re.search(r'users:\(\("([^\"]+)"', line)
        if proc_match:
            proc = proc_match.group(1)

        if "127.0.0.1:" in line or "::1:" in line:
            bind = "localhost"
        elif "0.0.0.0:" in line or "[::]:" in line or "*:" in line:
            bind = "all_interfaces"
        else:
            bind = "specific_address"

        if port in PORT_INFO:
            name, level, description, recommendation = PORT_INFO[port]
            if bind == "localhost" and level == "high":
                level = "medium"
                description = "Сервис относится к чувствительным, но сейчас привязан только к localhost. Это безопаснее, но конфигурацию всё равно стоит проверить."
            add_item(
                items,
                "network",
                level,
                f"порт {port}",
                f"Открытый сервис: {name}",
                description,
                recommendation,
                {"Привязка": bind, "Процесс": proc, "Строка": line.strip()},
            )
        else:
            if bind == "all_interfaces":
                add_item(
                    items,
                    "network",
                    "medium",
                    f"порт {port}",
                    "Необычный открытый порт",
                    "Порт слушает на всех интерфейсах, но не входит в список типовых портов, которые проверяет программа.",
                    f"sudo ufw deny {port}/tcp",
                    {"Привязка": bind, "Процесс": proc, "Строка": line.strip()},
                )

    return unique_items(items)


def get_cron_files():
    files = []
    for location in CRON_LOCATIONS:
        path = Path(location)
        if not path.exists():
            continue
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            try:
                for item in path.rglob("*"):
                    if item.is_file():
                        files.append(item)
            except OSError:
                continue
    return files


def read_text(path):
    try:
        if not path.is_file() or path.stat().st_size > 1024 * 1024:
            return ""
        with open(path, "rb") as fh:
            sample = fh.read(4096)
            if b"\x00" in sample:
                return ""
    except OSError:
        return ""

    for enc in ("utf-8", "latin-1", "cp1251"):
        try:
            return path.read_text(encoding=enc, errors="ignore")
        except OSError:
            continue
    return ""


def check_cron():
    items = []

    for cron_file in get_cron_files():
        try:
            mode = stat.S_IMODE(cron_file.stat().st_mode)
            if mode & 0o002:
                add_item(
                    items,
                    "cron",
                    "high",
                    str(cron_file),
                    "Cron-файл открыт на запись для всех",
                    "Файл планировщика может быть изменён любым пользователем.",
                    f"sudo chmod 600 '{cron_file}'",
                    {"Права": oct(mode)},
                )
        except OSError:
            pass

        text = read_text(cron_file)
        if not text:
            continue

        for pattern, description, recommendation in CRON_PATTERNS:
            if re.search(pattern, text, re.IGNORECASE):
                add_item(
                    items,
                    "cron",
                    "medium",
                    str(cron_file),
                    "Подозрительное содержимое cron-задачи",
                    description,
                    f"sudo nano '{cron_file}'",
                    {"Совпадение": pattern},
                )

    return unique_items(items)


def make_section(title, items):
    lines = ["=" * 80, title, "=" * 80]

    if not items:
        lines.append("Ничего подозрительного не найдено.")
        return "\n".join(lines)

    number = 1
    for item in items:
        lines.append(f"[{number}] Уровень риска: {level_name(item['level'])}")
        lines.append(f"Проблема: {item['problem']}")
        lines.append(f"Объект: {item['object']}")
        if item["details"]:
            for key, value in item["details"].items():
                lines.append(f"{key}: {value}")
        lines.append("")
        lines.append("Описание:")
        lines.append(item["description"])
        lines.append("")
        lines.append("Команда:")
        lines.append(item["recommendation"])
        lines.append("-" * 80)
        number += 1

    return "\n".join(lines)


def make_summary(network_items, perm_items, cron_items):
    high = 0
    medium = 0
    low = 0

    for item in network_items + perm_items + cron_items:
        if item["level"] == "high":
            high += 1
        elif item["level"] == "medium":
            medium += 1
        else:
            low += 1

    lines = [
        "=" * 80,
        "СВОДКА",
        "=" * 80,
        f"Проблем высокого уровня риска: {high}",
        f"Проблем среднего уровня риска: {medium}",
        f"Проблем низкого уровня риска: {low}",
        f"Найдено сетевых замечаний: {len(network_items)}",
        f"Найдено проблем с правами: {len(perm_items)}",
        f"Найдено замечаний по cron: {len(cron_items)}",
    ]
    return "\n".join(lines)


def make_report(network_items, perm_items, cron_items):
    parts = [
        "ОТЧЁТ БАЗОВОГО АУДИТА LINUX-СИСТЕМЫ",
        make_section("ПРОВЕРКА ОТКРЫТЫХ ПОРТОВ И СЕТЕВЫХ СЕРВИСОВ", network_items),
        make_section("ПРОВЕРКА ПРАВ ДОСТУПА К ФАЙЛАМ И КАТАЛОГАМ", perm_items),
        make_section("ПРОВЕРКА CRON-ЗАДАЧ", cron_items),
        make_summary(network_items, perm_items, cron_items),
    ]
    return "\n\n".join(parts) + "\n"


def save_report(text, filename):
    with open(filename, "w", encoding="utf-8") as fh:
        fh.write(text)