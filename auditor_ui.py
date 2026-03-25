import argparse
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, scrolledtext
except ImportError:
    tk = None

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
    21: ("FTP", "high", "FTP передаёт данные без шифрования.", "Лучше отключить FTP и использовать SFTP или SSH."),
    23: ("Telnet", "high", "Telnet передаёт логины и команды в открытом виде.", "Отключите Telnet и оставьте SSH."),
    69: ("TFTP", "high", "TFTP не использует аутентификацию и шифрование.", "Отключите TFTP, если он не нужен."),
    80: ("HTTP", "medium", "Веб-служба доступна по сети и требует отдельной проверки.", "Проверьте конфигурацию сайта, web-root и служебные файлы."),
    111: ("rpcbind", "medium", "rpcbind увеличивает поверхность атаки и часто нужен только вместе с другими службами.", "Ограничьте доступ через firewall или отключите сервис."),
    139: ("NetBIOS", "high", "Сетевой доступ к NetBIOS лучше ограничивать внутренней сетью.", "Проверьте, нужен ли сервис, и закройте внешний доступ."),
    445: ("SMB", "high", "Открытый SMB требует жёсткого контроля доступа.", "Ограничьте доступ по IP и проверьте общие ресурсы."),
    3306: ("MySQL/MariaDB", "high", "СУБД доступна по сети.", "Оставьте доступ только доверенным хостам или привяжите службу к localhost."),
    5432: ("PostgreSQL", "high", "СУБД доступна по сети.", "Проверьте bind-адрес и правила доступа."),
    5900: ("VNC", "high", "VNC часто оставляют без достаточной защиты.", "Ограничьте доступ по IP или отключите сервис."),
    6379: ("Redis", "high", "Redis не должен быть открыт во внешнюю сеть без защиты.", "Привяжите службу к localhost и настройте аутентификацию."),
    8080: ("HTTP-alt", "medium", "На этом порту часто работают тестовые сервисы и панели.", "Проверьте, что именно слушает порт, и ограничьте доступ."),
    8443: ("HTTPS-alt", "medium", "На нестандартном HTTPS-порту нередко работают служебные интерфейсы.", "Проверьте назначение сервиса и закройте лишний доступ."),
    9200: ("Elasticsearch", "high", "Elasticsearch без защиты может раскрывать данные.", "Включите аутентификацию и ограничьте сетевой доступ."),
    11211: ("Memcached", "high", "Memcached не должен быть доступен извне.", "Оставьте доступ только с localhost или внутренней сети."),
    27017: ("MongoDB", "high", "MongoDB, открытая по сети, требует обязательной аутентификацию.", "Проверьте bindIp и включите аутентификацию."),
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
                    "Проверьте, нужны ли такие права. Обычно достаточно 755, а для закрытых каталогов 750.",
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
                "Уменьшите права до минимально необходимых, например 644, 640 или 600.",
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
                "Уберите лишние права записи, например установите 644 или 640.",
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
                "Уберите право записи для остальных пользователей.",
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
                "Проверьте содержимое файла и при необходимости ограничьте права, например до 640 или 600.",
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
                    "Проверьте, какой процесс использует этот порт и действительно ли нужен внешний доступ.",
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
                    "Уберите лишние права записи и проверьте владельца файла.",
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
                    recommendation,
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
        lines.append("Рекомендация:")
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


def parse_args():
    parser = argparse.ArgumentParser(description="Linux Auditor UI")
    parser.add_argument(
        "--nogui",
        action="store_true",
        help="Запустить без графического интерфейса, как консольный вариант",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="audit_report.txt",
        help="файл для сохранения отчёта (по умолчанию audit_report.txt)",
    )
    return parser.parse_args()


class AuditorUI:
    def __init__(self):
        if not tk:
            raise RuntimeError("Tkinter не установлен, GUI невозможен")

        self.root = tk.Tk()
        self.root.title("Linux Auditor UI (Kali/Debian)")
        self.root.geometry("1050x680")

        self.var_ports = tk.BooleanVar(value=True)
        self.var_perm = tk.BooleanVar(value=True)
        self.var_cron = tk.BooleanVar(value=True)

        self.filter_level = tk.StringVar(value="all")
        self.search_text = tk.StringVar(value="")

        self.all_items = []

        self._build_widgets()

    def _build_widgets(self):
        frame_controls = tk.Frame(self.root, padx=8, pady=8)
        frame_controls.pack(side=tk.TOP, fill=tk.X)

        tk.Checkbutton(frame_controls, text="Проверять открытые порты", variable=self.var_ports).grid(row=0, column=0, sticky="w")
        tk.Checkbutton(frame_controls, text="Проверять права файлов/каталогов", variable=self.var_perm).grid(row=0, column=1, sticky="w")
        tk.Checkbutton(frame_controls, text="Проверять cron", variable=self.var_cron).grid(row=0, column=2, sticky="w")

        tk.Button(frame_controls, text="Запустить аудит", command=self.run_audit).grid(row=0, column=3, padx=10)
        tk.Button(frame_controls, text="Сохранить отчёт", command=self.save_report_dialog).grid(row=0, column=4, padx=10)

        tk.Label(frame_controls, text="Фильтр уровня:").grid(row=1, column=0, sticky="e")
        tk.OptionMenu(frame_controls, self.filter_level, "all", "high", "medium", "low", command=lambda _: self.update_report()).grid(row=1, column=1, sticky="w")

        tk.Label(frame_controls, text="Поиск/фильтр по тексту:").grid(row=1, column=2, sticky="e")
        tk.Entry(frame_controls, textvariable=self.search_text, width=30).grid(row=1, column=3, sticky="w")
        tk.Button(frame_controls, text="Применить фильтр", command=self.update_report).grid(row=1, column=4, padx=10)

        tk.Button(frame_controls, text="Открыть путь выбранной строки", command=self.open_selected_object).grid(row=1, column=5, padx=10)

        self.text_report = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, font=("Consolas", 10))
        self.text_report.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=8, pady=8)

    def run_audit(self):
        self.text_report.delete("1.0", tk.END)
        self.text_report.insert(tk.END, "Собираем данные, пожалуйста подождите...\n")
        self.root.update()

        network_items = []
        perm_items = []
        cron_items = []

        if self.var_ports.get():
            network_items = check_ports()
        if self.var_perm.get():
            perm_items = check_permissions()
        if self.var_cron.get():
            cron_items = check_cron()

        self.all_items = []
        for i in network_items:
            i["source"] = "network"
            self.all_items.append(i)
        for i in perm_items:
            i["source"] = "permissions"
            self.all_items.append(i)
        for i in cron_items:
            i["source"] = "cron"
            self.all_items.append(i)

        self.network_items = network_items
        self.perm_items = perm_items
        self.cron_items = cron_items

        self.update_report()

    def update_report(self):
        level = self.filter_level.get()
        search = self.search_text.get().lower().strip()

        def included(item):
            if level != "all" and item["level"] != level:
                return False
            if search:
                haystack = " ".join([str(item.get(k, "")).lower() for k in ["object", "problem", "description", "recommendation"]])
                return search in haystack
            return True

        filtered = [item for item in self.all_items if included(item)]

        report = make_report(
            [i for i in self.network_items if included(i)],
            [i for i in self.perm_items if included(i)],
            [i for i in self.cron_items if included(i)],
        )

        self.text_report.delete("1.0", tk.END)
        self.text_report.insert(tk.END, report)

        if not self.all_items:
            self.text_report.insert(tk.END, "\nСначала нажмите 'Запустить аудит'.\n")

    def open_selected_object(self):
        if not self.all_items:
            messagebox.showinfo("Инфо", "Сначала выполните аудит и выберите объект.")
            return

        selected = self.text_report.selection_get() if self.text_report.tag_ranges(tk.SEL) else ""
        target_path = None

        if selected:
            for part in selected.splitlines():
                if part.strip().startswith("Объект:"):
                    target_path = part.split("Объект:", 1)[1].strip()
                    break

        if not target_path:
            full_line = self.text_report.get("insert linestart", "insert lineend").strip()
            if full_line.startswith("Объект:"):
                target_path = full_line.split("Объект:", 1)[1].strip()

        if not target_path:
            messagebox.showwarning("Не найден объект", "выделите строку с 'Объект:' в отчёте")
            return

        if not os.path.exists(target_path):
            messagebox.showwarning("Путь не найден", f"Путь не существует: {target_path}")
            return

        try:
            subprocess.Popen(["xdg-open", target_path])
        except Exception:
            try:
                subprocess.Popen(["xdg-open", os.path.dirname(target_path)])
            except Exception as exc:
                messagebox.showerror("Ошибка", f"Не удалось открыть путь: {exc}")
                return

        messagebox.showinfo("Открыто", f"Открывается: {target_path}")

    def save_report_dialog(self):
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
            initialfile="audit_report.txt",
            title="Сохранить отчет",
        )
        if not path:
            return

        report = self.text_report.get("1.0", tk.END)
        try:
            save_report(report, path)
            messagebox.showinfo("Сохранено", f"Отчёт сохранён в: {path}")
        except Exception as exc:
            messagebox.showerror("Ошибка", f"Не удалось сохранить отчёт: {exc}")

    def run(self):
        self.root.mainloop()


def main():
    args = parse_args()

    if args.nogui:
        network_items = check_ports()
        perm_items = check_permissions()
        cron_items = check_cron()

        report = make_report(network_items, perm_items, cron_items)
        print(report, end="")
        save_report(report, args.output)
        print("Отчёт сохранён в файл:", args.output)
        return

    if not tk:
        print("Tkinter не установлен, запустите с --nogui")
        sys.exit(1)

    ui = AuditorUI()
    ui.run()


if __name__ == "__main__":
    main()
