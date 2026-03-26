import argparse
import datetime
import glob
import json
import logging
import os
import re
import socket
import stat
import subprocess
import sys
import urllib.request
import urllib.error
import urllib.parse
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s: %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S',
)

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

# Статическая база CVE-правил по известным сервисам/портам
CVE_SERVICE_DB = {
    22: [
        {
            "id": "CVE-2024-XXXX",
            "service": "OpenSSH",
            "level": "high",
            "description": "Обнаружен открытый SSH-порт. Возможно, используется уязвимая версия OpenSSH без обновлений.",
            "recommendation": "Обновите OpenSSH до последней стабильной версии и проверьте конфигурацию /etc/ssh/sshd_config.",
        }
    ],
    3306: [
        {
            "id": "CVE-2023-XXXX",
            "service": "MySQL/MariaDB",
            "level": "high",
            "description": "Обнаружен открытый MySQL-порт. Это повышает риск атак, если сервер не обновлён.",
            "recommendation": "Обновите MySQL/MariaDB и ограничьте доступ по сети (локалхост/брандмауэр).",
        }
    ],
    6379: [
        {
            "id": "CVE-2022-XXXX",
            "service": "Redis",
            "level": "high",
            "description": "Обнаружен открытый Redis-порт. Redis без аутентификации может привести к удалённому выполнению команд.",
            "recommendation": "Закройте доступ Redis из внешней сети, настройте авторизацию и используйте брандмауэр.",
        }
    ],
}

CVE_DB_FILENAME = "cve_db.json"
# Локальная директория cvelistV5 (можно указать через CVELOCAL_PATH)
CVELIST_LOCAL_PATH = os.environ.get("CVELOCAL_PATH", "./cves")
# GitHub raw base URL для cvelistV5 (парсинг без клонирования)
CVELIST_V5_BASE = "https://raw.githubusercontent.com/CVEProject/cvelistV5/main"
CVELIST_V5_PROXY = "https://ghproxy.com/https://raw.githubusercontent.com/CVEProject/cvelistV5/main"
# Если скачаем MITRE allitems.json, то можно указать директорию с файлом
MITRE_LOCAL_FILE = "allitems.json"

CVE_DB_TTL_DAYS = 7
CPE_MAP = {
    22: "cpe:2.3:a:openbsd:openssh",
    21: "cpe:2.3:a:wu:ftp",  # примеры
    23: "cpe:2.3:a:netkit:telnet",
    80: "cpe:2.3:a:apache:http_server",
    3306: "cpe:2.3:a:mysql:mysql",
    5432: "cpe:2.3:a:postgresql:postgresql",
    5900: "cpe:2.3:a:realvnc:vnc_connect",
    6379: "cpe:2.3:a:redis:redis",
    9200: "cpe:2.3:a:elastic:elasticsearch",
    27017: "cpe:2.3:a:mongodb:mongodb",
}

SERVICE_KEYWORDS = {
    22: ["openssh", "ssh"],
    21: ["ftp"],
    23: ["telnet"],
    80: ["http", "apache"],
    3306: ["mysql", "mariadb"],
    5432: ["postgresql"],
    5900: ["vnc"],
    6379: ["redis"],
    9200: ["elasticsearch"],
    27017: ["mongodb"],
}


def get_cve_db_path():
    return Path(os.path.abspath(os.path.dirname(__file__))) / CVE_DB_FILENAME


def load_local_cve_db():
    path = get_cve_db_path()
    if not path.exists():
        return None

    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError):
        return None


def save_local_cve_db(cve_db):
    path = get_cve_db_path()
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(cve_db, f, ensure_ascii=False, indent=2)
        return True
    except OSError:
        return False


def load_json_url(url, timeout=30):
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "LinuxAuditor/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                logging.warning("URL %s вернул статус %s", url, resp.status)
                return None
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        logging.warning("Не удалось загрузить JSON из %s: %s", url, e)
        return None


def load_json_file(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        logging.warning("Не удалось загрузить локальный JSON %s: %s", path, e)
        return None


def normalize_github_cvelist_url(url):
    if not isinstance(url, str) or not url:
        return url
    if url.startswith("https://github.com/") and "/blob/" in url:
        return url.replace("https://github.com/", "https://raw.githubusercontent.com/").replace("/blob/", "/")
    return url


def parse_cvelist_v5_to_service_db(cvelist_json):
    # Простое связывание по CPE из CPE_MAP или ключевым словам по сервисам
    if not cvelist_json:
        return {}

    if isinstance(cvelist_json, dict):
        if "CVE_Items" in cvelist_json:
            cve_items = cvelist_json.get("CVE_Items", [])
        elif "cves" in cvelist_json:
            cve_items = cvelist_json.get("cves", [])
        else:
            # Single cve record in cvelistV5 format
            cve_items = [cvelist_json]
    elif isinstance(cvelist_json, list):
        cve_items = cvelist_json
    else:
        return {}

    if not cve_items:
        return {}

    result = {}
    cpe_to_port = {v: k for k, v in CPE_MAP.items()}

    for item in cve_items:
        if not isinstance(item, dict):
            continue

        # ID and description support for both NVD and cvelistV5 payloads
        cve_id = None
        if item.get("cve", {}).get("CVE_data_meta"):
            cve_id = item.get("cve", {}).get("CVE_data_meta", {}).get("ID")
        elif item.get("cveMetadata"):
            cve_id = item.get("cveMetadata", {}).get("cveId")

        if not cve_id:
            continue

        desc = "Неизвестная уязвимость"
        if item.get("cve", {}).get("description"):
            desclist = item.get("cve", {}).get("description", {}).get("description_data", [])
            desc = next((x.get("value") for x in desclist if x.get("value")), desc)
        elif item.get("containers", {}).get("cna", {}).get("descriptions"):
            desclist = item.get("containers", {}).get("cna", {}).get("descriptions", [])
            desc = next((x.get("value") for x in desclist if x.get("value")), desc)

        # CVSS score
        score = None
        if item.get("impact"):
            impact = item.get("impact", {})
            if "baseMetricV3" in impact and impact["baseMetricV3"].get("cvssV3"):
                score = impact["baseMetricV3"]["cvssV3"].get("baseScore")
            elif "baseMetricV2" in impact and impact["baseMetricV2"].get("cvssV2"):
                score = impact["baseMetricV2"]["cvssV2"].get("baseScore")
        else:
            metrics = item.get("containers", {}).get("cna", {}).get("metrics", [])
            for metric in metrics:
                for key in ("cvssV4_0", "cvssV3_1", "cvssV3_0", "cvssV2_0"):
                    cvss = metric.get(key)
                    if cvss and cvss.get("baseScore") is not None:
                        score = cvss.get("baseScore")
                        break
                if score is not None:
                    break

        level = cve_score_to_level(score)

        known_ports = set()

        # First try CPE matching like NVD
        cpe_nodes = item.get("cve", {}).get("configurations", {}).get("nodes", [])
        for node in cpe_nodes:
            for cpe_match in node.get("cpe_match", []):
                cpe23 = cpe_match.get("cpe23Uri")
                if not cpe23:
                    continue
                for known_cpe, port in cpe_to_port.items():
                    if cpe23.startswith(known_cpe):
                        known_ports.add(port)

        # Fallback: распознавание по имени продукта и поставщика
        if not known_ports:
            affected = item.get("containers", {}).get("cna", {}).get("affected", [])
            known_parts = []
            for record in affected:
                if isinstance(record, dict):
                    known_parts.append(str(record.get("vendor", "")).lower())
                    known_parts.append(str(record.get("product", "")).lower())
                    for ver in record.get("versions", []):
                        if isinstance(ver, dict):
                            known_parts.append(str(ver.get("version", "")).lower())

            for port, keywords in SERVICE_KEYWORDS.items():
                for keyword in keywords:
                    for part in known_parts:
                        if keyword in part:
                            known_ports.add(port)
                            break
                    if port in known_ports:
                        break

        # Еще одна возможность с разделом cpe
        if not known_ports and item.get("containers", {}).get("cna", {}).get("problemTypes"):
            # в этих данных нет cpe, нужно прочитать заголовок или описание
            pass

        for port in known_ports:
            service_name = CPE_MAP.get(port, "unknown")
            entry = {
                "id": cve_id,
                "service": service_name,
                "level": level,
                "description": desc,
                "recommendation": "Проверьте обновления и конфигурацию сервиса.",
            }
            result.setdefault(port, []).append(entry)

    return result


def parse_mitre_cpe_uri(cpe_uri):
    if not isinstance(cpe_uri, str) or not cpe_uri.startswith("cpe:2.3:"):
        return None
    parts = cpe_uri.split(":")
    if len(parts) < 6:
        return None
    vendor = parts[3].lower().strip()
    product = parts[4].lower().strip()
    if not vendor or not product:
        return None
    return f"{vendor}:{product}"


def parse_mitre_feed_to_service_db(mitre_json):
    if not isinstance(mitre_json, dict):
        return {}

    cve_items = []
    if "CVE_data_Mitre" in mitre_json and isinstance(mitre_json.get("CVE_data_Mitre", {}).get("CVE_Items"), list):
        cve_items = mitre_json.get("CVE_data_Mitre", {}).get("CVE_Items", [])
    elif "CVE_Items" in mitre_json:
        cve_items = mitre_json.get("CVE_Items", [])

    if not cve_items:
        return {}

    result = {}
    cpe_to_port = {v: k for k, v in CPE_MAP.items()}

    for item in cve_items:
        if not isinstance(item, dict):
            continue

        cve_meta = item.get("cve", {}).get("CVE_data_meta", {})
        cve_id = cve_meta.get("ID")
        if not cve_id:
            continue

        desc = "Неизвестная уязвимость"
        desclist = item.get("cve", {}).get("description", {}).get("description_data", [])
        if isinstance(desclist, list) and desclist:
            desc = next((x.get("value") for x in desclist if x.get("value")), desc)

        score = None
        if item.get("impact"):
            impact = item.get("impact", {})
            if "baseMetricV3" in impact and impact["baseMetricV3"].get("cvssV3"):
                score = impact["baseMetricV3"]["cvssV3"].get("baseScore")
            elif "baseMetricV2" in impact and impact["baseMetricV2"].get("cvssV2"):
                score = impact["baseMetricV2"]["cvssV2"].get("baseScore")

        level = cve_score_to_level(score)

        known_ports = set()
        cpe_nodes = item.get("configurations", {}).get("nodes", [])
        for node in cpe_nodes:
            for cpe_match in node.get("cpe_match", []):
                cpe23 = cpe_match.get("cpe23Uri")
                cpe_key = parse_mitre_cpe_uri(cpe23)
                if not cpe_key:
                    continue
                for known_cpe, port in cpe_to_port.items():
                    if cpe_key.startswith(known_cpe):
                        known_ports.add(port)

        if not known_ports:
            for port, keywords in SERVICE_KEYWORDS.items():
                text = (item.get("cve", {}).get("problemtype", {}).get("problemtype_data", []) or [])
                if isinstance(text, list):
                    text = " ".join(str(x) for x in text)
                for keyword in keywords:
                    if keyword in desc.lower() or keyword in str(text).lower():
                        known_ports.add(port)
                        break

        for port in known_ports:
            service_name = CPE_MAP.get(port, "unknown")
            entry = {
                "id": cve_id,
                "service": service_name,
                "level": level,
                "description": desc,
                "recommendation": "Проверьте обновления и конфигурацию сервиса.",
            }
            result.setdefault(port, []).append(entry)

    return result


def load_mitre_local(local_path=None):
    local_path = local_path or MITRE_LOCAL_PATH
    if not local_path:
        return None

    local_file = os.path.join(local_path, MITRE_LOCAL_FILE)
    if not os.path.exists(local_file):
        return None

    data = load_json_file(local_file)
    if not data:
        return None

    mapped = parse_mitre_feed_to_service_db(data)
    if not mapped:
        return None

    return {
        "data": mapped,
        "meta": {"source": "mitre-local", "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()},
    }


def fetch_mitre_cve_db(timeout=30):
    # Локальное хранилище приоритетно
    local_result = load_mitre_local()
    if local_result:
        return local_result

    try:
        req = urllib.request.Request(MITRE_DATA_URL, headers={"User-Agent": "LinuxAuditor/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            if resp.status != 200:
                logging.warning("MITRE feed %s вернул статус %s", MITRE_DATA_URL, resp.status)
                return None
            content = resp.read()
    except Exception as e:
        logging.warning("Не удалось скачать MITRE feed %s: %s", MITRE_DATA_URL, e)
        return None

    try:
        import io, zipfile

        with zipfile.ZipFile(io.BytesIO(content)) as zf:
            with zf.open(MITRE_LOCAL_FILE) as f:
                data = json.load(f)
    except Exception as e:
        logging.warning("Ошибка при чтении MITRE ZIP %s: %s", MITRE_DATA_URL, e)
        return None

    mapped = parse_mitre_feed_to_service_db(data)
    if not mapped:
        return None

    return {
        "data": mapped,
        "meta": {"source": "mitre", "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()},
    }


def fetch_cvelist_v5_db(timeout=30):
    # Парсим свежие CVE из cvelistV5 прямо с GitHub (raw content) без полного клонирования.
    candidate_paths = [
        "cves/delta.json",
        "cves/deltaLog.json",
        "delta.json",
        "deltaLog.json",
    ]

    for base in (CVELIST_V5_BASE, CVELIST_V5_PROXY):
        for suffix in candidate_paths:
            url = f"{base}/{suffix}"
            data = load_json_url(url, timeout=timeout)
            if not isinstance(data, dict):
                continue

            # В delta.json и deltaLog.json описаны изменённые/новые CVE
            changes = []
            changes.extend(data.get("new", []))
            changes.extend(data.get("updated", []))

            if changes:
                mapped = {}
                max_fetch = 250
                for idx, entry in enumerate(changes):
                    if idx >= max_fetch:
                        break
                    github_link = entry.get("githubLink") or entry.get("url")
                    if not github_link:
                        continue
                    github_link = normalize_github_cvelist_url(github_link)
                    if not github_link:
                        continue

                    cve_payload = load_json_url(github_link, timeout=timeout)
                    if not cve_payload:
                        continue

                    item_data = parse_cvelist_v5_to_service_db(cve_payload)
                    for port, entries in item_data.items():
                        mapped.setdefault(port, []).extend(entries)

                if mapped:
                    return {
                        "data": mapped,
                        "meta": {"source": f"cvelistv5-github:{suffix}", "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()},
                    }

            # Иногда в этих файлах содержится полный набор или прямой CVE item
            mapped = parse_cvelist_v5_to_service_db(data)
            if mapped:
                return {
                    "data": mapped,
                    "meta": {"source": f"cvelistv5-github:{suffix}", "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()},
                }

    return None


def load_cvelist_v5_local(local_path=None):
    local_path = local_path or CVELIST_LOCAL_PATH
    if not local_path:
        return None

    # Предпочитаем delta.json (индекс обновлённых CVE)
    delta_path = os.path.join(local_path, "delta.json")
    if os.path.exists(delta_path):
        delta = load_json_file(delta_path)
        if isinstance(delta, dict):
            changes = []
            changes.extend(delta.get("new", []))
            changes.extend(delta.get("updated", []))

            mapped = {}
            max_fetch = 150
            for idx, entry in enumerate(changes):
                if idx >= max_fetch:
                    break
                github_link = entry.get("githubLink")
                if not github_link:
                    continue
                suffix = github_link.replace("https://raw.githubusercontent.com/CVEProject/cvelistV5/main/", "")
                if suffix.startswith("cves/"):
                    suffix = suffix[len("cves/"):]
                cve_path = os.path.join(local_path, suffix)
                data = load_json_file(cve_path)
                if not data:
                    continue
                entry_data = parse_cvelist_v5_to_service_db(data)
                for port, entries in entry_data.items():
                    mapped.setdefault(port, []).extend(entries)

            if mapped:
                return {
                    "data": mapped,
                    "meta": {"source": "cvelistv5-local", "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()},
                }

    # Старая структура с JSON-скопированными файлами
    candidate_paths = [
        os.path.join(local_path, "nvdcve-1.1-modified.json"),
        os.path.join(local_path, "nvdcve-1.1-recent.json"),
        os.path.join(local_path, "nvdv5.json"),
        os.path.join(local_path, "delta.json"),
        os.path.join(local_path, "deltaLog.json"),
    ]

    for path in candidate_paths:
        if not os.path.exists(path):
            continue
        data = load_json_file(path)
        if data:
            mapped = parse_cvelist_v5_to_service_db(data)
            if mapped:
                return {
                    "data": mapped,
                    "meta": {"source": "cvelistv5-local", "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()},
                }

    return None


def is_cve_db_stale(cve_meta, ttl_days=CVE_DB_TTL_DAYS):
    if not isinstance(cve_meta, dict):
        return True

    timestamp = cve_meta.get("updated_at")
    if not timestamp:
        return True

    try:
        updated_at = datetime.datetime.fromisoformat(timestamp)
        if updated_at.tzinfo is None:
            updated_at = updated_at.replace(tzinfo=datetime.timezone.utc)
        else:
            updated_at = updated_at.astimezone(datetime.timezone.utc)
    except ValueError:
        return True

    delta = datetime.datetime.now(datetime.timezone.utc) - updated_at
    return delta.days >= ttl_days


def cve_score_to_level(score):
    if score is None:
        return "medium"
    try:
        score = float(score)
    except (TypeError, ValueError):
        return "medium"
    if score >= 9.0:
        return "high"
    if score >= 7.0:
        return "medium"
    if score >= 4.0:
        return "low"
    return "info"


def get_cve_db(force_update=False, ttl_days=CVE_DB_TTL_DAYS, allow_online=True, cve_source=None):
    local = load_local_cve_db()

    def save_and_return(db, src):
        db.setdefault("meta", {})
        db["meta"].update({"source": src, "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()})
        save_local_cve_db(db)
        return db

    def try_online_sources():
        if cve_source in (None, "all", "local"):
            local_remote = load_cvelist_v5_local()
            if local_remote:
                return save_and_return(local_remote, "cvelistv5-local")

        if cve_source in (None, "all", "mitre"):
            mitre_remote = fetch_mitre_cve_db()
            if mitre_remote:
                return save_and_return(mitre_remote, "mitre")

        if cve_source in (None, "all", "cvelistv5"):
            remote = fetch_cvelist_v5_db()
            if remote:
                return save_and_return(remote, "cvelistv5")

        return None

    if force_update and allow_online:
        online = try_online_sources()
        if online:
            return online

    if local:
        meta = local.get("meta", {})
        stale = is_cve_db_stale(meta, ttl_days)
        if stale and allow_online:
            online = try_online_sources()
            if online:
                return online
        return local

    if allow_online:
        online = try_online_sources()
        if online:
            return online

    return {"data": CVE_SERVICE_DB, "meta": {"source": "builtin", "updated_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}}


def normalize_cve_db(cve_db):
    if not cve_db:
        return CVE_SERVICE_DB
    if isinstance(cve_db, dict) and "data" in cve_db and isinstance(cve_db["data"], dict):
        normalized = {}
        for k, v in cve_db["data"].items():
            try:
                normalized[int(k)] = v
            except (ValueError, TypeError):
                continue
        return normalized
    if isinstance(cve_db, dict):
        # Возможно старый формат
        return cve_db
    return CVE_SERVICE_DB

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
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            logging.warning("Команда %s вернула код %s: %s", cmd, result.returncode, result.stderr.strip())
        return result.stdout or ""
    except OSError as e:
        logging.warning("Не удалось выполнить команду %s: %s", cmd, e)
        return ""
    except Exception as e:
        logging.exception("Неожиданная ошибка при выполнении команды %s", cmd)
        return ""


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
    return {
        "critical": "CRITICAL",
        "high": "HIGH",
        "medium": "MEDIUM",
        "low": "LOW",
        "info": "INFO",
    }.get(str(level).lower(), str(level).upper() if level else "UNKNOWN")


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


_iptables_drop_rules_cache = None

def _load_iptables_drop_rules():
    global _iptables_drop_rules_cache
    _iptables_drop_rules_cache = set()
    data = run_command(["sudo", "iptables", "-L", "INPUT", "-n"])
    for line in data.splitlines():
        if "DROP" not in line:
            continue
        m = re.search(r"dpt:(\d+)", line)
        if not m:
            continue
        try:
            _iptables_drop_rules_cache.add(int(m.group(1)))
        except ValueError:
            continue
    return _iptables_drop_rules_cache


def has_drop_rule(port):
    global _iptables_drop_rules_cache
    if _iptables_drop_rules_cache is None:
        try:
            _load_iptables_drop_rules()
        except Exception as e:
            logging.warning("Не удалось получить правила iptables: %s", e)
            _iptables_drop_rules_cache = set()
    return port in _iptables_drop_rules_cache


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

        try:
            port = int(match.group(1))
        except (TypeError, ValueError):
            continue

        if port <= 0 or port > 65535:
            continue

        if has_drop_rule(port):
            continue  # Порт заблокирован firewall'ом, пропускаем

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
                    f"sudo iptables -A INPUT -p tcp --dport {port} -j DROP",
                    {"Привязка": bind, "Процесс": proc, "Строка": line.strip()},
                )

    return unique_items(items)


def _extract_port_from_object(obj):
    # ожидаем формат "порт <число>" (русский) или "port <число>"
    m = re.search(r"(?:порт|port)\s+(\d+)", str(obj), re.IGNORECASE)
    if m:
        return int(m.group(1))
    return None


def check_cve_services(network_items, cve_db=None):
    cve_rules = normalize_cve_db(cve_db or get_cve_db())
    items = []

    for net in network_items:
        port = _extract_port_from_object(net.get("object", ""))
        if not port or port not in cve_rules:
            continue

        for cve in cve_rules.get(port, []):
            add_item(
                items,
                "cve",
                cve.get("level", "medium"),
                net.get("object", f"порт {port}"),
                f"Потенциальная уязвимость {cve.get('id')} ({cve.get('service')})",
                cve.get("description", "Обнаружен сервис, подверженный известной CVE."),
                cve.get("recommendation", "Проверьте обновления и конфигурацию сервиса."),
                {
                    "CVE": cve.get("id"),
                    "Сервис": cve.get("service"),
                    "Основание": f"Открыт порт {port}",
                    "Состояние": net.get("details", {}).get("Привязка", "неизвестно"),
                },
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


def make_summary(network_items, perm_items, cron_items, cve_items=None):
    if cve_items is None:
        cve_items = []

    high = 0
    medium = 0
    low = 0

    for item in network_items + perm_items + cron_items + cve_items:
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
        f"Найдено CVE-замечаний: {len(cve_items)}",
    ]
    return "\n".join(lines)


def make_report(network_items, perm_items, cron_items, cve_items=None):
    if cve_items is None:
        cve_items = []
    parts = [
        "ОТЧЁТ БАЗОВОГО АУДИТА LINUX-СИСТЕМЫ",
        make_section("ПРОВЕРКА ОТКРЫТЫХ ПОРТОВ И СЕТЕВЫХ СЕРВИСОВ", network_items),
        make_section("ПРОВЕРКА ПРАВ ДОСТУПА К ФАЙЛАМ И КАТАЛОГАМ", perm_items),
        make_section("ПРОВЕРКА CRON-ЗАДАЧ", cron_items),
        make_section("ПРОВЕРКА CVE-СЕРВИСОВ (по открытым портам)", cve_items),
        make_summary(network_items, perm_items, cron_items, cve_items),
    ]
    return "\n\n".join(parts) + "\n"


def save_report(text, filename):
    with open(filename, "w", encoding="utf-8") as fh:
        fh.write(text)