import argparse
import sys
from auditor_core import check_ports, check_permissions, check_cron, check_cve_services, get_cve_db, make_report, save_report


def parse_args():
    parser = argparse.ArgumentParser(description="Linux Auditor CLI")
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
    parser.add_argument(
        "--cve",
        action="store_true",
        help="Включить проверку CVE по открытым сервисам",
    )
    parser.add_argument(
        "--cve-update",
        action="store_true",
        help="Принудительно обновить базу CVE до текущей версии",
    )
    parser.add_argument(
        "--cve-cache-days",
        type=int,
        default=7,
        help="Сколько дней считать базу CVE актуальной (по умолчанию 7)",
    )
    parser.add_argument(
        "--cve-source",
        choices=["mitre", "cvelistv5", "local", "builtin", "all"],
        default="all",
        help="Источник CVE: mitre, cvelistv5, local (клонированный cvelistV5), builtin (статический), all (попытка всех)",
    )
    parser.add_argument(
        "--no-cve-online",
        action="store_true",
        help="Не запрашивать CVE-данные из сети, использовать только локальную базу/встроенный список",
    )
    return parser.parse_args()


def main_cli():
    args = parse_args()

    network_items = check_ports()
    perm_items = check_permissions()
    cron_items = check_cron()

    cve_items = []
    if args.cve:
        cve_db = get_cve_db(
            force_update=args.cve_update,
            ttl_days=args.cve_cache_days,
            allow_online=not args.no_cve_online,
            cve_source=args.cve_source,
        )
        cve_items = check_cve_services(network_items, cve_db=cve_db)

    report = make_report(network_items, perm_items, cron_items, cve_items)
    print(report, end="")
    save_report(report, args.output)
    print("Отчёт сохранён в файл:", args.output)


if __name__ == "__main__":
    main_cli()