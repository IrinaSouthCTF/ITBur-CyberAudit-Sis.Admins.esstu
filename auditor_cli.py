import argparse
import sys
from auditor_core import check_ports, check_permissions, check_cron, check_cve_services, make_report, save_report


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
    return parser.parse_args()


def main_cli():
    args = parse_args()

    network_items = check_ports()
    perm_items = check_permissions()
    cron_items = check_cron()

    cve_items = []
    if args.cve:
        cve_items = check_cve_services(network_items)

    report = make_report(network_items, perm_items, cron_items, cve_items)
    print(report, end="")
    save_report(report, args.output)
    print("Отчёт сохранён в файл:", args.output)


if __name__ == "__main__":
    main_cli()