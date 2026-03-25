import os
import sys
import argparse

def parse_args():
    parser = argparse.ArgumentParser(description="Linux Auditor")
    parser.add_argument(
        "--nogui",
        action="store_true",
        help="Запустить без графического интерфейса",
    )
    parser.add_argument(
        "-o",
        "--output",
        default="audit_report.txt",
        help="файл для сохранения отчёта",
    )
    return parser.parse_args()

def main():
    args = parse_args()

    # Проверяем, можем ли запустить GUI
    can_use_gui = False
    try:
        from PyQt5.QtWidgets import QApplication
        can_use_gui = True
    except ImportError:
        pass

    # Если нет дисплея или принудительно CLI
    if args.nogui or not os.environ.get('DISPLAY') or not can_use_gui:
        from auditor_cli import main_cli
        # Передаем аргументы в CLI
        sys.argv = ['auditor_cli.py'] + sys.argv[1:]  # Симулируем вызов CLI с аргументами
        main_cli()
    else:
        from auditor_ui import main_ui
        main_ui()

if __name__ == "__main__":
    main()
