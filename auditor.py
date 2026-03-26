import os
import sys

def main():
    # Проверяем, можем ли запустить GUI
    can_use_gui = False
    try:
        from PyQt5.QtWidgets import QApplication
        can_use_gui = True
    except ImportError:
        pass

    # Если нет дисплея или принудительно CLI
    if "--nogui" in sys.argv or not os.environ.get('DISPLAY') or not can_use_gui:
        from auditor_cli import main_cli
        main_cli()
    else:
        from auditor_ui import main_ui
        main_ui()


if __name__ == "__main__":
    main()
