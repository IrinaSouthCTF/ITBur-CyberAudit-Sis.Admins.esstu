import os
import subprocess
import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QCheckBox,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QTextEdit,
    QFileDialog, QMessageBox, QSplitter, QFrame, QLabel, QLineEdit, QComboBox,
    QProgressBar, QStatusBar
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from PyQt5.QtGui import QFont, QPalette, QColor, QIcon
from auditor_core import check_ports, check_permissions, check_cron, make_report, save_report, level_name


class AuditWorker(QThread):
    finished = pyqtSignal(list, list, list)
    progress = pyqtSignal(str)

    def __init__(self, check_ports_flag, check_perm_flag, check_cron_flag):
        super().__init__()
        self.check_ports_flag = check_ports_flag
        self.check_perm_flag = check_perm_flag
        self.check_cron_flag = check_cron_flag

    def run(self):
        network_items = []
        perm_items = []
        cron_items = []

        if self.check_ports_flag:
            self.progress.emit("Проверяем открытые порты...")
            network_items = check_ports()

        if self.check_perm_flag:
            self.progress.emit("Проверяем права доступа...")
            perm_items = check_permissions()

        if self.check_cron_flag:
            self.progress.emit("Проверяем cron-задачи...")
            cron_items = check_cron()

        self.progress.emit("Готово")
        self.finished.emit(network_items, perm_items, cron_items)


class AuditorUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Linux Auditor UI (Kali/Debian)")
        self.setGeometry(100, 100, 1400, 900)
        self.setStyleSheet("""
            QMainWindow {
                background-color: #f5f5f5;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 8px 16px;
                border-radius: 4px;
                font-size: 14px;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3e8e41;
            }
            QCheckBox {
                font-size: 14px;
            }
            QComboBox, QLineEdit {
                padding: 5px;
                border: 1px solid #ccc;
                border-radius: 4px;
                font-size: 14px;
            }
            QTableWidget {
                gridline-color: #ddd;
                selection-background-color: #e3f2fd;
            }
            QHeaderView::section {
                background-color: #2196F3;
                color: white;
                padding: 8px;
                border: none;
                font-weight: bold;
            }
            QStatusBar {
                background-color: #333;
                color: white;
            }
        """)

        self.all_items = []
        self.filtered_items = []
        self.network_items = []
        self.perm_items = []
        self.cron_items = []

        self.init_ui()

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)

        # Панель управления
        control_frame = QFrame()
        control_frame.setFrameStyle(QFrame.StyledPanel)
        control_layout = QHBoxLayout(control_frame)

        self.chk_ports = QCheckBox("Проверять открытые порты")
        self.chk_ports.setChecked(True)
        control_layout.addWidget(self.chk_ports)

        self.chk_perm = QCheckBox("Проверять права файлов/каталогов")
        self.chk_perm.setChecked(True)
        control_layout.addWidget(self.chk_perm)

        self.chk_cron = QCheckBox("Проверять cron")
        self.chk_cron.setChecked(True)
        control_layout.addWidget(self.chk_cron)

        self.btn_audit = QPushButton("Запустить аудит")
        self.btn_audit.clicked.connect(self.run_audit)
        control_layout.addWidget(self.btn_audit)

        self.btn_save = QPushButton("Сохранить отчёт")
        self.btn_save.clicked.connect(self.save_report_dialog)
        control_layout.addWidget(self.btn_save)

        layout.addWidget(control_frame)

        # Фильтры
        filter_frame = QFrame()
        filter_layout = QHBoxLayout(filter_frame)

        filter_layout.addWidget(QLabel("Фильтр уровня:"))
        self.cmb_level = QComboBox()
        self.cmb_level.addItems(["all", "high", "medium", "low"])
        self.cmb_level.currentTextChanged.connect(self.update_table)
        filter_layout.addWidget(self.cmb_level)

        filter_layout.addWidget(QLabel("Поиск:"))
        self.txt_search = QLineEdit()
        self.txt_search.textChanged.connect(self.update_table)
        filter_layout.addWidget(self.txt_search)

        self.btn_open = QPushButton("Открыть путь")
        self.btn_open.clicked.connect(self.open_selected_path)
        filter_layout.addWidget(self.btn_open)

        layout.addWidget(filter_frame)

        # Таблица результатов
        self.table = QTableWidget()
        self.table.setColumnCount(5)
        self.table.setHorizontalHeaderLabels(["Уровень", "Проблема", "Объект", "Описание", "Рекомендация"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        layout.addWidget(self.table)

        # Прогресс и статус
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Готов к работе")

    def run_audit(self):
        self.btn_audit.setEnabled(False)
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)  # Неопределённый прогресс
        self.status_bar.showMessage("Запуск аудита...")

        self.worker = AuditWorker(
            self.chk_ports.isChecked(),
            self.chk_perm.isChecked(),
            self.chk_cron.isChecked()
        )
        self.worker.progress.connect(self.update_progress)
        self.worker.finished.connect(self.on_audit_finished)
        self.worker.start()

    def update_progress(self, message):
        self.status_bar.showMessage(message)

    def on_audit_finished(self, network_items, perm_items, cron_items):
        self.network_items = network_items
        self.perm_items = perm_items
        self.cron_items = cron_items

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

        self.update_table()
        self.btn_audit.setEnabled(True)
        self.progress.setVisible(False)
        self.status_bar.showMessage(f"Найдено {len(self.all_items)} проблем")

    def update_table(self):
        level_filter = self.cmb_level.currentText()
        search_text = self.txt_search.text().lower()

        self.filtered_items = [
            item for item in self.all_items
            if (level_filter == "all" or item["level"] == level_filter) and
               (not search_text or search_text in " ".join([
                   item.get(k, "").lower() for k in ["object", "problem", "description", "recommendation"]
               ]))
        ]

        self.table.setRowCount(len(self.filtered_items))
        for row, item in enumerate(self.filtered_items):
            self.table.setItem(row, 0, QTableWidgetItem(level_name(item["level"])))
            self.table.setItem(row, 1, QTableWidgetItem(item["problem"]))
            self.table.setItem(row, 2, QTableWidgetItem(item["object"]))
            self.table.setItem(row, 3, QTableWidgetItem(item["description"]))
            self.table.setItem(row, 4, QTableWidgetItem(item["recommendation"]))

            # Цвета строк
            color = {
                "high": QColor("#ffcccc"),
                "medium": QColor("#ffffcc"),
                "low": QColor("#ccffcc")
            }.get(item["level"], QColor("#ffffff"))

            for col in range(5):
                self.table.item(row, col).setBackground(color)

        self.table.resizeColumnsToContents()

    def open_selected_path(self):
        selected_rows = set()
        for item in self.table.selectedItems():
            selected_rows.add(item.row())

        if not selected_rows:
            QMessageBox.information(self, "Инфо", "Выберите строку в таблице.")
            return

        row = list(selected_rows)[0]
        obj_path = self.table.item(row, 2).text()

        if not os.path.exists(obj_path):
            QMessageBox.warning(self, "Ошибка", f"Путь не существует: {obj_path}")
            return

        dir_path = os.path.dirname(obj_path) if os.path.isfile(obj_path) else obj_path

        try:
            subprocess.Popen(["xdg-open", dir_path])
            QMessageBox.information(self, "Успех", f"Открыта директория: {dir_path}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось открыть: {e}")

    def save_report_dialog(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить отчёт", "audit_report.txt", "Text files (*.txt);;All files (*)"
        )
        if not path:
            return

        filtered_network = [i for i in self.network_items if i in self.filtered_items]
        filtered_perm = [i for i in self.perm_items if i in self.filtered_items]
        filtered_cron = [i for i in self.cron_items if i in self.filtered_items]

        report = make_report(filtered_network, filtered_perm, filtered_cron)
        try:
            save_report(report, path)
            QMessageBox.information(self, "Успех", f"Отчёт сохранён: {path}")
        except Exception as e:
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить: {e}")


def main_ui():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")  # Современный стиль
    window = AuditorUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main_ui()
