import os
import shutil
import subprocess
import sys
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QCheckBox,
    QPushButton, QTableWidget, QTableWidgetItem, QHeaderView, QTextEdit,
    QFileDialog, QMessageBox, QSplitter, QFrame, QLabel, QLineEdit, QComboBox,
    QProgressBar, QStatusBar, QGroupBox, QSizePolicy
)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QSize
from PyQt5.QtGui import QFont, QPalette, QColor, QIcon, QPixmap
from auditor_core import check_ports, check_permissions, check_cron, check_cve_services, make_report, save_report, level_name


class AuditWorker(QThread):
    finished = pyqtSignal(list, list, list, list)
    progress = pyqtSignal(str)

    def __init__(self, check_ports_flag, check_perm_flag, check_cron_flag, check_cve_flag):
        super().__init__()
        self.check_ports_flag = check_ports_flag
        self.check_perm_flag = check_perm_flag
        self.check_cron_flag = check_cron_flag
        self.check_cve_flag = check_cve_flag

    def run(self):
        network_items = []
        perm_items = []
        cron_items = []
        cve_items = []

        if self.check_ports_flag:
            self.progress.emit("Проверяем открытые порты...")
            network_items = check_ports()

        if self.check_perm_flag:
            self.progress.emit("Проверяем права доступа...")
            perm_items = check_permissions()

        if self.check_cron_flag:
            self.progress.emit("Проверяем cron-задачи...")
            cron_items = check_cron()

        if self.check_cve_flag and network_items:
            self.progress.emit("Проверяем потенциальные CVE по открытым сервисам...")
            cve_items = check_cve_services(network_items)

        self.progress.emit("Готово")
        self.finished.emit(network_items, perm_items, cron_items, cve_items)


class AuditorUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.level_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        self.setWindowTitle("Linux Auditor - Система аудита безопасности")
        self.setGeometry(100, 100, 1500, 900)
        self.setWindowIcon(QIcon())  # Можно добавить иконку позже

        # Темная тема
        self.setStyleSheet("""
            QMainWindow {
                background-color: #2b2b2b;
                color: #ffffff;
            }
            QGroupBox {
                font-weight: bold;
                border: 2px solid #555;
                border-radius: 5px;
                margin-top: 1ex;
                color: #ffffff;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 10px 0 10px;
                color: #4CAF50;
            }
            QPushButton {
                background-color: #4CAF50;
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 5px;
                font-size: 12px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #45a049;
            }
            QPushButton:pressed {
                background-color: #3e8e41;
            }
            QPushButton:disabled {
                background-color: #666;
                color: #999;
            }
            QCheckBox {
                font-size: 12px;
                color: #ffffff;
            }
            QComboBox, QLineEdit {
                padding: 8px;
                border: 1px solid #555;
                border-radius: 4px;
                font-size: 12px;
                background-color: #404040;
                color: #ffffff;
            }
            QComboBox::drop-down {
                border: none;
            }
            QComboBox::down-arrow {
                image: url(down_arrow.png); /* Можно добавить иконку */
            }
            QTableWidget {
                gridline-color: #555;
                background-color: #404040;
                color: #ffffff;
                selection-background-color: #4CAF50;
                alternate-background-color: #353535;
            }
            QHeaderView::section {
                background-color: #333;
                color: #4CAF50;
                padding: 8px;
                border: none;
                font-weight: bold;
                font-size: 12px;
            }
            QProgressBar {
                border: 2px solid #555;
                border-radius: 5px;
                text-align: center;
                background-color: #404040;
            }
            QProgressBar::chunk {
                background-color: #4CAF50;
                width: 10px;
            }
            QStatusBar {
                background-color: #333;
                color: #ffffff;
                border-top: 1px solid #555;
            }
            QLabel {
                color: #ffffff;
                font-size: 12px;
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
        layout.setSpacing(10)
        layout.setContentsMargins(15, 15, 15, 15)

        # Кнопка для раскрытия настроек
        self.btn_settings_toggle = QPushButton("▼ Настройки проверки")
        self.btn_settings_toggle.setMinimumHeight(30)
        self.btn_settings_toggle.clicked.connect(self.toggle_settings)
        layout.addWidget(self.btn_settings_toggle)

        # Группа настроек (раскрывается/складывается)
        self.settings_group = QGroupBox()
        self.settings_group.setFlat(True)
        settings_layout = QVBoxLayout(self.settings_group)
        settings_layout.setContentsMargins(20, 5, 5, 5)

        self.chk_ports = QCheckBox("Проверять открытые порты")
        self.chk_ports.setChecked(True)
        settings_layout.addWidget(self.chk_ports)

        self.chk_perm = QCheckBox("Проверять права файлов/каталогов")
        self.chk_perm.setChecked(True)
        settings_layout.addWidget(self.chk_perm)

        self.chk_cron = QCheckBox("Проверять cron-задачи")
        self.chk_cron.setChecked(True)
        settings_layout.addWidget(self.chk_cron)

        self.chk_cve = QCheckBox("Проверять CVE по открытым сервисам")
        self.chk_cve.setChecked(True)
        settings_layout.addWidget(self.chk_cve)

        self.settings_group.setVisible(True)
        layout.addWidget(self.settings_group)

        # Группа кнопок аудита
        audit_group = QGroupBox()
        audit_group.setFlat(True)
        audit_layout = QHBoxLayout(audit_group)

        self.btn_audit = QPushButton("Запустить аудит")
        self.btn_audit.setMinimumHeight(35)
        self.btn_audit.clicked.connect(self.run_audit)
        audit_layout.addWidget(self.btn_audit)

        self.btn_save = QPushButton("Сохранить отчёт")
        self.btn_save.setMinimumHeight(35)
        self.btn_save.clicked.connect(self.save_report_dialog)
        audit_layout.addWidget(self.btn_save)

        layout.addWidget(audit_group)

        # Группа фильтров
        filter_group = QGroupBox("Фильтры и поиск")
        filter_layout = QHBoxLayout(filter_group)

        filter_layout.addWidget(QLabel("Уровень риска:"))
        self.cmb_level = QComboBox()
        self.cmb_level.addItems(["all", "high", "medium", "low"])
        self.cmb_level.currentTextChanged.connect(self.update_table)
        filter_layout.addWidget(self.cmb_level)

        filter_layout.addWidget(QLabel("Поиск:"))
        self.txt_search = QLineEdit()
        self.txt_search.setPlaceholderText("Введите текст для поиска...")
        self.txt_search.textChanged.connect(self.update_table)
        filter_layout.addWidget(self.txt_search)

        self.btn_open = QPushButton("Открыть путь")
        self.btn_open.clicked.connect(self.open_selected_path)
        filter_layout.addWidget(self.btn_open)

        layout.addWidget(filter_group)

        # Таблица результатов
        table_group = QGroupBox("Результаты аудита")
        table_layout = QVBoxLayout(table_group)

        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Уровень", "Проблема", "Объект", "Описание", "Команда", "Флажок"])
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(2, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(3, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(4, QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(5, QHeaderView.Fixed)
        self.table.setSortingEnabled(True)
        self.table.cellClicked.connect(self.on_cell_clicked)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setColumnWidth(5, 15)  # Флажок
        table_layout.addWidget(self.table)

        layout.addWidget(table_group)

        # Прогресс и статус
        self.progress = QProgressBar()
        self.progress.setVisible(False)
        layout.addWidget(self.progress)

        self.status_bar = self.statusBar()
        self.status_bar.showMessage("Готов к аудиту системы безопасности")

    def toggle_settings(self):
        is_visible = self.settings_group.isVisible()
        self.settings_group.setVisible(not is_visible)
        self.btn_settings_toggle.setText("▶ Настройки проверки" if is_visible else "▼ Настройки проверки")

    def run_audit(self):
        self.btn_audit.setEnabled(False)
        self.btn_audit.setText("Выполняется...")
        self.progress.setVisible(True)
        self.progress.setRange(0, 0)  # Неопределённый прогресс
        self.status_bar.showMessage("Запуск комплексного аудита...")

        self.worker = AuditWorker(
            self.chk_ports.isChecked(),
            self.chk_perm.isChecked(),
            self.chk_cron.isChecked(),
            self.chk_cve.isChecked()
        )
        self.worker.progress.connect(self.update_progress)
        self.worker.finished.connect(self.on_audit_finished)
        self.worker.start()

    def update_progress(self, message):
        self.status_bar.showMessage(message)

    def on_audit_finished(self, network_items, perm_items, cron_items, cve_items):
        self.network_items = network_items
        self.perm_items = perm_items
        self.cron_items = cron_items
        self.cve_items = cve_items

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
        for i in cve_items:
            i["source"] = "cve"
            self.all_items.append(i)

        self.update_table()
        self.btn_audit.setEnabled(True)
        self.btn_audit.setText("Запустить аудит")
        self.progress.setVisible(False)
        total_issues = len(self.all_items)
        high_count = sum(1 for i in self.all_items if i["level"] == "high")
        self.status_bar.showMessage(f"Аудит завершён. Найдено проблем: {total_issues} (высокий риск: {high_count})")

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
            # Флажок
            indicator = QLabel()
            indicator.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
            if item["level"] == "critical":
                indicator.setStyleSheet("background-color: #ff4444; border: 1px solid #333; border-radius: 2px;")
            elif item["level"] == "high":
                indicator.setStyleSheet("background-color: #ff8800; border: 1px solid #333; border-radius: 2px;")
            elif item["level"] == "medium":
                indicator.setStyleSheet("background-color: #ffff00; border: 1px solid #333; border-radius: 2px;")
            elif item["level"] == "low":
                indicator.setStyleSheet("background-color: #4444ff; border: 1px solid #333; border-radius: 2px;")
            else:  # info
                indicator.setStyleSheet("background-color: #888888; border: 1px solid #333; border-radius: 2px;")
            self.table.setCellWidget(row, 5, indicator)

            level_item = QTableWidgetItem(level_name(item["level"]))
            level_item.setData(Qt.UserRole, self.level_order.get(item["level"], 5))
            self.table.setItem(row, 0, level_item)
            self.table.setItem(row, 1, QTableWidgetItem(item["problem"]))
            self.table.setItem(row, 2, QTableWidgetItem(item["object"]))
            self.table.setItem(row, 3, QTableWidgetItem(item["description"]))
            self.table.setItem(row, 4, QTableWidgetItem(item["recommendation"]))

        self.table.resizeColumnsToContents()
        self.table.resizeRowsToContents()

    def open_selected_path(self):
        selected_rows = set()
        for item in self.table.selectedItems():
            selected_rows.add(item.row())

        if not selected_rows:
            QMessageBox.information(self, "Информация", "Выберите строку в таблице результатов.")
            return

        row = list(selected_rows)[0]
        obj_path = self.table.item(row, 2).text()

        if not os.path.exists(obj_path):
            QMessageBox.warning(self, "Ошибка", f"Путь не существует: {obj_path}")
            return

        dir_path = os.path.dirname(obj_path) if os.path.isfile(obj_path) else obj_path

        try:
            if sys.platform.startswith("win"):
                os.startfile(dir_path)
            elif sys.platform.startswith("darwin"):
                subprocess.Popen(["open", dir_path])
            else:
                if not shutil.which("xdg-open"):
                    raise FileNotFoundError("xdg-open не найден")
                subprocess.Popen(["xdg-open", dir_path])
            QMessageBox.information(self, "Успех", f"Открыта директория: {dir_path}")
        except Exception as e:
            QMessageBox.critical(
                self,
                "Ошибка",
                f"Не удалось открыть директорию: {e}. Путь: {dir_path}",
            )

    def on_cell_clicked(self, row, col):
        if col == 4:  # Команда
            item = self.table.item(row, col)
            if item:
                QApplication.clipboard().setText(item.text())
                self.status_bar.showMessage("Команда скопирована в буфер обмена", 3000)

    def save_report_dialog(self):
        path, _ = QFileDialog.getSaveFileName(
            self, "Сохранить отчёт аудита", "audit_report.txt", "Текстовые файлы (*.txt);;Все файлы (*)"
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
            QMessageBox.critical(self, "Ошибка", f"Не удалось сохранить отчёт: {e}")


def main_ui():
    app = QApplication(sys.argv)
    app.setStyle("Fusion")  # Современный стиль
    app.setApplicationName("Linux Auditor")
    app.setApplicationVersion("1.0")
    window = AuditorUI()
    window.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main_ui()
