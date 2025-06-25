from PyQt5.QtWidgets import (QApplication, QMainWindow, QPushButton, QTextEdit, QVBoxLayout, QWidget, QFileDialog,
                             QProgressBar, QListWidget, QMessageBox, QHBoxLayout, QLabel, QTimeEdit, QComboBox, QDialog,
                             QLineEdit)
from PyQt5.QtCore import Qt, QThread, pyqtSignal, QTimer, QTime
from PyQt5.QtGui import QFont, QIcon
import sys
import uuid
import subprocess
import requests
import os
import shutil
from datetime import datetime
import json

unique_id = str(uuid.uuid4())
QUARANTINE_FOLDER = os.path.join(os.path.expanduser("~"), "antiv_quarantine")
SCHEDULE_FILE = os.path.join(os.path.expanduser("~"), "antiv_schedule.json")


class ScheduleDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.scan_path = None
        self.setWindowTitle("Schedule Scan")
        self.setModal(True)
        self.setup_ui()
        self.load_schedules()

    def setup_ui(self):
        layout = QVBoxLayout()

        # Time selection
        time_layout = QHBoxLayout()
        time_layout.addWidget(QLabel("Scan Time:"))
        self.time_edit = QTimeEdit()
        self.time_edit.setDisplayFormat("HH:mm")
        time_layout.addWidget(self.time_edit)

        # Frequency selection
        freq_layout = QHBoxLayout()
        freq_layout.addWidget(QLabel("Frequency:"))
        self.freq_combo = QComboBox()
        self.freq_combo.addItems(["Daily", "Weekly"])
        freq_layout.addWidget(self.freq_combo)

        # Path selection
        path_layout = QHBoxLayout()
        self.path_edit = QLineEdit()
        self.path_btn = QPushButton("Select Path")
        self.path_btn.clicked.connect(self.select_path)
        path_layout.addWidget(self.path_edit)
        path_layout.addWidget(self.path_btn)

        # Schedule list
        self.schedule_list = QListWidget()

        # Control buttons
        btn_layout = QHBoxLayout()
        add_btn = QPushButton("Add Schedule")
        remove_btn = QPushButton("Remove Selected")
        add_btn.clicked.connect(self.add_schedule)
        remove_btn.clicked.connect(self.remove_schedule)
        btn_layout.addWidget(add_btn)
        btn_layout.addWidget(remove_btn)

        # Add all layouts to main layout
        layout.addLayout(time_layout)
        layout.addLayout(freq_layout)
        layout.addLayout(path_layout)
        layout.addWidget(self.schedule_list)
        layout.addLayout(btn_layout)

        self.setLayout(layout)
        self.setStyleSheet("""
            QDialog {
                background-color: #1e2124;
                color: white;
            }
            QLabel {
                color: white;
            }
            QLineEdit, QTimeEdit, QComboBox {
                background-color: #2a2e33;
                color: white;
                border: 1px solid #444444;
                padding: 5px;
                border-radius: 3px;
            }
            
            QComboBox QAbstractItemView {
                background-color: #2B2B2B;
                color: #2B2B2B;
                selection-background-color: #2196f3;
                selection-color: white;
                border: 1px solid #444444;
            }
            
            QPushButton {
                background-color: #2196f3;
                color: white;
                border: none;
                padding: 5px;
                border-radius: 3px;
            }
            QListWidget {
                background-color: #2a2e33;
                color: white;
                border: 1px solid #444444;
                border-radius: 3px;
            }
        """)

    def select_path(self):
        path = QFileDialog.getExistingDirectory(self, "Select Directory to Scan")
        if path:
            if os.name == 'nt':  # Windows
                self.scan_path = path.replace('/', '\\')
            else:
                self.scan_path = path
            self.path_edit.setText(self.scan_path)

    def add_schedule(self):
        if not self.path_edit.text():
            QMessageBox.warning(self, "Error", "Please select a path to scan")
            return

        schedule = {
            'time': self.time_edit.time().toString("HH:mm"),
            'frequency': self.freq_combo.currentText(),
            'path': self.path_edit.text(),
            'last_run': None
        }

        schedules = self.load_schedules()
        schedules.append(schedule)
        self.save_schedules(schedules)
        self.refresh_schedule_list()

    def remove_schedule(self):
        current = self.schedule_list.currentRow()
        if current >= 0:
            schedules = self.load_schedules()
            del schedules[current]
            self.save_schedules(schedules)
            self.refresh_schedule_list()

    def load_schedules(self):
        if os.path.exists(SCHEDULE_FILE):
            try:
                with open(SCHEDULE_FILE, 'r') as f:
                    return json.load(f)
            except json.JSONDecodeError:
                return []
        return []

    def save_schedules(self, schedules):
        with open(SCHEDULE_FILE, 'w') as f:
            json.dump(schedules, f)

    def refresh_schedule_list(self):
        self.schedule_list.clear()
        schedules = self.load_schedules()
        for schedule in schedules:
            self.schedule_list.addItem(
                f"Scan {schedule['path']} {schedule['frequency']} at {schedule['time']}")


class ScanThread(QThread):
    update_progress = pyqtSignal(int, str)
    finished_scan = pyqtSignal(str, str)
    virus_found = pyqtSignal(str)
    stop_requested = pyqtSignal()

    def __init__(self, scan_path):
        super().__init__()
        self.scan_path = scan_path
        self._stop = False

    def run(self):
        files_to_scan = []
        for root, dirs, files in os.walk(self.scan_path):
            for file in files:
                files_to_scan.append(os.path.join(root, file))

        total_files = len(files_to_scan)
        if total_files == 0:
            self.finished_scan.emit("No files found to scan.", "")
            return

        # Create startupinfo to hide console
        startupinfo = None
        if os.name == 'nt':  # Windows
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = subprocess.SW_HIDE

        scanned_files = 0
        clamscan_process = subprocess.Popen(
            ['clamscan', '-r', self.scan_path],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            startupinfo=startupinfo,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == 'nt' else 0
        )

        final_summary = ""
        scanning_started = False

        for line in clamscan_process.stdout:
            if self._stop:
                clamscan_process.terminate()
                self.finished_scan.emit("Scan stopped.", "")
                return

            decoded_line = line.decode('utf-8')

            if "FOUND" in decoded_line:
                self.virus_found.emit(decoded_line.strip())

            if "----------- SCAN SUMMARY -----------" in decoded_line:
                final_summary = decoded_line.strip()
                scanning_started = True

            if scanning_started:
                final_summary += "\n" + decoded_line.strip()

            if "OK" in decoded_line:
                scanned_files += 1
                percent_done = int((scanned_files / total_files) * 100)
                self.update_progress.emit(percent_done, decoded_line.strip())

        clamscan_process.wait()
        self.finished_scan.emit(f"Scan complete: {scanned_files} of {total_files} files scanned.", final_summary)

    def stop_scan(self):
        self._stop = True
        self.stop_requested.emit()


class ClamavApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ANTIV App")
        self.setGeometry(100, 100, 1200, 700)

        # Create quarantine folder if it doesn't exist
        os.makedirs(QUARANTINE_FOLDER, exist_ok=True)

        # Load scheduled scans
        self.scheduled_scans = self.load_schedules()

        # Initialize timer for checking schedules
        self.schedule_timer = QTimer()
        self.schedule_timer.timeout.connect(self.check_schedules)
        self.schedule_timer.start(60000)  # Check every minute

        # Main widget and layout
        main_widget = QWidget()
        main_layout = QHBoxLayout()

        # Left sidebar
        sidebar = QWidget()
        sidebar.setFixedWidth(250)
        sidebar.setStyleSheet("""
            QWidget {
                background-color: #1e2124;
                color: white;
                border-radius : 10px;
            }
            QPushButton {
                text-align: left;
                padding: 10px;
                border: none;
                border-radius: 5px;
                margin: 2px;
                font-size: 14px;
                font-weight: bold;
                background-color: #2a2e33;
            }
            QPushButton:hover {
                border : 1px solid #2196F3;
                padding: 9px;
            }
            QPushButton:disabled {
                background-color: #2B2B2B;
                color: #666666;
            }
        """)

        sidebar_layout = QVBoxLayout()
        sidebar_layout.setSpacing(2)
        sidebar_layout.setContentsMargins(5, 5, 5, 5)

        # Sidebar title
        title_label = QLabel("Antiv Feature")
        title_label.setStyleSheet("font-size: 16px; font-weight: bold; padding: 10px;")
        sidebar_layout.addWidget(title_label)

        # Create sidebar buttons
        self.select_path_btn = self.create_sidebar_button("Select Path", "📁")
        #self.select_path_btn = self.create_sidebar_button_with_svg("Select Path", "utils/ic_folder.svg")
        self.select_drive_btn = self.create_sidebar_button("Select Drive", "💽")
        self.scan_btn = self.create_sidebar_button("Scan", "🔍")
        self.stop_btn = self.create_sidebar_button("Stop Scan", "⏹")
        self.schedule_btn = self.create_sidebar_button("Schedule Scan", "⏰")
        self.view_quarantine_btn = self.create_sidebar_button("View Quarantine", "🔒")
        self.report_btn = self.create_sidebar_button("Send Report", "📊")
        self.upgrade_btn = self.create_sidebar_button("Check for Updates", "⬆️")

        # Add buttons to sidebar
        for btn in [self.scan_btn, self.stop_btn,self.select_path_btn, self.select_drive_btn, self.schedule_btn, self.view_quarantine_btn,
                    self.report_btn, self.upgrade_btn]:
            sidebar_layout.addWidget(btn)

        sidebar_layout.addStretch()
        sidebar.setLayout(sidebar_layout)

        # Right content area
        content_widget = QWidget()
        content_layout = QVBoxLayout()
        content_widget.setStyleSheet("""
            QWidget {
                background-color: #1e2124;
                color: white;
                border-radius : 10px;
            }
            QTextEdit {
                background-color: #2a2e33;
                border: 1px solid #444444;
                border-radius: 5px;
                padding: 10px;
                font-family: monospace;
            }
            QProgressBar {
                border: 1px solid #444444;
                border-radius: 5px;
                text-align: center;
                background-color : #2a2e33;
            }
            QProgressBar::chunk {
                background-color: #2196F3;
            }
        """)

        # Status label
        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("font-size: 14px; padding: 10px;")
        content_layout.addWidget(self.status_label)

        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(25)
        content_layout.addWidget(self.progress_bar)

        # Report text area
        self.textbox = QTextEdit()
        self.textbox.setReadOnly(True)
        content_layout.addWidget(self.textbox)

        content_widget.setLayout(content_layout)

        # Add sidebar and content to main layout
        main_layout.addWidget(sidebar)
        main_layout.addWidget(content_widget)

        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)

        # Connect signals
        self.connect_signals()

        # Initialize variables
        self.scan_path = ""
        self.selected_drive = ""
        self.scan_thread = None

        # Disable stop button initially
        self.stop_btn.setEnabled(False)

    def create_sidebar_button(self, text, icon):
        btn = QPushButton(f"{icon} {text}")
        btn.setFixedHeight(40)
        return btn

    def create_sidebar_button_with_svg(self, text, icon_path : None):
        button = QPushButton(text)
        if icon_path:
            button.setIcon(QIcon(icon_path))

        button.setFixedHeight(40)
        return button

    def connect_signals(self):
        self.select_path_btn.clicked.connect(self.select_path)
        self.select_drive_btn.clicked.connect(self.show_drive_selection)
        self.scan_btn.clicked.connect(self.start_scan)
        self.stop_btn.clicked.connect(self.stop_scan)
        self.report_btn.clicked.connect(self.send_report)
        self.upgrade_btn.clicked.connect(self.check_upgrade)
        self.schedule_btn.clicked.connect(self.show_schedule_dialog)
        self.view_quarantine_btn.clicked.connect(self.view_quarantine)

    def show_schedule_dialog(self):
        dialog = ScheduleDialog(self)
        dialog.exec_()

    def load_schedules(self):
        if os.path.exists(SCHEDULE_FILE):
            with open(SCHEDULE_FILE, 'r') as f:
                return json.load(f)
        return []

    def save_schedules(self):
        with open(SCHEDULE_FILE, 'w') as f:
            json.dump(self.scheduled_scans, f)

    def check_schedules(self):
        current_time = QTime.currentTime()
        current_datetime = datetime.now()

        if not os.path.exists(SCHEDULE_FILE):
            return

        try:
            with open(SCHEDULE_FILE, 'r') as f:
                schedules = json.load(f)

            for schedule in schedules:
                scheduled_time = QTime.fromString(schedule['time'], "HH:mm")

                if current_time.hour() == scheduled_time.hour() and current_time.minute() == scheduled_time.minute():
                    last_run = schedule.get('last_run')
                    should_run = False

                    if not last_run:
                        should_run = True
                    else:
                        last_run_date = datetime.fromisoformat(last_run)
                        if schedule['frequency'] == 'Daily':
                            should_run = (current_datetime.date() != last_run_date.date())
                        elif schedule['frequency'] == 'Weekly':
                            should_run = (current_datetime - last_run_date).days >= 7

                    if should_run:
                        self.scan_path = schedule['path']
                        self.start_scan()
                        schedule['last_run'] = current_datetime.isoformat()

                        # Update the schedule file
                        with open(SCHEDULE_FILE, 'w') as f:
                            json.dump(schedules, f)

        except Exception as e:
            print(f"Error checking schedules: {str(e)}")

    def view_quarantine(self):
        quarantine_window = QDialog(self)
        quarantine_window.setWindowTitle("Quarantine Folder")
        quarantine_window.setStyleSheet("""
            QDialog {
                background-color: #1e2124;
                color: white;
            }
            QListWidget {
                background-color: #2a2e33;
                color: white;
                border: 1px solid #444444;
            }
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 5px;
                border-radius: 3px;
            }
        """)
        layout = QVBoxLayout()

        list_widget = QListWidget()
        for file in os.listdir(QUARANTINE_FOLDER):
            list_widget.addItem(file)

        restore_btn = QPushButton("Restore Selected")
        delete_btn = QPushButton("Delete Selected")

        restore_btn.clicked.connect(lambda: self.restore_quarantined_file(list_widget))
        delete_btn.clicked.connect(lambda: self.delete_quarantined_file(list_widget))

        layout.addWidget(list_widget)
        layout.addWidget(restore_btn)
        layout.addWidget(delete_btn)

        quarantine_window.setLayout(layout)
        quarantine_window.exec_()

    def restore_quarantined_file(self, list_widget):
        selected_items = list_widget.selectedItems()
        if not selected_items:
            return

        file_name = selected_items[0].text()
        quarantine_path = os.path.join(QUARANTINE_FOLDER, file_name)

        restore_path = QFileDialog.getExistingDirectory(self, "Select Restore Location")
        if restore_path:
            try:
                shutil.move(quarantine_path, os.path.join(restore_path, file_name))
                list_widget.takeItem(list_widget.row(selected_items[0]))
                self.textbox.append(f"Restored {file_name} to {restore_path}")
            except Exception as e:
                self.textbox.append(f"Error restoring file: {str(e)}")

    def delete_quarantined_file(self, list_widget):
        selected_items = list_widget.selectedItems()
        if not selected_items:
            return

        file_name = selected_items[0].text()
        quarantine_path = os.path.join(QUARANTINE_FOLDER, file_name)

        try:
            os.remove(quarantine_path)
            list_widget.takeItem(list_widget.row(selected_items[0]))
            self.textbox.append(f"Deleted {file_name} from quarantine")
        except Exception as e:
            self.textbox.append(f"Error deleting file: {str(e)}")

    def handle_virus_found(self, message):
        file_path = message.split(': ')[0]
        try:
            file_name = os.path.basename(file_path)
            quarantine_path = os.path.join(QUARANTINE_FOLDER, file_name)
            shutil.move(file_path, quarantine_path)
            self.textbox.append(f"Moved infected file to quarantine: {file_name}")
        except Exception as e:
            self.textbox.append(f"Error quarantining file: {str(e)}")

    def select_path(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder:
            self.scan_path = folder.replace('/', '\\') if os.name == 'nt' else folder
            self.textbox.append(f"Selected folder: {self.scan_path}")
            self.status_label.setText("Ready to scan")

    def show_drive_selection(self):
        drive_list = self.get_available_drives()

        if not drive_list:
            QMessageBox.warning(self, "No Drives Found", "No drives were found to scan.")
            return

        self.drive_selection_window = QDialog(self)
        self.drive_selection_window.setWindowTitle("Select Drive to Scan")
        self.drive_selection_window.setStyleSheet("""
            QDialog {
                background-color: #1e2124;
                color: white;
            }
            QListWidget {
                background-color: #2a2e33;
                color: white;
                border: 1px solid #444444;
            }
            QPushButton {
                background-color: #2196F3;
                color: white;
                border: none;
                padding: 5px;
                border-radius: 3px;
            }
        """)
        layout = QVBoxLayout()

        self.drive_list_widget = QListWidget()
        self.drive_list_widget.addItems(drive_list)
        layout.addWidget(self.drive_list_widget)

        select_button = QPushButton('Select Drive')
        select_button.clicked.connect(self.start_scan_on_selected_drive)
        layout.addWidget(select_button)

        self.drive_selection_window.setLayout(layout)
        self.drive_selection_window.exec_()

    def get_available_drives(self):
        drives = []
        if os.name == 'nt':  # Windows
            for drive in range(65, 91):  # ASCII values for A-Z
                drive_letter = chr(drive) + ":\\"
                if os.path.exists(drive_letter):
                    drives.append(drive_letter)
        elif os.name == 'posix':  # Linux/macOS
            for drive in ['/media', '/mnt']:
                if os.path.exists(drive):
                    for sub_dir in os.listdir(drive):
                        drive_path = os.path.join(drive, sub_dir)
                        if os.path.isdir(drive_path):
                            drives.append(drive_path)
        return drives

    def start_scan_on_selected_drive(self):
        selected_items = self.drive_list_widget.selectedItems()
        if selected_items:
            self.selected_drive = selected_items[0].text()
            self.scan_path = self.selected_drive
            self.start_scan()
            self.drive_selection_window.close()
        else:
            QMessageBox.warning(self, "No Drive Selected", "Please select a drive to scan.")

    def start_scan(self):
        if not self.scan_path:
            self.textbox.append("No folder or drive selected for scanning.")
            return

        self.scan_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        self.status_label.setText("Scanning...")

        self.scan_thread = ScanThread(self.scan_path)
        self.scan_thread.update_progress.connect(self.update_progress)
        self.scan_thread.finished_scan.connect(self.on_scan_finished)
        self.scan_thread.virus_found.connect(self.handle_virus_found)
        self.scan_thread.stop_requested.connect(self.on_stop_scan)
        self.scan_thread.start()

    def stop_scan(self):
        if self.scan_thread:
            self.scan_thread.stop_scan()
            self.status_label.setText("Stopping scan...")

    def on_stop_scan(self):
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.status_label.setText("Scan stopped")
        self.textbox.append("Scan stopped.")

    def update_progress(self, percent_done, message):
        self.progress_bar.setValue(percent_done)
        self.textbox.append(message)
        self.status_label.setText(f"Scanning... {percent_done}%")

    def on_scan_finished(self, message, summary):
        self.scan_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self.textbox.append(message)
        self.textbox.append("----------- FINAL SUMMARY -----------")
        self.textbox.append(summary)
        self.progress_bar.setValue(100)
        self.status_label.setText("Scan Complete")

    def send_report(self):
        try:
            report_data = {
                'unique_id': unique_id,
                'report': self.textbox.toPlainText()
            }
            response = requests.post('https://yourserver.com/report', json=report_data)
            if response.status_code == 200:
                self.textbox.append("Report sent successfully")
                self.status_label.setText("Report sent")
            else:
                self.textbox.append("Error sending report")
                self.status_label.setText("Error sending report")
        except Exception as e:
            self.textbox.append(f"Error sending report: {str(e)}")
            self.status_label.setText("Error sending report")

    def check_upgrade(self):
        try:
            response = requests.get('https://yourserver.com/api/upgrade')
            if response.status_code == 200:
                data = response.json()
                if data['update_available']:
                    self.textbox.append("An update is available! Please update the app.")
                    self.status_label.setText("Update available")
                else:
                    self.textbox.append("Your app is up-to-date.")
                    self.status_label.setText("No updates available")
            else:
                self.textbox.append("Error checking for updates.")
                self.status_label.setText("Update check failed")
        except Exception as e:
            self.textbox.append(f"Error checking for updates: {str(e)}")
            self.status_label.setText("Update check failed")

    # Main application code
if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle('Fusion')  # Use Fusion style for better dark theme support
    window = ClamavApp()
    window.show()
    sys.exit(app.exec_())
