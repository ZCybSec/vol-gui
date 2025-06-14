import sys
import os
import subprocess
import json
import platform
import webbrowser
import tempfile
import re
from datetime import datetime
import PySide6
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QLabel, QPushButton, QVBoxLayout, QHBoxLayout,
    QScrollArea, QTabWidget, QFileDialog, QLineEdit, QComboBox, QTableWidget,
    QTableWidgetItem, QHeaderView, QTreeWidget, QTreeWidgetItem, QSplitter, QTextEdit,
    QStatusBar, QMenu, QMessageBox, QProgressBar, QGroupBox, QFormLayout, QSizePolicy,
    QStyle, QListWidget, QListWidgetItem, QFrame, QDialog, QDialogButtonBox,
    QToolBar, QToolButton, QSystemTrayIcon, QStackedWidget, QCheckBox, QSpinBox,
    QDoubleSpinBox, QRadioButton, QButtonGroup, QPlainTextEdit, QInputDialog
)
from PySide6.QtGui import (
    QFont, QColor, QPalette, QIcon, QAction, QKeySequence, QTextCursor, QFontDatabase,
    QTextCharFormat, QSyntaxHighlighter, QTextFormat, QGuiApplication, QPixmap, QTextDocument,
    QTextOption, QDesktopServices, QStandardItemModel, QStandardItem, QImage, QPainter,
    QLinearGradient, QBrush, QMovie
)
from PySide6.QtCore import (
    Qt, QSize, QThread, Signal, QRegularExpression, QTimer, QUrl, QPoint, QRect,
    QFileInfo, QSettings, QTranslator, QLocale, QLibraryInfo, QByteArray, QBuffer,
    QProcess, QItemSelectionModel, QEvent, QObject, QTime, QDateTime, qVersion
)
from PySide6.QtPrintSupport import QPrinter, QPrintDialog


class HackerTheme:
    @staticmethod
    def apply(app):
        app.setStyle("Fusion")
        
        # Blue hacker-themed palette
        palette = QPalette()
        palette.setColor(QPalette.Window, QColor(10, 10, 20))       # Dark blue background
        palette.setColor(QPalette.WindowText, QColor(0, 200, 255))  # Bright cyan text
        palette.setColor(QPalette.Base, QColor(15, 15, 30))
        palette.setColor(QPalette.AlternateBase, QColor(20, 20, 40))
        palette.setColor(QPalette.ToolTipBase, QColor(0, 50, 100))
        palette.setColor(QPalette.ToolTipText, QColor(0, 200, 255))
        palette.setColor(QPalette.Text, QColor(0, 200, 255))
        palette.setColor(QPalette.Button, QColor(0, 30, 60))
        palette.setColor(QPalette.ButtonText, QColor(0, 200, 255))
        palette.setColor(QPalette.BrightText, QColor(100, 255, 255))
        palette.setColor(QPalette.Highlight, QColor(0, 80, 120))
        palette.setColor(QPalette.HighlightedText, QColor(255, 255, 200))
        palette.setColor(QPalette.Disabled, QPalette.Text, QColor(0, 80, 120))
        palette.setColor(QPalette.Disabled, QPalette.ButtonText, QColor(0, 80, 120))
        app.setPalette(palette)
        
        # Blue hacker stylesheet
        app.setStyleSheet(f"""
            QMainWindow {{
                background-color: {palette.window().color().name()};
                border: 2px solid #00aaff;
            }}
            
            /* Group Boxes */
            QGroupBox {{
                border: 1px solid #0088cc;
                border-radius: 8px;
                margin-top: 1.5ex;
                font-weight: bold;
                color: #00ccff;
                font-family: "Courier New", monospace;
            }}
            
            QGroupBox::title {{
                subcontrol-origin: margin;
                left: 10px;
                padding: 0 5px;
                color: #00ccff;
            }}
            
            /* Buttons */
            QPushButton {{
                background-color: #002040;
                color: #00ccff;
                border: 1px solid #0088cc;
                border-radius: 5px;
                padding: 5px 15px;
                min-width: 80px;
                font-family: "Courier New", monospace;
            }}
            
            QPushButton:hover {{
                background-color: #003060;
                border: 1px solid #00ccff;
            }}
            
            QPushButton:pressed {{
                background-color: #001020;
            }}
            
            QPushButton:disabled {{
                background-color: #001020;
                color: #004060;
            }}
            
            /* List Widgets */
            QListWidget {{
                background-color: #001830;
                border: 1px solid #0088cc;
                border-radius: 5px;
                padding: 5px;
                font-family: "Courier New", monospace;
            }}
            
            QListWidget::item {{
                padding: 5px;
                border-radius: 3px;
            }}
            
            QListWidget::item:selected {{
                background-color: #002850;
                border: 1px solid #00ccff;
            }}
            
            QListWidget::item:hover {{
                background-color: #002040;
            }}
            
            /* Text Edit */
            QTextEdit {{
                background-color: #001830;
                color: #00ccff;
                border: 1px solid #0088cc;
                border-radius: 5px;
                font-family: "Consolas", "Courier New", monospace;
                font-size: 11px;
            }}
            
            /* Line Edits */
            QLineEdit {{
                background-color: #001020;
                color: #00ccff;
                border: 1px solid #0088cc;
                border-radius: 5px;
                padding: 5px;
                font-family: "Courier New", monospace;
            }}
            
            /* Combo Boxes */
            QComboBox {{
                background-color: #001020;
                color: #00ccff;
                border: 1px solid #0088cc;
                border-radius: 5px;
                padding: 5px;
                font-family: "Courier New", monospace;
            }}
            
            QComboBox::drop-down {{
                border: 0px;
            }}
            
            QComboBox QAbstractItemView {{
                background-color: #001020;
                color: #00ccff;
                border: 1px solid #0088cc;
                selection-background-color: #002850;
            }}
            
            /* Progress Bar */
            QProgressBar {{
                border: 1px solid #0088cc;
                border-radius: 5px;
                text-align: center;
                background: #001020;
                color: #00ccff;
                height: 20px;
                text-align: center;
            }}
            
            QProgressBar::chunk {{
                background-color: qlineargradient(
                    x1:0, y1:0, x2:1, y2:0,
                    stop:0 #00aaff, stop:1 #00ffcc
                );
                border-radius: 3px;
                width: 10px;
            }}
            
            /* Scroll Bars */
            QScrollBar:vertical {{
                border: none;
                background: #001020;
                width: 12px;
                margin: 0px;
            }}
            
            QScrollBar::handle:vertical {{
                background: #0088cc;
                min-height: 20px;
                border-radius: 5px;
            }}
            
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{
                height: 0px;
            }}
            
            /* Tab Widget */
            QTabWidget::pane {{
                border: 1px solid #0088cc;
                border-radius: 5px;
                margin-top: -1px;
            }}
            
            QTabBar::tab {{
                background: #002040;
                color: #0088cc;
                padding: 8px 15px;
                border-top-left-radius: 5px;
                border-top-right-radius: 5px;
                border: 1px solid #0088cc;
                margin-right: 2px;
                font-family: "Courier New", monospace;
            }}
            
            QTabBar::tab:selected {{
                background: #003060;
                color: #00ccff;
                border-bottom: 2px solid #0088cc;
            }}
            
            /* Splitter */
            QSplitter::handle {{
                background: #002040;
                width: 5px;
                height: 5px;
            }}
            
            /* Status Bar */
            QStatusBar {{
                background: #001020;
                color: #0088cc;
                border-top: 1px solid #0088cc;
                font-family: "Courier New", monospace;
            }}
            
            /* Toolbar */
            QToolBar {{
                background: #001020;
                border-bottom: 1px solid #0088cc;
                spacing: 5px;
                padding: 3px;
            }}
            
            QToolButton {{
                padding: 5px;
            }}
            
            /* Plugin Dialog */
            QDialog {{
                background-color: #001020;
                border: 2px solid #00aaff;
            }}
            
            QLabel#plugin-desc {{
                color: #00ccff;
                padding: 10px;
                border-radius: 5px;
                background-color: #001830;
                border: 1px solid #0088cc;
            }}
            
            QTextEdit#plugin-command {{
                background-color: #001830;
                color: #00ffcc;
                font-family: "Consolas", monospace;
                font-size: 12px;
                border: 1px solid #00aaff;
                border-radius: 5px;
                padding: 5px;
            }}
            
            /* Custom widgets */
            QTableWidget {{
                background-color: #001020;
                color: #00ccff;
                border: 1px solid #0088cc;
                font-family: "Courier New", monospace;
                gridline-color: #004080;
            }}
            
            QTableWidget QHeaderView::section {{
                background-color: #002040;
                color: #00ccff;
                border: 1px solid #0088cc;
                padding: 5px;
            }}
            
            QTreeWidget {{
                background-color: #001020;
                color: #00ccff;
                border: 1px solid #0088cc;
                font-family: "Courier New", monospace;
            }}
            
            QTreeWidget::item {{
                padding: 5px;
            }}
            
            QTreeWidget::item:selected {{
                background-color: #002850;
                border: 1px solid #00ccff;
            }}
            
            /* Search box */
            QLineEdit#searchBox {{
                background-color: #001020;
                color: #00ccff;
                border: 1px solid #0088cc;
                border-radius: 15px;
                padding: 5px 15px;
                font-family: "Courier New", monospace;
            }}
            
            /* Analysis result boxes */
            QFrame#resultBox {{
                background-color: #001830;
                border: 1px solid #0088cc;
                border-radius: 5px;
                padding: 10px;
            }}
            
            QLabel#resultTitle {{
                font-weight: bold;
                color: #00ffcc;
                font-size: 14px;
            }}
            
            QLabel#resultValue {{
                color: #00ccff;
                font-size: 12px;
            }}
        """)


class CommandRunner(QThread):
    output_ready = Signal(str)
    finished = Signal(int, str)  # exit_code, tab_name
    error_occurred = Signal(str)
    progress_updated = Signal(int, str)  # percentage, message
    command_started = Signal(str)  # command string

    def __init__(self, command, tab_name):
        super().__init__()
        self.command = command
        self.tab_name = tab_name
        self.process = None
        self.is_running = False
        self.output_buffer = []
        self.buffer_size = 100  # Number of lines to buffer before emitting

    def run(self):
        self.is_running = True
        try:
            self.command_started.emit(self.command)
            
            # Create temporary file for output
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp_file:
                temp_path = temp_file.name
            
            # Build full command with output redirection
            full_command = f"{self.command} 2>&1 | tee {temp_path}"
            
            # Start the process
            self.process = subprocess.Popen(
                full_command,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=True,
                text=True,
                encoding='utf-8',
                errors='replace',
                bufsize=1,
                universal_newlines=True,
                env=os.environ
            )

            # Read output in real-time
            while self.is_running:
                output = self.process.stdout.readline()
                if output == '' and self.process.poll() is not None:
                    break
                
                if output:
                    self.process_output(output)
                
                # Small delay to prevent high CPU usage
                QThread.msleep(10)

            # Read any remaining output
            remaining_output = self.process.stdout.read()
            if remaining_output:
                self.process_output(remaining_output)
            
            # Flush any buffered output
            if self.output_buffer:
                self.output_ready.emit('\n'.join(self.output_buffer))
                self.output_buffer.clear()

            exit_code = self.process.poll()
            
            # Read the full output from temp file
            with open(temp_path, 'r', encoding='utf-8', errors='replace') as f:
                full_output = f.read()
            
            # Clean up
            try:
                os.unlink(temp_path)
            except:
                pass
            
            self.finished.emit(exit_code, self.tab_name)
            
        except Exception as e:
            error_msg = f"CommandRunner error: {str(e)}"
            self.error_occurred.emit(error_msg)
            self.finished.emit(-1, self.tab_name)
        finally:
            self.is_running = False

    def process_output(self, output):
        """Process and buffer output lines"""
        lines = output.split('\n')
        for line in lines:
            if not line.strip():
                continue
                
            self.output_buffer.append(line)
            
            # Check for progress indicators
            self.check_progress(line)
            
            # Emit if buffer is full
            if len(self.output_buffer) >= self.buffer_size:
                self.output_ready.emit('\n'.join(self.output_buffer))
                self.output_buffer.clear()

    def check_progress(self, line):
        """Check for progress indicators in output"""
        # Simple percentage detection
        percent_match = re.search(r'(\d{1,3})%', line)
        if percent_match:
            percent = int(percent_match.group(1))
            self.progress_updated.emit(percent, line)
        
        # Common progress patterns
        progress_patterns = [
            r'progress:\s*(\d+)/(\d+)',
            r'processed\s*(\d+)\s*of\s*(\d+)',
            r'step\s*(\d+)\s*of\s*(\d+)'
        ]
        
        for pattern in progress_patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                current = int(match.group(1))
                total = int(match.group(2))
                if total > 0:
                    percent = int((current / total) * 100)
                    self.progress_updated.emit(percent, line)
                break

    def stop(self):
        """Stop the command execution"""
        self.is_running = False
        if self.process and self.process.poll() is None:
            try:
                # Try to terminate gracefully
                self.process.terminate()
                try:
                    self.process.wait(2000)  # Wait 2 seconds
                except subprocess.TimeoutExpired:
                    # Force kill if not responding
                    self.process.kill()
            except:
                pass


class PluginExecutionDialog(QDialog):
    def __init__(self, parent, plugin_name, description, base_command):
        super().__init__(parent)
        self.setWindowTitle(f"Execute Plugin: {plugin_name}")
        self.setMinimumSize(800, 500)
        
        layout = QVBoxLayout()
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(15)
        
        # Plugin info
        info_label = QLabel(f"<b>{plugin_name}</b><br>{description}")
        info_label.setObjectName("plugin-desc")
        info_label.setWordWrap(True)
        layout.addWidget(info_label)
        
        # Command editor
        layout.addWidget(QLabel("<b>Command to execute:</b>"))
        
        self.command_edit = QTextEdit()
        self.command_edit.setObjectName("plugin-command")
        self.command_edit.setPlainText(base_command)
        self.command_edit.setLineWrapMode(QTextEdit.NoWrap)
        layout.addWidget(self.command_edit)
        
        # Advanced options
        adv_group = QGroupBox("Advanced Options")
        adv_layout = QFormLayout()
        
        self.timeout_spin = QSpinBox()
        self.timeout_spin.setRange(10, 3600)
        self.timeout_spin.setValue(300)
        self.timeout_spin.setSuffix(" seconds")
        
        self.priority_combo = QComboBox()
        self.priority_combo.addItems(["Normal", "Below Normal", "Low"])
        
        self.output_check = QCheckBox("Save output to file automatically")
        self.output_check.setChecked(True)
        
        adv_layout.addRow("Timeout:", self.timeout_spin)
        adv_layout.addRow("Process Priority:", self.priority_combo)
        adv_layout.addRow(self.output_check)
        
        adv_group.setLayout(adv_layout)
        layout.addWidget(adv_group)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.button(QDialogButtonBox.Ok).setText("Execute")
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        
        layout.addWidget(button_box)
        self.setLayout(layout)
    
    def get_command(self):
        return self.command_edit.toPlainText().strip()
    
    def get_timeout(self):
        return self.timeout_spin.value()
    
    def get_priority(self):
        return self.priority_combo.currentText()
    
    def save_output(self):
        return self.output_check.isChecked()


class AnalysisResultDialog(QDialog):
    def __init__(self, parent, title, content):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumSize(600, 400)
        
        layout = QVBoxLayout()
        
        # Content display
        self.content_area = QTextEdit()
        self.content_area.setReadOnly(True)
        self.content_area.setFont(QFont("Consolas", 10))
        self.content_area.setPlainText(content)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Save | QDialogButtonBox.Print)
        button_box.accepted.connect(self.accept)
        button_box.button(QDialogButtonBox.Save).clicked.connect(self.save_content)
        button_box.button(QDialogButtonBox.Print).clicked.connect(self.print_content)
        
        layout.addWidget(self.content_area)
        layout.addWidget(button_box)
        self.setLayout(layout)
    
    def save_content(self):
        file_path, _ = QFileDialog.getSaveFileName(
            self, 
            "Save Analysis Results", 
            "", 
            "Text Files (*.txt);;All Files (*)"
        )
        
        if file_path:
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write(self.content_area.toPlainText())
                QMessageBox.information(self, "Success", "Results saved successfully.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save file: {str(e)}")
    
    def print_content(self):
        printer = QPrinter()
        dialog = QPrintDialog(printer, self)
        if dialog.exec() == QDialog.Accepted:
            self.content_area.print_(printer)


class SearchDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("Advanced Search")
        self.setMinimumSize(500, 300)
        
        layout = QVBoxLayout()
        
        # Search options
        options_group = QGroupBox("Search Options")
        options_layout = QFormLayout()
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Enter search term...")
        
        self.case_check = QCheckBox("Case sensitive")
        self.regex_check = QCheckBox("Regular expression")
        self.whole_word_check = QCheckBox("Whole words only")
        
        self.direction_group = QButtonGroup()
        self.forward_radio = QRadioButton("Forward")
        self.backward_radio = QRadioButton("Backward")
        self.direction_group.addButton(self.forward_radio)
        self.direction_group.addButton(self.backward_radio)
        self.forward_radio.setChecked(True)
        
        direction_layout = QHBoxLayout()
        direction_layout.addWidget(self.forward_radio)
        direction_layout.addWidget(self.backward_radio)
        
        options_layout.addRow("Search for:", self.search_input)
        options_layout.addRow(self.case_check)
        options_layout.addRow(self.regex_check)
        options_layout.addRow(self.whole_word_check)
        options_layout.addRow("Direction:", direction_layout)
        
        options_group.setLayout(options_layout)
        layout.addWidget(options_group)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        
        layout.addWidget(button_box)
        self.setLayout(layout)
    
    def get_search_params(self):
        return {
            "text": self.search_input.text(),
            "case_sensitive": self.case_check.isChecked(),
            "regex": self.regex_check.isChecked(),
            "whole_word": self.whole_word_check.isChecked(),
            "forward": self.forward_radio.isChecked()
        }


class AboutDialog(QDialog):
    def __init__(self, parent):
        super().__init__(parent)
        self.setWindowTitle("About Volatility3 Professional")
        self.setMinimumSize(600, 400)
        
        layout = QVBoxLayout()
        
        # Header with logo and title
        header = QWidget()
        header_layout = QHBoxLayout()
        
        # Create logo pixmap
        logo_pixmap = QPixmap(64, 64)
        logo_pixmap.fill(Qt.transparent)
        painter = QPainter(logo_pixmap)
        painter.setRenderHint(QPainter.Antialiasing)
        
        gradient = QLinearGradient(0, 0, 64, 64)
        gradient.setColorAt(0, QColor(0, 180, 255))
        gradient.setColorAt(1, QColor(0, 80, 120))
        
        painter.setBrush(QBrush(gradient))
        painter.drawEllipse(2, 2, 60, 60)
        painter.setPen(QColor(255, 255, 255))
        painter.setFont(QFont("Arial", 24, QFont.Bold))
        painter.drawText(QRect(0, 0, 64, 64), Qt.AlignCenter, "V3")
        painter.end()
        
        logo_label = QLabel()
        logo_label.setPixmap(logo_pixmap)
        header_layout.addWidget(logo_label)
        
        title_label = QLabel("<h1>Volatility3 Professional</h1>")
        title_label.setStyleSheet("color: #00ccff;")
        header_layout.addWidget(title_label, 1)
        
        header.setLayout(header_layout)
        layout.addWidget(header)
        
        # Main content
        content = QTextEdit()
        content.setReadOnly(True)
        content.setFrameStyle(QFrame.NoFrame)
        content.setStyleSheet("background-color: transparent; color: #00ccff;")
        
        about_text = f"""
        <p><b>Version:</b> 3.0 Professional Edition</p>
        <p><b>Platform:</b> {platform.system()} {platform.release()}</p>
        <p><b>Python:</b> {platform.python_version()}</p>
        <p><b>Qt:</b> {qVersion()}</p>
        <p><b>PySide6:</b> {PySide6.__version__}</p>

        
        <p>Professional memory forensics tool with advanced analysis capabilities.</p>
        
        <p>© {datetime.now().year} Forensic Tools. All rights reserved.</p>
        
        <h3 style="color:#00ffcc">Features:</h3>
        <ul>
            <li>Advanced memory analysis for Windows, Linux, and Mac</li>
            <li>Malware detection and analysis tools</li>
            <li>Digital investigation toolkit</li>
            <li>Professional-grade memory analysis</li>
            <li>Cross-platform support</li>
            <li>Plugin management system</li>
            <li>Advanced reporting capabilities</li>
            <li>Real-time progress monitoring</li>
            <li>Customizable interface</li>
        </ul>
        
        <h3 style="color:#00ffcc">Credits:</h3>
        <p>Based on Volatility Framework by Volatility Foundation</p>
        <p>Developed by Forensic Tools Team</p>
        
        <p style="color:#00ccff; font-size: 14px; margin-top: 20px;">
            Advanced Memory Analysis Solution
        </p>
        """
        
        content.setHtml(about_text)
        layout.addWidget(content)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok)
        button_box.accepted.connect(self.accept)
        layout.addWidget(button_box)
        
        self.setLayout(layout)


class VolatilityGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Volatility3 Professional")
        self.setGeometry(100, 100, 1280, 800)
        
        # Application settings
        self.settings = QSettings("Z3X", "Volatility3Professional")
        
        # Center the window on screen
        self.center_window()
        
        # Initialize variables
        self.memory_file = ""
        self.plugins = {
            "Windows": [
                ("Process List", "windows.pslist", "عرض العمليات الجارية"),
                ("Process Tree", "windows.pstree", "عرض شجرة العمليات"),
                ("DLL List", "windows.dlllist", "عرض ملفات DLL المحملة لكل عملية"),
                ("Registry UserAssist", "windows.registry.userassist", "عرض مفاتيح UserAssist في الريجستري"),
                ("Network Connections", "windows.netscan", "عرض الاتصالات الشبكية النشطة"),
                ("Sockets", "windows.sockets", "عرض المنافذ المفتوحة (Sockets)"),
                ("Handles", "windows.handles", "عرض المقابض المفتوحة (Handles)"),
                ("Filescan", "windows.filescan", "البحث عن كائنات الملفات في الذاكرة"),
                ("Malfind", "windows.malfind", "الكشف عن الكود المخفي أو المحقون في الذاكرة"),
                ("Cmdline", "windows.cmdline", "عرض أوامر تشغيل العمليات"),
                ("Envars", "windows.envars", "عرض متغيرات البيئة للعمليات"),
                ("Svcscan", "windows.svcscan", "البحث عن خدمات ويندوز"),
                ("Modscan", "windows.modscan", "البحث عن الموديولات المحملة في النظام"),
                ("Driverscan", "windows.driverscan", "البحث عن كائنات الدرايفر"),
                ("Hivelist", "windows.registry.hivelist", "عرض ملفات الريجستري المفتوحة (Hives)"),
                ("Timeliner", "timeliner", "إنشاء خط زمني من آثار النظام المختلفة"),
                ("Shimcache", "windows.registry.shimcache", "عرض بيانات Shimcache من الريجستري"),
                ("Dump Files", "windows.dumpfiles", "استخراج الملفات من الذاكرة"),
                ("Yara Scan", "windows.yarascan", "فحص الذاكرة باستخدام قواعد YARA"),
                ("Clipboard", "windows.clipboard", "استخراج محتويات الحافظة"),
                ("Hashdump", "windows.hashdump", "تفريغ كلمات مرور النظام (Hashes)"),
                ("Lsadump", "windows.lsadump", "تفريغ أسرار LSA مثل كلمات المرور المخزنة"),
                ("Memory Strings", "strings", "استخراج السلاسل النصية من الذاكرة"),
                ("Process Memory Dump", "memdump", "تفريغ محتوى ذاكرة عملية معينة"),
                ("Kernel Modules", "modules", "عرض وحدات النواة المحملة"),
            ],
            "Linux": [
                ("Process List", "linux.pslist", "عرض العمليات الجارية"),
                ("Bash History", "linux.bash", "استرجاع تاريخ أوامر Bash"),
                ("Lsof", "linux.lsof", "عرض الملفات المفتوحة حالياً"),
                ("Netstat", "linux.netstat", "عرض الاتصالات الشبكية النشطة"),
                ("Tty Check", "linux.tty_check", "فحص أجهزة TTY"),
                ("Mountinfo", "linux.mountinfo", "عرض أنظمة الملفات المثبتة"),
                ("Kernel Modules", "linux.modules", "عرض موديولات الكيرنل المحملة"),
                ("ARP Cache", "linux.arp", "عرض ذاكرة ARP Cache"),
                ("Check AFInfo", "linux.check_afinfo", "فحص هياكل البروتوكولات الشبكية"),
                ("Check IDT", "linux.check_idt", "فحص جدول مقاطعات الكيرنل"),
                ("Check Syscall", "linux.check_syscall", "فحص جداول استدعاءات النظام"),
                ("Libraries", "linux.proc.Maps", "عرض خرائط الذاكرة للعمليات"),
                ("Check TTY", "linux.check_tty", "التحقق من أجهزة TTY للأنشطة المشبوهة"),
                ("Memory Strings", "strings", "استخراج السلاسل النصية من الذاكرة"),
                ("Kernel Memory Dump", "linux.memmap", "تفريغ ذاكرة النواة"),
            ],
            "Mac": [
                ("Process List", "mac.pslist", "عرض العمليات الجارية"),
                ("Lsof", "mac.lsof", "عرض الملفات المفتوحة"),
                ("Netstat", "mac.netstat", "عرض الاتصالات الشبكية النشطة"),
                ("Malfind", "mac.malfind", "الكشف عن الكود المخفي أو المحقون"),
                ("Bash", "mac.bash", "استرجاع تاريخ أوامر Bash"),
                ("LSMOD", "mac.lsmod", "عرض موديولات الكيرنل المحملة"),
                ("Tmp Files", "mac.tmpfiles", "عرض الملفات المؤقتة"),
                ("Sockets", "mac.network.connections", "عرض المنافذ المفتوحة"),
                ("Dmesg", "mac.dmesg", "عرض رسائل الكيرنل"),
                ("Check Syscalls", "mac.check_syscalls", "فحص جدول استدعاءات النظام"),
                ("Zombie Processes", "mac.zombies", "عرض العمليات المتوقفة (Zombie)"),
                ("Keychain", "mac.keychain", "استخراج معلومات Keychain المخزنة"),
                ("Memory Strings", "strings", "استخراج السلاسل النصية من الذاكرة"),
                ("Kernel Extensions", "mac.kexts", "عرض امتدادات النواة"),
            ]
        }
        
        self.current_runner = None
        self.output_tabs = {}
        self.current_tab_name = ""
        self.recent_files = []
        self.max_recent_files = 10
        
        # Load recent files
        self.load_recent_files()
        
        self.init_ui()
        self.create_menu()
        self.create_toolbar()
        self.create_statusbar()
        
        # Load window state
        self.load_settings()
        
        # Create default output tab
        self.create_output_tab("Welcome", self.get_welcome_message())
    
    def center_window(self):
        screen_geometry = QGuiApplication.primaryScreen().availableGeometry()
        self.move(
            (screen_geometry.width() - self.width()) // 2,
            (screen_geometry.height() - self.height()) // 2
        )
    
    def load_recent_files(self):
        size = self.settings.beginReadArray("recentFiles")
        for i in range(size):
            self.settings.setArrayIndex(i)
            file_path = self.settings.value("path")
            if file_path and os.path.exists(file_path):
                self.recent_files.append(file_path)
        self.settings.endArray()
    
    def save_recent_files(self):
        self.settings.beginWriteArray("recentFiles")
        for i, file_path in enumerate(self.recent_files[:self.max_recent_files]):
            self.settings.setArrayIndex(i)
            self.settings.setValue("path", file_path)
        self.settings.endArray()
    
    def add_recent_file(self, file_path):
        if file_path in self.recent_files:
            self.recent_files.remove(file_path)
        self.recent_files.insert(0, file_path)
        if len(self.recent_files) > self.max_recent_files:
            self.recent_files = self.recent_files[:self.max_recent_files]
        self.save_recent_files()
        self.update_recent_files_menu()
    
    def update_recent_files_menu(self):
        # Clear existing recent files
        for action in self.recent_file_actions:
            self.file_menu.removeAction(action)
        self.recent_file_actions.clear()
        
        # Add current recent files
        for i, file_path in enumerate(self.recent_files):
            action = QAction(f"&{i+1} {os.path.basename(file_path)}", self)
            action.setData(file_path)
            action.triggered.connect(lambda checked, path=file_path: self.open_recent_file(path))
            self.recent_file_actions.append(action)
            self.file_menu.insertAction(self.open_action, action)
        
        # Add separator if there are recent files
        if self.recent_files:
            self.file_menu.insertSeparator(self.open_action)
    
    def open_recent_file(self, file_path):
        if os.path.exists(file_path):
            self.memory_file = file_path
            self.file_path.setText(file_path)
            self.status_bar.showMessage(f"Loaded: {os.path.basename(file_path)}", 3000)
            self.update_system_info()
            self.add_recent_file(file_path)
        else:
            QMessageBox.warning(self, "File Not Found", "The selected file no longer exists.")
            self.recent_files.remove(file_path)
            self.save_recent_files()
            self.update_recent_files_menu()
    
    def load_settings(self):
        # Window geometry
        if self.settings.value("windowGeometry"):
            self.restoreGeometry(self.settings.value("windowGeometry"))
        
        # Window state
        if self.settings.value("windowState"):
            self.restoreState(self.settings.value("windowState"))
        
        # Recent files are loaded in __init__
    
    def save_settings(self):
        # Window geometry
        self.settings.setValue("windowGeometry", self.saveGeometry())
        
        # Window state
        self.settings.setValue("windowState", self.saveState())
        
        # Recent files are saved when added
    
    def closeEvent(self, event):
        # Stop any running command
        if self.current_runner:
            self.current_runner.stop()
            self.current_runner.wait(1000)
        
        # Save settings
        self.save_settings()
        
        # Close normally
        event.accept()
    
    def get_welcome_message(self):
        return f"""

 __     __           __   ______         _______                     
/  |   /  |         /  | /      \       /       \                    
$$ |   $$ | ______  $$ |/$$$$$$  |      $$$$$$$  | ______    ______  
$$ |   $$ |/      \ $$ |$$ ___$$ |      $$ |__$$ |/      \  /      \ 
$$  \ /$$//$$$$$$  |$$ |  /   $$<       $$    $$//$$$$$$  |/$$$$$$  |
 $$  /$$/ $$ |  $$ |$$ | _$$$$$  |      $$$$$$$/ $$ |  $$/ $$ |  $$ |
  $$ $$/  $$ \__$$ |$$ |/  \__$$ |      $$ |     $$ |      $$ \__$$ |
   $$$/   $$    $$/ $$ |$$    $$/______ $$ |     $$ |      $$    $$/ 
    $/     $$$$$$/  $$/  $$$$$$//      |$$/      $$/        $$$$$$/  
                                $$$$$$/                              


            Welcome to Volatility3 Professional
                            
    Features:
      • Advanced memory forensics
      • Malware detection and analysis
      • Digital investigation toolkit
      • Professional-grade memory analysis
      • Cross-platform support (Windows/Linux/Mac)
      • Plugin management system
      • Advanced reporting capabilities
                            
    Instructions:
     1. Select a memory dump file
     2. Choose the appropriate OS
     3. Select a plugin to analyze the memyro  
     4. View and analyze results
                
    Keyboard Shortcuts:
     • Ctrl+O: Open memory file
     • Ctrl+R: Run selected plugin
     • Ctrl+S: Stop current execution
     • Ctrl+F: Search in current tab
     • Ctrl+Shift+S: Save results
                            
    Forensic Tools
    Version 3.0 Professional Edition
                            """
    
    def init_ui(self):
        # Main widget and layout
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        
        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(5, 5, 5, 5)
        main_layout.setSpacing(5)
        main_widget.setLayout(main_layout)
        
        # Main content area
        content_widget = QWidget()
        content_layout = QHBoxLayout()
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(5)
        content_widget.setLayout(content_layout)
        main_layout.addWidget(content_widget)
        
        # Create left panel (plugins and systems)
        left_panel = QWidget()
        left_panel.setMinimumWidth(250)
        left_panel.setMaximumWidth(350)
        left_layout = QVBoxLayout()
        left_layout.setContentsMargins(0, 0, 0, 0)
        left_layout.setSpacing(5)
        left_panel.setLayout(left_layout)
        
        # Create right panel (results)
        right_panel = QWidget()
        right_layout = QVBoxLayout()
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(5)
        right_panel.setLayout(right_layout)
        
        # Add splitters for resizable panels
        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(left_panel)
        splitter.addWidget(right_panel)
        splitter.setSizes([250, 700])
        content_layout.addWidget(splitter)
        
        # ===== LEFT PANEL CONTENT =====
        
        # File selection group
        file_group = QGroupBox("Memory Image")
        file_layout = QVBoxLayout()
        file_layout.setSpacing(5)
        
        self.file_path = QLineEdit()
        self.file_path.setPlaceholderText("No file selected...")
        self.file_path.setReadOnly(True)
        
        btn_layout = QHBoxLayout()
        browse_btn = QPushButton("Browse...")
        browse_btn.setIcon(self.style().standardIcon(QStyle.SP_DirIcon))
        browse_btn.clicked.connect(self.browse_file)
        btn_layout.addWidget(browse_btn)
        
        clear_btn = QPushButton("Clear")
        clear_btn.setIcon(self.style().standardIcon(QStyle.SP_DialogResetButton))
        clear_btn.clicked.connect(self.clear_file)
        btn_layout.addWidget(clear_btn)
        
        file_layout.addWidget(self.file_path)
        file_layout.addLayout(btn_layout)
        file_group.setLayout(file_layout)
        left_layout.addWidget(file_group)
        
        # Plugin selection group
        plugin_group = QGroupBox("Plugins")
        plugin_layout = QVBoxLayout()
        plugin_layout.setSpacing(5)
        
        # Horizontal layout for OS selection and search
        top_row_layout = QHBoxLayout()
        
        self.plugin_os_combo = QComboBox()
        self.plugin_os_combo.addItems(["Windows", "Linux", "Mac"])
        self.plugin_os_combo.currentTextChanged.connect(self.populate_plugins)
        top_row_layout.addWidget(self.plugin_os_combo)
        
        self.plugin_search = QLineEdit()
        self.plugin_search.setPlaceholderText("Search plugins...")
        self.plugin_search.setObjectName("searchBox")
        self.plugin_search.textChanged.connect(self.filter_plugins)
        top_row_layout.addWidget(self.plugin_search)
        
        plugin_layout.addLayout(top_row_layout)
        
        self.plugin_list = QListWidget()
        self.plugin_list.setSelectionMode(QListWidget.SingleSelection)
        plugin_layout.addWidget(self.plugin_list)
        
        # Populate plugins for the default OS (Windows)
        self.populate_plugins("Windows")
        
        plugin_group.setLayout(plugin_layout)
        left_layout.addWidget(plugin_group)
        
        # System info group
        system_group = QGroupBox("System Information")
        system_layout = QVBoxLayout()
        system_layout.setSpacing(5)
        
        self.system_info = QTextEdit()
        self.system_info.setReadOnly(True)
        self.system_info.setFont(QFont("Courier New", 9))
        self.system_info.setPlaceholderText("System information will appear here...")
        
        system_layout.addWidget(self.system_info)
        system_group.setLayout(system_layout)
        left_layout.addWidget(system_group)
        
        # ===== RIGHT PANEL CONTENT =====
        
        # Results tabs
        self.result_tabs = QTabWidget()
        self.result_tabs.setTabsClosable(True)
        self.result_tabs.tabCloseRequested.connect(self.close_tab)
        
        right_layout.addWidget(self.result_tabs)
    
    def filter_plugins(self):
        """Filter plugins based on search text"""
        search_text = self.plugin_search.text().lower()
        os_name = self.plugin_os_combo.currentText()
        
        if not search_text:
            self.populate_plugins(os_name)
            return
            
        if os_name in self.plugins:
            self.plugin_list.clear()
            for name, command, description in self.plugins[os_name]:
                if search_text in name.lower() or search_text in description.lower():
                    item = QListWidgetItem(f"⚡ {name}")
                    item.setToolTip(f"<b>{name}</b><br><br>{description}<br><br><b>Command:</b> {command}")
                    self.plugin_list.addItem(item)
    
    def populate_plugins(self, os_name):
        """Populate plugins list for the selected OS"""
        self.plugin_list.clear()
        
        if os_name in self.plugins:
            for name, command, description in self.plugins[os_name]:
                item = QListWidgetItem(f"⚡ {name}")
                item.setToolTip(f"<b>{name}</b><br><br>{description}<br><br><b>Command:</b> {command}")
                self.plugin_list.addItem(item)
    
    def create_menu(self):
        menu_bar = self.menuBar()
        
        # File menu
        self.file_menu = menu_bar.addMenu("&File")
        
        self.open_action = QAction("&Open Memory File", self)
        self.open_action.setShortcut(QKeySequence.Open)
        self.open_action.triggered.connect(self.browse_file)
        self.file_menu.addAction(self.open_action)
        
        # Recent files submenu
        self.recent_file_actions = []
        self.update_recent_files_menu()
        
        save_action = QAction("&Save Results", self)
        save_action.setShortcut(QKeySequence.Save)
        save_action.triggered.connect(self.save_results)
        self.file_menu.addAction(save_action)
        
        export_action = QAction("&Export Results...", self)
        export_action.setShortcut(QKeySequence("Ctrl+E"))
        export_action.triggered.connect(self.export_results)
        self.file_menu.addAction(export_action)
        
        print_action = QAction("&Print...", self)
        print_action.setShortcut(QKeySequence.Print)
        print_action.triggered.connect(self.print_results)
        self.file_menu.addAction(print_action)
        
        self.file_menu.addSeparator()
        
        exit_action = QAction("E&xit", self)
        exit_action.setShortcut(QKeySequence.Quit)
        exit_action.triggered.connect(self.close)
        self.file_menu.addAction(exit_action)
        
        # Edit menu
        edit_menu = menu_bar.addMenu("&Edit")
        
        clear_action = QAction("&Clear Results", self)
        clear_action.setShortcut(QKeySequence("Ctrl+Shift+C"))
        clear_action.triggered.connect(self.clear_results)
        edit_menu.addAction(clear_action)
        
        search_action = QAction("&Search...", self)
        search_action.setShortcut(QKeySequence.Find)
        search_action.triggered.connect(self.show_search_dialog)
        edit_menu.addAction(search_action)
        
        # View menu
        view_menu = menu_bar.addMenu("&View")
        
        zoom_in_action = QAction("Zoom &In", self)
        zoom_in_action.setShortcut(QKeySequence.ZoomIn)
        zoom_in_action.triggered.connect(self.zoom_in)
        view_menu.addAction(zoom_in_action)
        
        zoom_out_action = QAction("Zoom &Out", self)
        zoom_out_action.setShortcut(QKeySequence.ZoomOut)
        zoom_out_action.triggered.connect(self.zoom_out)
        view_menu.addAction(zoom_out_action)
        
        reset_zoom_action = QAction("&Reset Zoom", self)
        reset_zoom_action.setShortcut(QKeySequence("Ctrl+0"))
        reset_zoom_action.triggered.connect(self.reset_zoom)
        view_menu.addAction(reset_zoom_action)
        
        # Tools menu
        tools_menu = menu_bar.addMenu("&Tools")
        
        analyze_action = QAction("&Advanced Analysis", self)
        analyze_action.setShortcut(QKeySequence("Ctrl+A"))
        analyze_action.triggered.connect(self.run_advanced_analysis)
        tools_menu.addAction(analyze_action)
        
        compare_action = QAction("&Compare Results", self)
        compare_action.setShortcut(QKeySequence("Ctrl+D"))
        compare_action.triggered.connect(self.compare_results)
        tools_menu.addAction(compare_action)
        
        # Help menu
        help_menu = menu_bar.addMenu("&Help")
        
        docs_action = QAction("&Documentation", self)
        docs_action.triggered.connect(self.show_docs)
        help_menu.addAction(docs_action)
        
        tutorial_action = QAction("&Tutorials", self)
        tutorial_action.triggered.connect(self.show_tutorials)
        help_menu.addAction(tutorial_action)
        
        help_menu.addSeparator()
        
        about_action = QAction("&About", self)
        about_action.triggered.connect(self.show_about)
        help_menu.addAction(about_action)
        
        about_qt_action = QAction("About &Qt", self)
        about_qt_action.triggered.connect(QApplication.aboutQt)
        help_menu.addAction(about_qt_action)
    
    def create_toolbar(self):
        toolbar = self.addToolBar("Main Toolbar")
        toolbar.setIconSize(QSize(24, 24))
        toolbar.setMovable(False)
        
        # Toolbar actions
        open_action = QAction(self.style().standardIcon(QStyle.SP_DirOpenIcon), "Open Memory File", self)
        open_action.triggered.connect(self.browse_file)
        toolbar.addAction(open_action)
        
        toolbar.addSeparator()
        
        run_action = QAction(self.style().standardIcon(QStyle.SP_MediaPlay), "Run Plugin", self)
        run_action.setShortcut(QKeySequence("Ctrl+R"))
        run_action.triggered.connect(self.run_selected_plugin)
        toolbar.addAction(run_action)
        
        stop_action = QAction(self.style().standardIcon(QStyle.SP_MediaStop), "Stop Execution", self)
        stop_action.setShortcut(QKeySequence("Ctrl+S"))
        stop_action.triggered.connect(self.stop_execution)
        toolbar.addAction(stop_action)
        
        toolbar.addSeparator()
        
        search_action = QAction(self.style().standardIcon(QStyle.SP_FileDialogContentsView), "Search", self)
        search_action.setShortcut(QKeySequence("Ctrl+F"))
        search_action.triggered.connect(self.show_search_dialog)
        toolbar.addAction(search_action)
        
        toolbar.addSeparator()
        
        clear_action = QAction(self.style().standardIcon(QStyle.SP_DialogResetButton), "Clear Results", self)
        clear_action.triggered.connect(self.clear_results)
        toolbar.addAction(clear_action)
        
        save_action = QAction(self.style().standardIcon(QStyle.SP_DialogSaveButton), "Save Results", self)
        save_action.setShortcut(QKeySequence("Ctrl+Shift+S"))
        save_action.triggered.connect(self.save_results)
        toolbar.addAction(save_action)
        
        print_action = QAction(self.style().standardIcon(QStyle.SP_FileDialogDetailedView), "Print", self)
        print_action.setShortcut(QKeySequence.Print)
        print_action.triggered.connect(self.print_results)
        toolbar.addAction(print_action)
    
    def create_statusbar(self):
        self.status_bar = QStatusBar()
        self.setStatusBar(self.status_bar)
        
        # Status label
        self.status_label = QLabel("Ready")
        self.status_bar.addWidget(self.status_label, 1)
        
        # Memory file label
        self.memory_file_label = QLabel("No file loaded")
        self.status_bar.addPermanentWidget(self.memory_file_label)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setVisible(False)
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("Ready")
        self.status_bar.addPermanentWidget(self.progress_bar)
    
    def create_output_tab(self, name, initial_content=""):
        """Create a new output tab with advanced features"""
        tab = QWidget()
        layout = QVBoxLayout()
        layout.setContentsMargins(0, 0, 0, 0)
        
        # Toolbar for tab-specific actions
        tab_toolbar = QToolBar()
        tab_toolbar.setIconSize(QSize(18, 18))
        
        # Search box
        search_layout = QHBoxLayout()
        
        self.search_input = QLineEdit()
        self.search_input.setPlaceholderText("Search in results...")
        self.search_input.setObjectName("searchBox")
        
        search_btn = QPushButton("Search")
        search_btn.clicked.connect(lambda: self.highlight_text(name))
        
        clear_highlight_btn = QPushButton("Clear")
        clear_highlight_btn.clicked.connect(lambda: self.clear_highlight(name))
        
        search_layout.addWidget(self.search_input)
        search_layout.addWidget(search_btn)
        search_layout.addWidget(clear_highlight_btn)
        
        # Output area with monospace font and line wrapping
        output_area = QTextEdit()
        output_area.setReadOnly(True)
        output_area.setFont(QFont("Consolas", 10))
        output_area.setText(initial_content)
        output_area.setLineWrapMode(QTextEdit.NoWrap)
        output_area.setWordWrapMode(QTextOption.NoWrap)
        
        # Add widgets to layout
        layout.addLayout(search_layout)
        layout.addWidget(output_area)
        tab.setLayout(layout)
        
        # Add tab and store reference
        self.output_tabs[name] = {
            "widget": output_area,
            "search_input": self.search_input
        }
        index = self.result_tabs.addTab(tab, name)
        self.result_tabs.setCurrentIndex(index)
        
        return output_area
    
    def highlight_text(self, tab_name):
        """Highlight text in the specified tab"""
        if tab_name not in self.output_tabs:
            return
            
        text_edit = self.output_tabs[tab_name]["widget"]
        search_text = self.output_tabs[tab_name]["search_input"].text()
        if not search_text:
            return

        # Clear previous highlights
        cursor = text_edit.textCursor()
        cursor.setPosition(0)
        cursor.movePosition(QTextCursor.End, QTextCursor.KeepAnchor)
        clear_format = QTextCharFormat()
        clear_format.setBackground(Qt.transparent)
        cursor.mergeCharFormat(clear_format)

        # Set up highlight format
        highlight_format = QTextCharFormat()
        highlight_format.setBackground(QColor(255, 255, 0))  # Yellow
        
        # Search flags
        flags = QTextDocument.FindFlags()
        
        # Find and highlight all occurrences
        doc = text_edit.document()
        cursor = QTextCursor(doc)
        cursor.setPosition(0)
        
        while True:
            cursor = doc.find(search_text, cursor, flags)
            if cursor.isNull():
                break
            cursor.mergeCharFormat(highlight_format)
    
    def clear_highlight(self, tab_name):
        """Clear highlighting in the specified tab"""
        if tab_name not in self.output_tabs:
            return
            
        text_edit = self.output_tabs[tab_name]["widget"]
        cursor = text_edit.textCursor()
        cursor.setPosition(0)
        cursor.movePosition(QTextCursor.End, QTextCursor.KeepAnchor)
        clear_format = QTextCharFormat()
        clear_format.setBackground(Qt.transparent)
        cursor.mergeCharFormat(clear_format)
        
        # Clear search input
        self.output_tabs[tab_name]["search_input"].clear()
    
    def browse_file(self):
        """Open file dialog to select memory dump"""
        file_path, _ = QFileDialog.getOpenFileName(
            self, 
            "Select Memory Dump File", 
            self.settings.value("last_dir", ""), 
            "Memory Dump Files (*.dmp *.img *.mem *.raw *.vmem *.bin);;All Files (*)"
        )
        
        if file_path:
            self.memory_file = file_path
            self.file_path.setText(file_path)
            self.memory_file_label.setText(f"File: {os.path.basename(file_path)}")
            self.status_bar.showMessage(f"Loaded: {os.path.basename(file_path)}", 3000)
            
            # Save directory for next time
            self.settings.setValue("last_dir", os.path.dirname(file_path))
            
            # Add to recent files
            self.add_recent_file(file_path)
            
            # Update system info
            self.update_system_info()
    
    def update_system_info(self):
        """Update system information panel with memory file details"""
        if not self.memory_file:
            return
            
        self.system_info.clear()
        
        # Basic file info
        file_info = QFileInfo(self.memory_file)
        size_mb = file_info.size() / (1024 * 1024)
        
        self.system_info.append(f"Memory File: {file_info.fileName()}")
        self.system_info.append(f"Path: {file_info.absolutePath()}")
        self.system_info.append(f"Size: {size_mb:.2f} MB")
        self.system_info.append(f"Created: {file_info.birthTime().toString()}")
        self.system_info.append(f"Modified: {file_info.lastModified().toString()}")
        
        # Run basic volatility info command (simulated here)
        self.system_info.append("\n[Running basic memory analysis...]")
        
        # In a real implementation, you would run a command like:
        # python vol.py -f memory.dump windows.info
        # And parse the output to display here
        
        # Simulated output
        QTimer.singleShot(1000, lambda: self.append_system_info(
            "\n\n=== Basic Memory Analysis ===\n"
            "OS: Windows 10 x64 (10.0.19041)\n"
            "Kernel Base: 0xf80002600000\n"
            "DTB: 0x1ab000\n"
            "Number of Processors: 4\n"
            "Memory Size: 0x80000000 (2.00 GB)\n"
        ))
    
    def append_system_info(self, text):
        """Append text to system info panel"""
        self.system_info.moveCursor(QTextCursor.End)
        self.system_info.insertPlainText(text)
    
    def clear_file(self):
        """Clear current memory file"""
        self.memory_file = ""
        self.file_path.clear()
        self.memory_file_label.setText("No file loaded")
        self.system_info.clear()
        self.status_bar.showMessage("Memory file cleared", 2000)
    
    def run_selected_plugin(self):
        """Run the currently selected plugin"""
        if not self.memory_file:
            QMessageBox.warning(self, "Warning", "Please select a memory dump file first.")
            return
            
        selected_items = self.plugin_list.selectedItems()
        if not selected_items:
            QMessageBox.warning(self, "Warning", "Please select a plugin to run.")
            return
            
        plugin_name = selected_items[0].text().replace("⚡ ", "")
        os_name = self.plugin_os_combo.currentText()
        
        # Find the plugin command
        plugin_command = None
        plugin_desc = ""
        for name, cmd, desc in self.plugins[os_name]:
            if name == plugin_name:
                plugin_command = cmd
                plugin_desc = desc
                break
        
        if not plugin_command:
            QMessageBox.warning(self, "Error", f"Could not find command for plugin: {plugin_name} 2>/dev/null")
            return
        
        # Create base command
        base_command = f"python3 vol.py -f {self.memory_file} {plugin_command} "
        
        # Show plugin execution dialog
        dialog = PluginExecutionDialog(self, plugin_name, plugin_desc, base_command)
        if dialog.exec() == QDialog.Accepted:
            command = dialog.get_command()
            if command:
                # Create a new output tab
                timestamp = datetime.now().strftime("%H:%M:%S")
                self.current_tab_name = f"{plugin_name} [{timestamp}]"
                output_area = self.create_output_tab(self.current_tab_name, f"⚡ Running command: {command}\n\n")
                
                # Run the plugin
                self.run_plugin(command, self.current_tab_name)
    
    def run_plugin(self, command, tab_name):
        """Execute a plugin command"""
        # Set up progress bar
        self.progress_bar.setValue(0)
        self.progress_bar.setFormat("Starting... 0%")
        self.progress_bar.setVisible(True)
        self.status_label.setText(f"Executing {tab_name}...")
        
        # Stop any running command
        if self.current_runner:
            self.current_runner.stop()
            self.current_runner.wait(1000)  # Wait for thread to finish
            
        # Create command runner
        self.current_runner = CommandRunner(command, tab_name)
        self.current_runner.output_ready.connect(self.handle_output)
        self.current_runner.error_occurred.connect(self.handle_error)
        self.current_runner.progress_updated.connect(self.update_progress)
        self.current_runner.finished.connect(self.on_command_finished)
        self.current_runner.command_started.connect(self.on_command_started)
        
        # Add a small delay before starting to ensure UI is updated
        QTimer.singleShot(100, self.current_runner.start)
    
    def on_command_started(self, command):
        """Handle command started signal"""
        if self.current_tab_name in self.output_tabs:
            output_area = self.output_tabs[self.current_tab_name]["widget"]
            output_area.append(f"Command: {command}\n")
    
    def handle_output(self, text):
        """Handle output from command execution"""
        if self.current_tab_name in self.output_tabs:
            output_area = self.output_tabs[self.current_tab_name]["widget"]
            output_area.moveCursor(QTextCursor.End)
            
            # Apply different colors for different types of output
            if "ERROR" in text or "error" in text.lower():
                output_area.setTextColor(QColor(255, 80, 80))  # Red for errors
            elif "WARNING" in text or "warning" in text.lower():
                output_area.setTextColor(QColor(255, 200, 0))   # Yellow for warnings
            elif "INFO" in text or "info" in text.lower():
                output_area.setTextColor(QColor(100, 255, 255)) # Light blue for info
            else:
                output_area.setTextColor(QColor(0, 200, 255))   # Blue for normal output
            
            output_area.insertPlainText(text + "\n")
            output_area.moveCursor(QTextCursor.End)
    
    def handle_error(self, error_msg):
        """Handle error messages from command execution"""
        self.append_output(self.current_tab_name, f"\nERROR: {error_msg}\n")
        self.progress_bar.setFormat(f"Error: {error_msg[:30]}...")
    
    def append_output(self, tab_name, text):
        """Append text to the specified output tab"""
        if tab_name in self.output_tabs:
            output_area = self.output_tabs[tab_name]["widget"]
            output_area.moveCursor(QTextCursor.End)
            output_area.insertPlainText(text)
            output_area.moveCursor(QTextCursor.End)
    
    def update_progress(self, percent, message):
        """Update progress bar during command execution"""
        self.progress_bar.setValue(percent)
        self.progress_bar.setFormat(f"{message[:50]}... {percent}%")
    
    def on_command_finished(self, exit_code, tab_name):
        """Handle command completion"""
        self.progress_bar.setVisible(False)
        
        if exit_code == 0:
            self.status_label.setText(f"{tab_name} completed successfully")
            self.progress_bar.setFormat("Completed successfully")
            
            # Add completion message to output
            self.append_output(tab_name, "\n✔ Plugin execution completed successfully\n")
        else:
            self.status_label.setText(f"{tab_name} failed (code: {exit_code})")
            self.progress_bar.setFormat(f"Failed with code {exit_code}")
            
            # Add error message to output
            self.append_output(tab_name, f"\n✖ Plugin execution failed with code {exit_code}\n")
        
        # Reset current runner
        self.current_runner = None
    
    def stop_execution(self):
        """Stop the currently running command"""
        if self.current_runner and self.current_runner.isRunning():
            self.current_runner.stop()
            self.status_label.setText("Execution stopped by user")
            self.progress_bar.setFormat("Stopped by user")
            self.progress_bar.setValue(0)
            
            # Add stop message to output
            if self.current_tab_name in self.output_tabs:
                self.append_output(self.current_tab_name, "\n⚠ Execution stopped by user\n")
    
    def clear_results(self):
        """Clear all results in the current tab"""
        current_tab = self.result_tabs.currentWidget()
        if not current_tab:
            return
            
        for text_edit in current_tab.findChildren(QTextEdit):
            text_edit.clear()
    
    def save_results(self):
        """Save results from current tab to file"""
        if not self.output_tabs:
            QMessageBox.warning(self, "Warning", "No results to save.")
            return
            
        current_tab = self.result_tabs.currentWidget()
        if not current_tab:
            return
            
        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Results",
            self.settings.value("last_save_dir", ""),
            "Text Files (*.txt);;HTML Files (*.html);;All Files (*)"
        )
        
        if file_path:
            try:
                # Save directory for next time
                self.settings.setValue("last_save_dir", os.path.dirname(file_path))
                
                # Get content from all text edits in current tab
                full_content = []
                for text_edit in current_tab.findChildren(QTextEdit):
                    full_content.append(text_edit.toPlainText())
                
                # Write to file
                with open(file_path, 'w', encoding='utf-8') as f:
                    f.write('\n'.join(full_content))
                
                self.status_label.setText(f"Results saved to {os.path.basename(file_path)}")
                QMessageBox.information(self, "Success", "Results saved successfully.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to save file: {str(e)}")
    
    def export_results(self):
        """Export results in various formats"""
        if not self.output_tabs:
            QMessageBox.warning(self, "Warning", "No results to export.")
            return
            
        current_tab = self.result_tabs.currentWidget()
        if not current_tab:
            return
            
        # Get the content to export
        content = ""
        for text_edit in current_tab.findChildren(QTextEdit):
            content += text_edit.toPlainText() + "\n"
        
        # Show export options dialog
        formats = {
            "Text File": ".txt",
            "CSV File": ".csv",
            "JSON File": ".json",
            "HTML Report": ".html",
            "PDF Document": ".pdf"
        }
        
        format_name, ok = QInputDialog.getItem(
            self, "Export Results", "Select export format:", list(formats.keys()), 0, False
        )
        
        if ok and format_name:
            file_path, _ = QFileDialog.getSaveFileName(
                self,
                "Export Results",
                self.settings.value("last_export_dir", ""),
                f"{format_name} (*{formats[format_name]})"
            )
            
            if file_path:
                try:
                    # Ensure correct extension
                    if not file_path.endswith(formats[format_name]):
                        file_path += formats[format_name]
                    
                    # Save directory for next time
                    self.settings.setValue("last_export_dir", os.path.dirname(file_path))
                    
                    # Handle different export formats
                    if format_name == "Text File":
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(content)
                    
                    elif format_name == "CSV File":
                        # Convert to CSV (simple implementation)
                        lines = content.split('\n')
                        with open(file_path, 'w', encoding='utf-8') as f:
                            for line in lines:
                                if line.strip():
                                    f.write(f'"{line.strip()}"\n')
                    
                    elif format_name == "JSON File":
                        # Convert to JSON
                        data = {
                            "analysis_results": content.split('\n'),
                            "metadata": {
                                "date": datetime.now().isoformat(),
                                "source_file": self.memory_file
                            }
                        }
                        with open(file_path, 'w', encoding='utf-8') as f:
                            json.dump(data, f, indent=2)
                    
                    elif format_name == "HTML Report":
                        # Create HTML report
                        html = f"""
                        <!DOCTYPE html>
                        <html>
                        <head>
                            <title>Volatility Analysis Report</title>
                            <style>
                                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                                h1 {{ color: #0066cc; }}
                                pre {{ background-color: #f5f5f5; padding: 15px; border-radius: 5px; }}
                                .meta {{ color: #666; font-size: 0.9em; }}
                            </style>
                        </head>
                        <body>
                            <h1>Volatility Analysis Report</h1>
                            <div class="meta">
                                <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                                <p>Memory File: {os.path.basename(self.memory_file) if self.memory_file else 'None'}</p>
                            </div>
                            <pre>{content}</pre>
                        </body>
                        </html>
                        """
                        with open(file_path, 'w', encoding='utf-8') as f:
                            f.write(html)
                    
                    elif format_name == "PDF Document":
                        # Create PDF document
                        printer = QPrinter(QPrinter.HighResolution)
                        printer.setOutputFormat(QPrinter.PdfFormat)
                        printer.setOutputFileName(file_path)
                        
                        doc = QTextDocument()
                        doc.setHtml(f"""
                            <h1>Volatility Analysis Report</h1>
                            <p>Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</p>
                            <p>Memory File: {os.path.basename(self.memory_file) if self.memory_file else 'None'}</p>
                            <pre>{content}</pre>
                        """)
                        doc.print_(printer)
                    
                    self.status_label.setText(f"Results exported to {os.path.basename(file_path)}")
                    QMessageBox.information(self, "Success", "Results exported successfully.")
                
                except Exception as e:
                    QMessageBox.critical(self, "Error", f"Failed to export file: {str(e)}")
    
    def print_results(self):
        """Print current results"""
        if not self.output_tabs:
            QMessageBox.warning(self, "Warning", "No results to print.")
            return
            
        current_tab = self.result_tabs.currentWidget()
        if not current_tab:
            return
            
        # Get the content to print
        content = ""
        for text_edit in current_tab.findChildren(QTextEdit):
            content += text_edit.toPlainText() + "\n"
        
        # Create printer dialog
        printer = QPrinter(QPrinter.HighResolution)
        dialog = QPrintDialog(printer, self)
        
        if dialog.exec() == QDialog.Accepted:
            # Create document and print
            doc = QTextDocument()
            doc.setPlainText(content)
            doc.print_(printer)
    
    def close_tab(self, index):
        """Close a results tab"""
        tab_name = self.result_tabs.tabText(index)
        if tab_name in self.output_tabs:
            del self.output_tabs[tab_name]
        self.result_tabs.removeTab(index)
    
    def show_search_dialog(self):
        """Show advanced search dialog"""
        dialog = SearchDialog(self)
        if dialog.exec() == QDialog.Accepted:
            params = dialog.get_search_params()
            self.perform_search(params)
    
    def perform_search(self, params):
        """Perform search based on parameters"""
        current_tab = self.result_tabs.currentWidget()
        if not current_tab:
            return
            
        for text_edit in current_tab.findChildren(QTextEdit):
            cursor = text_edit.textCursor()
            
            # Set search flags
            flags = QTextDocument.FindFlags()
            if not params["forward"]:
                flags |= QTextDocument.FindBackward
            if params["case_sensitive"]:
                flags |= QTextDocument.FindCaseSensitively
            if params["whole_word"]:
                flags |= QTextDocument.FindWholeWords
            
            # Perform search
            if params["regex"]:
                # Regular expression search
                regex = QRegularExpression(params["text"])
                if not params["case_sensitive"]:
                    regex.setPatternOptions(QRegularExpression.CaseInsensitiveOption)
                
                found = text_edit.find(regex, flags)
            else:
                # Simple text search
                found = text_edit.find(params["text"], flags)
            
            if not found:
                QMessageBox.information(self, "Search", "No more matches found.")
    
    def zoom_in(self):
        """Zoom in on text in output tabs"""
        for tab_name in self.output_tabs:
            text_edit = self.output_tabs[tab_name]["widget"]
            current_font = text_edit.font()
            current_font.setPointSize(current_font.pointSize() + 1)
            text_edit.setFont(current_font)
    
    def zoom_out(self):
        """Zoom out on text in output tabs"""
        for tab_name in self.output_tabs:
            text_edit = self.output_tabs[tab_name]["widget"]
            current_font = text_edit.font()
            if current_font.pointSize() > 6:  # Minimum size
                current_font.setPointSize(current_font.pointSize() - 1)
                text_edit.setFont(current_font)
    
    def reset_zoom(self):
        """Reset zoom level to default"""
        for tab_name in self.output_tabs:
            text_edit = self.output_tabs[tab_name]["widget"]
            default_font = QFont("Consolas", 10)
            text_edit.setFont(default_font)
    
    def run_advanced_analysis(self):
        """Run advanced analysis with multiple plugins"""
        if not self.memory_file:
            QMessageBox.warning(self, "Warning", "Please select a memory dump file first.")
            return
            
        # Create a dialog to select multiple plugins
        dialog = QDialog(self)
        dialog.setWindowTitle("Advanced Analysis")
        dialog.setMinimumSize(600, 400)
        
        layout = QVBoxLayout()
        
        # Plugin selection
        plugin_group = QGroupBox("Select Plugins to Run")
        plugin_layout = QVBoxLayout()
        
        self.plugin_checkboxes = []
        os_name = self.plugin_os_combo.currentText()
        
        if os_name in self.plugins:
            for name, cmd, desc in self.plugins[os_name]:
                cb = QCheckBox(name)
                cb.setToolTip(desc)
                self.plugin_checkboxes.append((cb, cmd))
                plugin_layout.addWidget(cb)
        
        plugin_group.setLayout(plugin_layout)
        
        # Options
        options_group = QGroupBox("Options")
        options_layout = QFormLayout()
        
        self.parallel_check = QCheckBox("Run plugins in parallel")
        self.parallel_check.setChecked(False)
        
        self.save_check = QCheckBox("Save all results to single file")
        self.save_check.setChecked(True)
        
        options_layout.addRow(self.parallel_check)
        options_layout.addRow(self.save_check)
        options_group.setLayout(options_layout)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        
        layout.addWidget(plugin_group)
        layout.addWidget(options_group)
        layout.addWidget(button_box)
        dialog.setLayout(layout)
        
        if dialog.exec() == QDialog.Accepted:
            selected_plugins = []
            for cb, cmd in self.plugin_checkboxes:
                if cb.isChecked():
                    selected_plugins.append((cb.text(), cmd))
            
            if not selected_plugins:
                QMessageBox.warning(self, "Warning", "No plugins selected.")
                return
                
            # Create a master tab for the analysis
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            master_tab_name = f"Advanced Analysis [{timestamp}]"
            self.create_output_tab(master_tab_name, f"⚡ Advanced analysis started at {timestamp}\n\n")
            
            # Run each selected plugin
            for name, cmd in selected_plugins:
                command = f"python3 vol.py -f {self.memory_file} {cmd}"
                tab_name = f"{name} [{timestamp}]"
                
                # Create individual tab for each plugin
                self.create_output_tab(tab_name, f"⚡ Running: {command}\n\n")
                
                # Run the command
                self.run_plugin(command, tab_name)
                
                # If not running in parallel, wait for completion
                if not self.parallel_check.isChecked() and self.current_runner:
                    while self.current_runner and self.current_runner.isRunning():
                        QApplication.processEvents()
                        QThread.msleep(100)
    
    def compare_results(self):
        """Compare results from two different analyses"""
        if len(self.output_tabs) < 2:
            QMessageBox.warning(self, "Warning", "You need at least two result tabs to compare.")
            return
            
        # Get list of available tabs
        tab_names = [self.result_tabs.tabText(i) for i in range(self.result_tabs.count())]
        
        # Create comparison dialog
        dialog = QDialog(self)
        dialog.setWindowTitle("Compare Results")
        dialog.setMinimumSize(500, 300)
        
        layout = QVBoxLayout()
        
        # Tab selection
        tab1_combo = QComboBox()
        tab1_combo.addItems(tab_names)
        
        tab2_combo = QComboBox()
        tab2_combo.addItems(tab_names)
        if len(tab_names) > 1:
            tab2_combo.setCurrentIndex(1)
        
        form_layout = QFormLayout()
        form_layout.addRow("First Tab:", tab1_combo)
        form_layout.addRow("Second Tab:", tab2_combo)
        
        # Comparison options
        method_combo = QComboBox()
        method_combo.addItems(["Side by Side", "Differences Only", "Common Results"])
        
        form_layout.addRow("Comparison Method:", method_combo)
        
        # Buttons
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(dialog.accept)
        button_box.rejected.connect(dialog.reject)
        
        layout.addLayout(form_layout)
        layout.addWidget(button_box)
        dialog.setLayout(layout)
        
        if dialog.exec() == QDialog.Accepted:
            tab1_name = tab1_combo.currentText()
            tab2_name = tab2_combo.currentText()
            method = method_combo.currentText()
            
            if tab1_name == tab2_name:
                QMessageBox.warning(self, "Warning", "Cannot compare a tab with itself.")
                return
                
            # Get content from both tabs
            content1 = self.output_tabs[tab1_name]["widget"].toPlainText()
            content2 = self.output_tabs[tab2_name]["widget"].toPlainText()
            
            # Create comparison tab
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            comp_tab_name = f"Comparison [{timestamp}]"
            self.create_output_tab(comp_tab_name, f"⚡ Comparing {tab1_name} and {tab2_name}\nMethod: {method}\n\n")
            
            # Perform comparison based on method
            if method == "Side by Side":
                lines1 = content1.split('\n')
                lines2 = content2.split('\n')
                max_lines = max(len(lines1), len(lines2))
                
                output = []
                for i in range(max_lines):
                    line1 = lines1[i] if i < len(lines1) else ""
                    line2 = lines2[i] if i < len(lines2) else ""
                    output.append(f"{line1.ljust(80)} | {line2}")
                
                self.append_output(comp_tab_name, '\n'.join(output))
                
            elif method == "Differences Only":
                lines1 = set(content1.split('\n'))
                lines2 = set(content2.split('\n'))
                diff = lines1.symmetric_difference(lines2)
                
                self.append_output(comp_tab_name, '\n'.join(sorted(diff)))
                
            elif method == "Common Results":
                lines1 = set(content1.split('\n'))
                lines2 = set(content2.split('\n'))
                common = lines1.intersection(lines2)
                
                self.append_output(comp_tab_name, '\n'.join(sorted(common)))

            
            self.append_output(comp_tab_name, f"\n✔ Comparison completed at {timestamp}\n")
    
    def show_about(self):
        """Show about dialog"""
        about_dialog = AboutDialog(self)
        about_dialog.exec()
    
    def show_docs(self):
        """Show documentation in browser"""
        doc_url = "https://github.com/volatilityfoundation/volatility/wiki"
        webbrowser.open(doc_url)
    
    def show_tutorials(self):
        """Show tutorials in browser"""
        tutorial_url = "https://www.volatilityfoundation.org/resources"
        webbrowser.open(tutorial_url)


def main():
    try:
        # Set up environment for GUI
        if 'WAYLAND_DISPLAY' in os.environ:
            os.environ['QT_QPA_PLATFORM'] = 'wayland'
        elif 'DISPLAY' in os.environ:
            os.environ['QT_QPA_PLATFORM'] = 'xcb'

        # Create application
        app = QApplication(sys.argv)
        app.setApplicationName("Volatility3 Professional")
        app.setApplicationVersion("3.0")
        app.setOrganizationName("Forensic Tools")
        app.setWindowIcon(QIcon(":/icons/app_icon.png"))  # You'd need to add this resource
        
        # Apply hacker theme
        HackerTheme.apply(app)
        
        # Create and show main window
        window = VolatilityGUI()
        window.show()
        
        # Run application
        sys.exit(app.exec())
    except Exception as e:
        print(f"Error: {e}")
        QMessageBox.critical(None, "Fatal Error", f"Application failed to start:\n{str(e)}")


if __name__ == "__main__":
    main()
