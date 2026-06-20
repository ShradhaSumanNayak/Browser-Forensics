import sys
import os
import platform
from pathlib import Path
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QCheckBox, QPushButton, QLabel, 
                             QTextEdit, QLineEdit, QFileDialog, QGroupBox, QProgressBar,
                             QDialog, QComboBox, QMessageBox, QGridLayout, QFrame)
from PyQt5.QtCore import QThread, QTimer, pyqtSignal, Qt
from PyQt5.QtGui import QIcon

# Import the main execution logic
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from main import execute_extraction
from utils.integrity import get_tool_hash, verify_environment
from utils.io_helper import sanitize_path
from api.remote_agent import RemoteForensicAgent

class ExtractionWorker(QThread):
    """
    Background worker thread to run the forensic extraction without freezing the GUI.
    """
    log_signal = pyqtSignal(str)
    finished_signal = pyqtSignal()

    def __init__(self, output_dir, do_chrome, do_firefox, do_edge, do_safari, do_brave, do_opera, do_tor, do_quarantine, do_deep_recovery, case_id="N/A", investigator="Unknown", evidence_id="N/A", **kwargs):
        super().__init__()
        self.output_dir = output_dir
        self.do_chrome = do_chrome
        self.do_firefox = do_firefox
        self.do_edge = do_edge
        self.do_safari = do_safari
        self.do_brave = do_brave
        self.do_opera = do_opera
        self.do_tor = do_tor
        self.do_quarantine = do_quarantine
        self.do_deep_recovery = do_deep_recovery
        self.case_id = case_id
        self.investigator = investigator
        self.evidence_id = evidence_id
        
        self.f_history = kwargs.get('fetch_history', True)
        self.f_cookies = kwargs.get('fetch_cookies', True)
        self.f_bookmarks = kwargs.get('fetch_bookmarks', True)
        self.f_passwords = kwargs.get('fetch_passwords', True)
        self.f_forms = kwargs.get('fetch_forms', True)
        self.f_extensions = kwargs.get('fetch_extensions', True)
        self.f_sessions = kwargs.get('fetch_sessions', True)
        self.warrant_id = kwargs.get('warrant_id', "N/A")
        self.jurisdiction = kwargs.get('jurisdiction', "N/A")
        self.redact_pii = kwargs.get('redact_pii', False)
        self.image_path = kwargs.get('image_path', "")
        self.mobile_detect = kwargs.get('mobile_detect', False)
        self.do_all = kwargs.get('do_all', False)
        self.firefox_master_password = kwargs.get('firefox_master_password', "")
        self.analyze_intent = kwargs.get('analyze_intent', False)
        self.hijack_session = kwargs.get('hijack_session', False)
        self.fetch_hardware_fingerprint = kwargs.get('fetch_hardware_fingerprint', True)
        self.export_downloads = kwargs.get('export_downloads', True)

    def run(self):
        # Pass the pyqtSignal's emit method as the logger_callback to main.py
        execute_extraction(
            output=self.output_dir,
            do_chrome=self.do_chrome,
            do_firefox=self.do_firefox,
            do_edge=self.do_edge,
            do_safari=self.do_safari,
            do_brave=self.do_brave,
            do_opera=self.do_opera,
            do_tor=self.do_tor,
            do_all=self.do_all,
            quarantine=self.do_quarantine,
            deep_recovery=self.do_deep_recovery,
            logger_callback=self.log_signal.emit,
            fetch_history=self.f_history,
            fetch_cookies=self.f_cookies,
            fetch_bookmarks=self.f_bookmarks,
            fetch_passwords=self.f_passwords,
            fetch_forms=self.f_forms,
            fetch_extensions=self.f_extensions,
            fetch_sessions=self.f_sessions,
            case_id=self.case_id,
            investigator=self.investigator,
            evidence_id=self.evidence_id,
            warrant_id=self.warrant_id,
            jurisdiction=self.jurisdiction,
            redact_pii=self.redact_pii,
            image_path=self.image_path,
            do_mobile=self.mobile_detect,
            firefox_master_password=self.firefox_master_password,
            analyze_intent=self.analyze_intent,
            hijack_session=self.hijack_session,
            fetch_hardware_fingerprint=self.fetch_hardware_fingerprint,
            export_downloads=self.export_downloads,
        )
        self.finished_signal.emit()

def get_desktop_path():
    """ Dynamically finds the true desktop folder even if OneDrive is hijacking it. """
    onedrive_desktop = Path.home() / "OneDrive" / "Desktop"
    if onedrive_desktop.exists():
        return str(onedrive_desktop)
    return str(Path.home() / "Desktop")

class LoginDialog(QDialog):
    """
    Electronic ID and Role-Based Access Control (RBAC) login for LEA standards.
    """
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Browser Forensics Tool - Secure Login")
        self.setFixedSize(400, 250)
        self.user_data = None
        
        layout = QVBoxLayout()
        layout.setContentsMargins(30, 30, 30, 30)
        layout.setSpacing(15)

        title = QLabel("SECURE ACCESS GATEWAY")
        title.setAlignment(Qt.AlignCenter)
        title.setStyleSheet("font-size: 16pt; font-weight: bold; color: #0078d4; margin-bottom: 10px;")
        layout.addWidget(title)
        
        layout.addWidget(QLabel("INVESTIGATOR AUTHENTICATION"))
        
        self.input_user = QLineEdit()
        self.input_user.setPlaceholderText("Badge ID / Username")
        layout.addWidget(self.input_user)
        
        self.input_pass = QLineEdit()
        self.input_pass.setPlaceholderText("Security Credential")
        self.input_pass.setEchoMode(QLineEdit.Password)
        layout.addWidget(self.input_pass)
        
        self.combo_role = QComboBox()
        self.combo_role.addItems(["Field Analyst", "Technical Lead/Supervisor", "Audit Officer"])
        layout.addWidget(self.combo_role)
        
        self.btn_login = QPushButton("AUTHORIZE ACCESS")
        self.btn_login.setMinimumHeight(50)
        self.btn_login.clicked.connect(self.authenticate)
        layout.addWidget(self.btn_login)
        
        self.setLayout(layout)

    def authenticate(self):
        # In a real enterprise app, this would check against an LDAP/AD server
        # For this prototype, we'll accept any non-empty input as 'authenticated'
        user = self.input_user.text()
        password = self.input_pass.text()
        role = self.combo_role.currentText()
        
        if user and password:
            self.user_data = {"user": user, "role": role}
            self.accept()
        else:
            QMessageBox.warning(self, "Access Denied", "Invalid Investigator Credentials.")

class ForensicDashboard(QMainWindow):
    remote_trigger_signal = pyqtSignal(dict)

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Browser Forensics Tool")
        self.setMinimumSize(800, 600)
        self.output_dir = os.path.join(get_desktop_path(), "forensics_output")
        
        # Self-Integrity Check
        self.tool_hash = get_tool_hash()
        self.env_info = verify_environment()
        
        # User Authentication and Identity
        self.current_user = None
        self.current_role = None
        self.mobile_detected = False
        
        # Remote Agent Instance
        self.remote_agent = RemoteForensicAgent(port=8888, extraction_callback=self.handle_remote_trigger)
        self.remote_trigger_signal.connect(self._handle_remote_trigger_on_ui_thread)

        self.initUI()
        self.create_menus()
        self.apply_elite_styling()
        icon_path = self._resource_root() / "assets" / "browser_forensics_tool.ico"
        if icon_path.exists():
            self.setWindowIcon(QIcon(str(icon_path)))

    def _grid_label(self, text):
        label = QLabel(text)
        label.setAlignment(Qt.AlignRight | Qt.AlignVCenter)
        label.setMinimumWidth(135)
        return label

    def _set_output_dir_label(self):
        self.lbl_outdir.setText(f"OUTPUT: {self.output_dir}")

    def _set_mobile_status(self, text, color):
        self.lbl_mobile_status.setText(text)
        self.lbl_mobile_status.setStyleSheet(
            f"color: {color}; font-weight: bold; padding: 4px 8px; border: 1px solid {color}; border-radius: 4px;"
        )

    def _set_remote_agent_status(self, text, color):
        self.lbl_agent_status.setText(text)
        self.lbl_agent_status.setStyleSheet(
            f"color: {color}; font-weight: bold; padding: 4px 8px; border: 1px solid {color}; border-radius: 4px;"
        )

    def _resource_root(self):
        if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
            return Path(sys._MEIPASS)
        return Path(__file__).resolve().parents[1]

    def _refresh_remote_agent_status(self):
        if self.remote_agent.is_running:
            self._set_remote_agent_status("AGENT: LISTENING", "#107c10")
        elif self.cb_remote_agent.isChecked():
            self._set_remote_agent_status("AGENT: STARTING", "#0078d4")
        else:
            self._set_remote_agent_status("AGENT: OFFLINE", "#666666")

    def _open_path(self, target_path):
        import subprocess

        if platform.system() == "Windows":
            os.startfile(target_path)
            return
        opener = "open" if platform.system() == "Darwin" else "xdg-open"
        subprocess.run([opener, target_path], check=False)

    def initUI(self):
        container = QWidget()
        self.setCentralWidget(container)
        main_layout = QVBoxLayout(container)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(10)

        # 1. Master Integrity Header (Elite Tactical Design)
        header_frame = QFrame()
        header_frame.setObjectName("HeaderFrame")
        header_layout = QHBoxLayout(header_frame)
        header_layout.setContentsMargins(10, 5, 10, 5)
        
        self.lbl_tool_hash = QLabel(f"INTEGRITY: {self.tool_hash[:32]}...")
        self.lbl_tool_hash.setToolTip(f"Full SHA-256: {self.tool_hash}")
        
        self.lbl_user_badge = QLabel("UNAUTHENTICATED SESSION")
        self.lbl_user_badge.setObjectName("BadgeLabel")
        
        self.lbl_security_status = QLabel(f"STATUS: {'AUTHORIZED' if self.env_info['is_admin'] else 'RESTRICTED'}")
        self.lbl_security_status.setObjectName("StatusLabel")
        
        header_layout.addWidget(self.lbl_tool_hash)
        header_layout.addStretch()
        header_layout.addWidget(self.lbl_user_badge)
        header_layout.addSpacing(20)
        header_layout.addWidget(self.lbl_security_status)
        main_layout.addWidget(header_frame)

        # 2. Case Management (Grid Layout)
        case_group = QGroupBox("CASE MANAGEMENT & CHAIN OF CUSTODY")
        case_grid = QGridLayout()
        case_grid.setSpacing(10)
        case_grid.setColumnStretch(1, 1)
        case_grid.setColumnStretch(3, 1)
        
        self.input_case_id = QLineEdit()
        self.input_case_id.setPlaceholderText("Case Identifier (e.g. 2026-X-11)")
        self.input_investigator = QLineEdit()
        self.input_investigator.setPlaceholderText("Authorized Personnel")
        self.input_evidence_id = QLineEdit()
        self.input_evidence_id.setPlaceholderText("Artifact Evidence ID")
        
        self.input_warrant_id = QLineEdit()
        self.input_warrant_id.setPlaceholderText("Search Warrant/Legal Order")
        self.input_jurisdiction = QLineEdit()
        self.input_jurisdiction.setPlaceholderText("Reporting Jurisdiction")
        self.input_firefox_master_password = QLineEdit()
        self.input_firefox_master_password.setPlaceholderText("Firefox/Tor Master Password (Optional)")
        self.input_firefox_master_password.setEchoMode(QLineEdit.Password)

        case_grid.addWidget(self._grid_label("CASE ID:"), 0, 0)
        case_grid.addWidget(self.input_case_id, 0, 1)
        case_grid.addWidget(self._grid_label("INVESTIGATOR:"), 0, 2)
        case_grid.addWidget(self.input_investigator, 0, 3)
        case_grid.addWidget(self._grid_label("EVIDENCE ID:"), 1, 0)
        case_grid.addWidget(self.input_evidence_id, 1, 1)
        case_grid.addWidget(self._grid_label("WARRANT:"), 1, 2)
        case_grid.addWidget(self.input_warrant_id, 1, 3)
        case_grid.addWidget(self._grid_label("JURISDICTION:"), 2, 0)
        case_grid.addWidget(self.input_jurisdiction, 2, 1)
        case_grid.addWidget(self._grid_label("FF/TOR PASSWORD:"), 2, 2)
        case_grid.addWidget(self.input_firefox_master_password, 2, 3)
        
        case_group.setLayout(case_grid)
        main_layout.addWidget(case_group)

        # 3. Acquisition Sources
        acq_row = QHBoxLayout()
        
        hw_group = QGroupBox("HARDWARE & MOBILE ACQUISITION")
        hw_layout = QGridLayout()
        hw_layout.setColumnStretch(1, 1)
        self.input_image_path = QLineEdit()
        self.input_image_path.setPlaceholderText("Forensic Disk Image (.dd, .E01)")
        self.btn_browse_img = QPushButton("BROWSE")
        self.btn_browse_img.setMinimumWidth(110)
        
        self.btn_detect_android = QPushButton("DETECT HANDSET")
        self.btn_detect_android.setMinimumWidth(110)
        self.lbl_mobile_status = QLabel()
        self.lbl_mobile_status.setAlignment(Qt.AlignCenter)
        self.lbl_mobile_status.setMinimumWidth(220)
        self._set_mobile_status("MOBILE: DISCONNECTED", "#aa0000")
        
        hw_layout.addWidget(self._grid_label("IMAGE:"), 0, 0)
        hw_layout.addWidget(self.input_image_path, 0, 1)
        hw_layout.addWidget(self.btn_browse_img, 0, 2)
        hw_layout.addWidget(self.btn_detect_android, 1, 0, 1, 2)
        hw_layout.addWidget(self.lbl_mobile_status, 1, 2)
        hw_group.setLayout(hw_layout)
        
        acq_row.addWidget(hw_group)
        main_layout.addLayout(acq_row)

        # 4. Browser & Artifact Matrix
        matrix_layout = QHBoxLayout()
        
        browser_group = QGroupBox("TARGETED BROWSERS")
        browser_vbox = QVBoxLayout()
        
        # Grid for browsers to keep them neat
        browser_grid = QGridLayout()
        browser_grid.setColumnStretch(0, 1)
        browser_grid.setColumnStretch(1, 1)
        self.cb_chrome = QCheckBox("Chrome")
        self.cb_chrome.setChecked(True)
        self.cb_firefox = QCheckBox("Firefox")
        self.cb_firefox.setChecked(True)
        self.cb_edge = QCheckBox("Edge")
        self.cb_edge.setChecked(True)
        self.cb_brave = QCheckBox("Brave")
        self.cb_brave.setChecked(True)
        self.cb_opera = QCheckBox("Opera")
        self.cb_opera.setChecked(True)
        self.cb_tor = QCheckBox("Tor")
        self.cb_tor.setChecked(True)
        self.cb_safari = QCheckBox("Safari") # Added Safari back
        
        browser_grid.addWidget(self.cb_chrome, 0, 0)
        browser_grid.addWidget(self.cb_firefox, 0, 1)
        browser_grid.addWidget(self.cb_edge, 1, 0)
        browser_grid.addWidget(self.cb_brave, 1, 1)
        browser_grid.addWidget(self.cb_opera, 2, 0)
        browser_grid.addWidget(self.cb_tor, 2, 1)
        browser_grid.addWidget(self.cb_safari, 3, 0) # Position Safari
        browser_vbox.addLayout(browser_grid)
        browser_group.setLayout(browser_vbox)
        
        artifact_group = QGroupBox("FORENSIC ARTIFACTS")
        art_grid = QGridLayout()
        art_grid.setColumnStretch(0, 1)
        art_grid.setColumnStretch(1, 1)
        self.cb_history = QCheckBox("History")
        self.cb_history.setChecked(True)
        self.cb_cookies = QCheckBox("Cookies")
        self.cb_cookies.setChecked(True)
        self.cb_bookmarks = QCheckBox("Bookmarks")
        self.cb_bookmarks.setChecked(True)
        self.cb_passwords = QCheckBox("Passwords")
        self.cb_passwords.setChecked(True)
        self.cb_forms = QCheckBox("Autofill")
        self.cb_forms.setChecked(True)
        self.cb_sessions = QCheckBox("Sessions")
        self.cb_sessions.setChecked(True)
        self.cb_extensions = QCheckBox("Extensions")
        self.cb_export_downloads = QCheckBox("Export Physical Downloads")
        self.cb_export_downloads.setChecked(True)
        self.cb_hardware = QCheckBox("Hardware Fingerprints")
        self.cb_hardware.setChecked(True)
        
        art_grid.addWidget(self.cb_history, 0, 0)
        art_grid.addWidget(self.cb_cookies, 0, 1)
        art_grid.addWidget(self.cb_bookmarks, 1, 0)
        art_grid.addWidget(self.cb_passwords, 1, 1)
        art_grid.addWidget(self.cb_forms, 2, 0)
        art_grid.addWidget(self.cb_sessions, 2, 1)
        art_grid.addWidget(self.cb_extensions, 3, 0)
        art_grid.addWidget(self.cb_export_downloads, 3, 1)
        # Hardware moved to Strategic Controls for better thematic grouping
        artifact_group.setLayout(art_grid)
        
        matrix_layout.addWidget(browser_group, 1)
        matrix_layout.addWidget(artifact_group, 1)
        main_layout.addLayout(matrix_layout)

        # 5. Strategic Controls
        ctrl_group = QGroupBox("STRATEGIC TACTICAL CONTROLS")
        ctrl_layout = QGridLayout()
        ctrl_layout.setColumnStretch(0, 1)
        ctrl_layout.setColumnStretch(1, 1)
        ctrl_layout.setColumnStretch(2, 1)
        
        self.cb_sandbox = QCheckBox("QUARANTINE MALWARE (WSB)")
        self.cb_sandbox.setChecked(True)
        self.cb_deep_recovery = QCheckBox("DEEP RECOVERY CARVING")
        self.cb_redact_pii = QCheckBox("PII COMPLIANCE REDACTION")
        self.cb_intent_analysis = QCheckBox("AI INTENT ANALYSIS (LLM)")
        self.cb_hijack_session = QCheckBox("GENERATE HIJACK CONTAINER")
        
        ctrl_layout.addWidget(self.cb_sandbox, 0, 0)
        ctrl_layout.addWidget(self.cb_deep_recovery, 0, 1)
        ctrl_layout.addWidget(self.cb_redact_pii, 0, 2)
        ctrl_layout.addWidget(self.cb_intent_analysis, 1, 0)
        ctrl_layout.addWidget(self.cb_hijack_session, 1, 1)
        ctrl_layout.addWidget(self.cb_hardware, 1, 2) # Move hardware here for symmetry
        
        self.cb_remote_agent = QCheckBox("REMOTE TRIAGE AGENT (REST API)")
        self.cb_remote_agent.clicked.connect(self.toggle_remote_agent)
        self.cb_remote_agent.setStyleSheet("color: #0078d4;")
        self.lbl_agent_status = QLabel()
        self.lbl_agent_status.setAlignment(Qt.AlignCenter)
        self.lbl_agent_status.setMinimumWidth(160)
        self._set_remote_agent_status("AGENT: OFFLINE", "#666666")
        ctrl_layout.addWidget(self.cb_remote_agent, 2, 0, 1, 2)
        ctrl_layout.addWidget(self.lbl_agent_status, 2, 2)
        
        dir_sub_layout = QHBoxLayout()
        dir_sub_layout.setSpacing(10)
        self.lbl_outdir = QLabel()
        self.lbl_outdir.setStyleSheet("font-family: 'Consolas'; font-size: 9pt;")
        self.lbl_outdir.setTextInteractionFlags(Qt.TextSelectableByMouse)
        self.lbl_outdir.setWordWrap(True)
        self._set_output_dir_label()
        btn_select_dir = QPushButton("TARGET DIRECTORY")
        btn_select_dir.setMinimumWidth(150)
        btn_select_dir.clicked.connect(self.select_directory)
        dir_sub_layout.addWidget(self.lbl_outdir, 1)
        dir_sub_layout.addWidget(btn_select_dir)
        ctrl_layout.addLayout(dir_sub_layout, 3, 0, 1, 3)
        
        ctrl_group.setLayout(ctrl_layout)
        main_layout.addWidget(ctrl_group)

        # 6. Execution Progress
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)

        self.lbl_status = QLabel("SYSTEM READY - STANDING BY FOR EXTRACTION")
        self.lbl_status.setAlignment(Qt.AlignCenter)
        self.lbl_status.setObjectName("StatusMessage")
        main_layout.addWidget(self.lbl_status)

        # 7. Final Action Buttons
        btn_action_layout = QHBoxLayout()
        self.btn_run = QPushButton("START MISSION EXTRACTION")
        self.btn_run.setObjectName("RunButton")
        self.btn_run.setMinimumHeight(60)
        self.btn_run.clicked.connect(self.start_extraction)
        
        self.btn_reports = QPushButton("OPEN REPORT FOLDER")
        self.btn_reports.setObjectName("ReportButton")
        self.btn_reports.setEnabled(False)
        self.btn_reports.setMinimumHeight(60)
        self.btn_reports.clicked.connect(self.open_reports)
        
        btn_action_layout.addWidget(self.btn_run, 3)
        btn_action_layout.addWidget(self.btn_reports, 1)
        main_layout.addLayout(btn_action_layout)

        # 8. Forensic Terminal
        self.console = QTextEdit()
        self.console.setReadOnly(True)
        self.console.setObjectName("ForensicTerminal")
        self.console.setLineWrapMode(QTextEdit.NoWrap)
        main_layout.addWidget(self.console)

        # Connect functional buttons
        self.btn_browse_img.clicked.connect(self.browse_image)
        self.btn_detect_android.clicked.connect(self.detect_mobile)

    def create_menus(self):
        menubar = self.menuBar()
        
        # File Menu
        file_menu = menubar.addMenu('&File')
        exit_action = file_menu.addAction('Exit Mission')
        exit_action.triggered.connect(self.close)
        
        # Tools Menu
        tools_menu = menubar.addMenu('&Tools')
        open_dir_action = tools_menu.addAction('Open Output Directory')
        open_dir_action.triggered.connect(self.open_reports)
        
        refresh_action = tools_menu.addAction('Refresh System Integrity')
        refresh_action.triggered.connect(self.refresh_integrity)
        
        # Help Menu
        help_menu = menubar.addMenu('&Help')
        manual_action = help_menu.addAction('Mission Manual (README)')
        manual_action.triggered.connect(self.open_manual)
        
        about_action = help_menu.addAction('About / Integrity Audit')
        about_action.triggered.connect(self.show_about)

    def refresh_integrity(self):
        self.tool_hash = get_tool_hash()
        self.lbl_tool_hash.setText(f"INTEGRITY: {self.tool_hash[:32]}...")
        self.log_message(f"[*] Integrity Audit Refreshed: {self.tool_hash}")

    def open_manual(self):
        readme_path = self._resource_root() / "README.md"
        if os.path.exists(readme_path):
            self._open_path(readme_path)
        else:
            QMessageBox.information(self, "Manual", "README.md not found in root directory.")

    def show_about(self):
        about_text = f"""
        <b>Browser Forensic Tool - Elite Edition</b><br><br>
        Version: 2026.1.0 (STABLE)<br>
        Release Date: March 2026<br><br>
        <b>Forensic Integrity (SHA-256):</b><br>
        {self.tool_hash}<br><br>
        <b>Operation Details:</b><br>
        - Investigator: {self.current_user}<br>
        - Machine: {platform.node()}<br>
        - Authorized Jurisdiction: LEA / Enterprise Global
        """
        QMessageBox.about(self, "About Mission Control", about_text)

    def toggle_remote_agent(self):
        if self.cb_remote_agent.isChecked():
            self.remote_agent.start()
            self._set_remote_agent_status("AGENT: STARTING", "#0078d4")
            QTimer.singleShot(300, self._refresh_remote_agent_status)
            self.log_message("[*] Remote Forensic Agent Started (Port 8888)")
        else:
            self.remote_agent.stop()
            self._refresh_remote_agent_status()
            self.log_message("[*] Remote Forensic Agent Stopped")

    def select_directory(self):
        dir_path = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if dir_path:
            self.output_dir = sanitize_path(dir_path)
            self._set_output_dir_label()

    def open_reports(self):
        self._open_path(self.output_dir)

    def apply_elite_styling(self):
        """ Applies a professional enterprise light forensic theme. """
        self.setStyleSheet("""
            QMainWindow, QDialog { 
                background-color: #f5f7fa; 
                color: #201f1e; 
                font-family: 'Segoe UI', Arial;
            }
            
            #HeaderFrame {
                background-color: #ffffff;
                border-bottom: 2px solid #0078d4;
                border-radius: 4px;
            }
            
            QGroupBox { 
                border: 1px solid #d1d1d1; 
                margin-top: 20px; 
                font-weight: bold; 
                color: #005a9e;
                border-radius: 6px;
                padding-top: 15px;
                background-color: #ffffff;
            }
            QGroupBox::title { 
                subcontrol-origin: margin; 
                left: 15px; 
                padding: 0 5px; 
                background-color: #f5f7fa;
            }
            
            QLineEdit, QComboBox { 
                background-color: #ffffff; 
                border: 1px solid #c8c8c8; 
                border-radius: 4px;
                color: #201f1e; 
                padding: 8px; 
            }
            QLineEdit:focus {
                border-color: #0078d4;
            }
            
            QPushButton {
                background-color: #ffffff;
                border: 1px solid #c8c8c8;
                color: #201f1e;
                padding: 8px 15px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #f0f0f0;
                border-color: #0078d4;
            }
            
            #RunButton {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #0078d4, stop:1 #005a9e);
                border: none;
                font-size: 14pt;
                color: white;
            }
            #RunButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #008be2, stop:1 #0078d4);
            }
            #RunButton:disabled {
                background: #e1e1e1;
                color: #999999;
            }
            
            #ReportButton {
                border: 2px solid #107c10;
                color: #107c10;
            }
            #ReportButton:enabled {
                background-color: #e6f4e6;
            }
            
            #ForensicTerminal { 
                background-color: #f8f9fa; 
                color: #003366; 
                font-family: 'Consolas', monospace; 
                border: 1px solid #d1d1d1;
                border-radius: 4px;
                font-size: 10pt;
            }
            
            QProgressBar {
                border: 1px solid #d1d1d1;
                border-radius: 6px;
                text-align: center;
                background-color: #e1e1e1;
                height: 28px;
                color: #201f1e;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: #0078d4;
            }
            
            #StatusMessage {
                color: #107c10;
                font-weight: bold;
                letter-spacing: 1px;
            }
            
            #BadgeLabel {
                color: #d83b01;
                font-weight: bold;
                border: 1px solid #d83b01;
                padding: 2px 8px;
                border-radius: 3px;
            }
            
            QCheckBox { spacing: 8px; color: #444444; }
            QCheckBox::indicator { width: 18px; height: 18px; }
            QCheckBox:hover { color: #000000; }
            
            QLabel { color: #444444; }
        """)

    def browse_image(self):
        fname, _ = QFileDialog.getOpenFileName(self, 'Select Forensic Image', '', "Images (*.dd *.E01 *.img *.iso)")
        if fname:
            self.input_image_path.setText(sanitize_path(fname))

    def detect_mobile(self):
        from collectors.mobile_android import AndroidBrowserCollector
        collector = AndroidBrowserCollector("./")
        devices = collector.list_devices()
        if devices:
            self.mobile_detected = True
            self._set_mobile_status(f"MOBILE: {len(devices)} DEVICE(S) DETECTED ({devices[0]})", "#008800")
        else:
            self.mobile_detected = False
            self._set_mobile_status("MOBILE: NO DEVICE DETECTED", "#aa0000")

    def build_extraction_options(self):
        return {
            "output": self.output_dir,
            "do_chrome": self.cb_chrome.isChecked(),
            "do_firefox": self.cb_firefox.isChecked(),
            "do_edge": self.cb_edge.isChecked(),
            "do_safari": self.cb_safari.isChecked(),
            "do_brave": self.cb_brave.isChecked(),
            "do_opera": self.cb_opera.isChecked(),
            "do_tor": self.cb_tor.isChecked(),
            "quarantine": self.cb_sandbox.isChecked(),
            "deep_recovery": self.cb_deep_recovery.isChecked(),
            "fetch_history": self.cb_history.isChecked(),
            "fetch_cookies": self.cb_cookies.isChecked(),
            "fetch_bookmarks": self.cb_bookmarks.isChecked(),
            "fetch_passwords": self.cb_passwords.isChecked(),
            "fetch_forms": self.cb_forms.isChecked(),
            "fetch_extensions": self.cb_extensions.isChecked(),
            "fetch_sessions": self.cb_sessions.isChecked(),
            "case_id": self.input_case_id.text() or "N/A",
            "investigator": self.input_investigator.text() or "Unknown",
            "evidence_id": self.input_evidence_id.text() or "N/A",
            "warrant_id": self.input_warrant_id.text() or "N/A",
            "jurisdiction": self.input_jurisdiction.text() or "N/A",
            "redact_pii": self.cb_redact_pii.isChecked(),
            "image_path": self.input_image_path.text(),
            "do_mobile": self.mobile_detected,
            "firefox_master_password": self.input_firefox_master_password.text(),
            "analyze_intent": self.cb_intent_analysis.isChecked(),
            "hijack_session": self.cb_hijack_session.isChecked(),
            "fetch_hardware_fingerprint": self.cb_hardware.isChecked(),
            "export_downloads": self.cb_export_downloads.isChecked(),
        }

    def handle_remote_trigger(self, payload):
        self.remote_trigger_signal.emit(payload or {})

    def _handle_remote_trigger_on_ui_thread(self, payload):
        options = self.build_extraction_options()
        payload = payload or {}
        allowed_keys = set(options.keys()) | {"do_all"}

        for key, value in payload.items():
            if key in allowed_keys:
                if key in {"output", "image_path"}:
                    options[key] = sanitize_path(value)
                else:
                    options[key] = value

        self._start_worker(options)

    def log_message(self, message):
        self.console.append(message)
        # Specific progress estimation based on log keywords
        if "Starting Parallel Collection" in message:
            self.progress_bar.setValue(15)
        elif "Collection Phase Complete" in message:
            self.progress_bar.setValue(40)
        elif "Starting Parsing Phase" in message:
            self.progress_bar.setValue(60)
        elif "Initializing Deep Recovery" in message:
            self.progress_bar.setValue(85)
        elif "Analysis Complete" in message:
            self.progress_bar.setValue(100)
            self.lbl_status.setText("Investigation Complete - Reports Ready")
        
        # Auto-scroll to bottom
        scrollbar = self.console.verticalScrollBar()
        scrollbar.setValue(scrollbar.maximum())

    def _start_worker(self, options):
        if hasattr(self, "worker") and self.worker.isRunning():
            self.log_message("[-] Extraction already in progress. Ignoring new request.")
            return

        self.btn_run.setEnabled(False)
        self.btn_run.setText("EXTRACTION IN PROGRESS...")
        self.btn_run.setStyleSheet("background-color: #660000; color: white; font-weight: bold; font-size: 14px;")
        self.lbl_status.setText("EXTRACTION ACTIVE - COLLECTING EVIDENCE")

        self.worker = ExtractionWorker(
            output_dir=options["output"],
            do_chrome=options["do_chrome"],
            do_firefox=options["do_firefox"],
            do_edge=options["do_edge"],
            do_safari=options["do_safari"],
            do_brave=options["do_brave"],
            do_opera=options["do_opera"],
            do_tor=options["do_tor"],
            do_quarantine=options["quarantine"],
            do_deep_recovery=options["deep_recovery"],
            case_id=options["case_id"],
            investigator=options["investigator"],
            evidence_id=options["evidence_id"],
            fetch_history=options["fetch_history"],
            fetch_cookies=options["fetch_cookies"],
            fetch_bookmarks=options["fetch_bookmarks"],
            fetch_passwords=options["fetch_passwords"],
            fetch_forms=options["fetch_forms"],
            fetch_extensions=options["fetch_extensions"],
            fetch_sessions=options["fetch_sessions"],
            warrant_id=options["warrant_id"],
            jurisdiction=options["jurisdiction"],
            redact_pii=options["redact_pii"],
            image_path=sanitize_path(options["image_path"]),
            mobile_detect=options["do_mobile"],
            do_all=options.get("do_all", False),
            firefox_master_password=options.get("firefox_master_password", ""),
            analyze_intent=options.get("analyze_intent", False),
            hijack_session=options.get("hijack_session", False),
            fetch_hardware_fingerprint=options.get("fetch_hardware_fingerprint", True),
            export_downloads=options.get("export_downloads", True)
        )
        self.worker.log_signal.connect(self.log_message)
        self.worker.finished_signal.connect(self.extraction_finished)
        self.worker.start()

    def start_extraction(self):
        # Pre-flight validation
        if not self.input_case_id.text().strip():
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Metadata Required", "Case ID is mandatory for forensic integrity.")
            return
        if not self.input_investigator.text().strip():
            from PyQt5.QtWidgets import QMessageBox
            QMessageBox.warning(self, "Metadata Required", "Investigator name is mandatory for chain of custody.")
            return

        self.console.clear()
        self._start_worker(self.build_extraction_options())

    def extraction_finished(self):
        self.btn_run.setEnabled(True)
        self.btn_run.setText("START MISSION EXTRACTION")
        self.btn_run.setStyleSheet("")
        self.btn_reports.setEnabled(True)
        self.lbl_status.setText("INVESTIGATION COMPLETE - REPORTS VERIFIED")
        self.progress_bar.setValue(100)

def launch_gui():
    app = QApplication(sys.argv)
    app.setApplicationName("Browser Forensics Tool")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("Browser Forensics Tool")

    icon_path = Path(__file__).resolve().parents[1] / "assets" / "browser_forensics_tool.ico"
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        icon_path = Path(sys._MEIPASS) / "assets" / "browser_forensics_tool.ico"
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    login = LoginDialog()
    if login.exec_() == QDialog.Accepted:
        dashboard = ForensicDashboard()
        dashboard.current_user = login.user_data["user"]
        dashboard.current_role = login.user_data["role"]
        dashboard.lbl_user_badge.setText(f"BADGE: {dashboard.current_user} [{dashboard.current_role}]")
        # Pre-fill investigator field in metadata
        dashboard.input_investigator.setText(dashboard.current_user)
        
        dashboard.show()
        sys.exit(app.exec_())
    sys.exit(0)

if __name__ == '__main__':
    launch_gui()
