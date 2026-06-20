import sys
from pathlib import Path

from PyQt5.QtGui import QIcon
from PyQt5.QtWidgets import QApplication

from gui.dashboard import LoginDialog, ForensicDashboard


APP_NAME = "Browser Forensics Tool"
APP_VERSION = "1.0.0"
APP_ORGANIZATION = "Browser Forensics Tool"


def _resource_root():
    if getattr(sys, "frozen", False) and hasattr(sys, "_MEIPASS"):
        return Path(sys._MEIPASS)
    return Path(__file__).resolve().parent


def _app_icon_path():
    return _resource_root() / "assets" / "browser_forensics_tool.ico"


if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName(APP_ORGANIZATION)

    icon_path = _app_icon_path()
    if icon_path.exists():
        app.setWindowIcon(QIcon(str(icon_path)))

    login = LoginDialog()
    if login.exec_() == LoginDialog.Accepted:
        dashboard = ForensicDashboard()
        dashboard.current_user = login.user_data["user"]
        dashboard.current_role = login.user_data["role"]
        dashboard.lbl_user_badge.setText(f"BADGE: {dashboard.current_user} [{dashboard.current_role}]")
        dashboard.input_investigator.setText(dashboard.current_user)
        dashboard.show()
        sys.exit(app.exec_())
    else:
        print("[!] Login attempt rejected or cancelled by user.")
        sys.exit(0)
