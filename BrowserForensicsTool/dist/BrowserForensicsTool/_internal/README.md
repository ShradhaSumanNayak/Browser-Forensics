# COMPREHENSIVE BROWSER FORENSIC TOOL (ELITE EDITION)

## Mission Overview
The **Comprehensive Browser Forensic Tool** is a mission-critical forensic acquisition and analysis suite designed for Law Enforcement Agencies (LEAs), military investigators, and enterprise security auditing. It provides a robust, tamper-evident, and cross-platform solution for extracting deep-level digital evidence from all major web browsers.

## Key Capabilities (Phase 1-14)
- **Multi-Source Acquisition**: Direct support for live systems, mounted forensic images, native raw disk images (`.dd`, `.img`, `.iso`), segmented E01 images when `pyewf` is available, and Android devices via ADB.
- **Deep Digital Carving**: Byte-level recovery of deleted/uncommitted data from SQLite Sidecar files (`-wal`, `-shm`) and Cache Reconstruction.
- **Enterprise Reporting**: Native generation of NIST DERD, Magnet AXIOM, and unified XLSX Forensic Timelines.
- **Chain of Custody**: Portable ECC-signed forensic custody logs with exported public verification key.
- **AI-Powered Analysis**: Integrated behavioral anomaly detection and real-time Threat Intel (VirusTotal/PhishTank).
- **Remote Triage**: Built-in REST API agent with IP allowlisting, token auth, payload validation, TLS support, and JSONL audit logging.
- **Tactical Security**: Automatic PII Redaction (GDPR/CCPA) and Malware Quarantine into secure Windows Sandbox (.wsb) containers.
- **Cloud Storage Evidence Extraction**: Identifies browser-derived activity for Google Drive, OneDrive/SharePoint, Dropbox, Box, iCloud Drive, MEGA, pCloud, MediaFire, and WeTransfer from history, downloads, bookmarks, sessions, and selected cookies.
- **Deep Browser Storage Extraction**: Collects and parses Local Storage, IndexedDB, Service Worker, Firefox storage, and Safari website data for cloud and session evidence.

## Technical Standards
- **Integrity**: Every extraction is cryptographically hashed (SHA-256) at the moment of capture.
- **Resilience**: Aggressive file-copying logic handles locked artifacts by attempting direct engine-level attachment.
- **Compliance**: Implements RBAC (Role-Based Access Control) for investigator authorization.

## Getting Started
1. **Install runtime dependencies**: `pip install -r requirements.txt`
2. **Optional image support**: install `pytsk3` with `pip install -r requirements-image.txt`; add `pyewf` separately if you need native E01 handling on your platform.
3. **Launch**: Execute `python main_gui.py` for the GUI or `python main.py --all` for CLI collection.
4. **Authenticate**: Log in with authorized Badge/Investigator credentials to activate Chain of Custody.
5. **Configure**: Select target browsers, artifacts, optional mounted/image source, and optional Firefox/Tor master password.
6. **Execute**: Start extraction. The tool will generate evidence copies, CSV/XLSX/PDF reports, custody logs, and hash manifests.

## System Requirements
- **OS**: Windows 10/11 (Preferred for Sandbox support), macOS, or Linux.
- **Privileges**: Administrator/Root access is highly recommended for full disk access.
- **Dependencies**: See `requirements.txt`. Native image parsing additionally uses `pytsk3` and optional `pyewf`.

## Testing
- Install test dependencies with `pip install -r requirements-dev.txt`
- Run `pytest tests`

---
**STABILITY STATUS: ELITE / MISSION-READY**
*Developed for the highest standard of Forensic Engineering.*
