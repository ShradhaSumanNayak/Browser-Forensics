import os
import argparse
import datetime
import platform
import getpass
import sys
from pathlib import Path

# Collectors
from collectors.chrome import ChromeCollector
from collectors.firefox import FirefoxCollector
from collectors.edge import EdgeCollector
from collectors.safari import SafariCollector
from collectors.brave import BraveCollector
from collectors.opera import OperaCollector
from collectors.tor import TorCollector
from collectors.cloud_sync import CloudSyncCollector
from collectors.mobile_android import AndroidBrowserCollector
from utils.disk_imager import DiskImager

# Parsers
from parsers.history_parser import HistoryParser
from parsers.cookies_parser import CookiesParser
from parsers.downloads_parser import DownloadsParser
from parsers.bookmarks_parser import BookmarksParser
from parsers.passwords_parser import PasswordsParser
from parsers.form_parser import FormParser
from parsers.extensions_parser import ExtensionsParser
from parsers.session_parser import SessionParser
from parsers.recovery_parser import RecoveryParser
from parsers.cache_reconstructor import CacheReconstructor
from parsers.cloud_sync_parser import CloudSyncParser
from parsers.cloud_storage_parser import CloudStorageParser
from parsers.browser_storage_parser import BrowserStorageParser
from parsers.service_worker_parser import ServiceWorkerParser

# Reporters & Utils
from reports.csv_report import CSVReportGenerator
from reports.pdf_report import PDFReportGenerator
from reports.timeline_generator import TimelineGenerator
from utils.sandboxer import WindowsSandboxGenerator
from utils.byte_carver import ByteCarver
from utils.integrity import get_tool_hash, verify_environment
from utils.io_helper import sanitize_path, export_physical_downloads
from utils.chain_of_custody import log_custody_event
from utils.pii_redactor import PIIRedactor
from utils.threat_intel import AnomalyDetector, ThreatIntel
from utils.cms_exporter import CMSExporter
from utils.llm_analyzer import LLMIntentAnalyzer
from utils.session_hijacker import SessionHijackerTheForge
from parsers.permissions_parser import PermissionsParser
from parsers.browser_detection import detect_browser, is_chromium, is_firefox_family


def _build_image_artifact_prefix(browser_key, profile_path):
    profile_path = Path(profile_path)
    parts = list(profile_path.parts)
    lowered = [part.lower() for part in parts]

    owner = "unknown"
    if "users" in lowered:
        idx = lowered.index("users")
        if idx + 1 < len(parts):
            owner = parts[idx + 1]
    elif "home" in lowered:
        idx = lowered.index("home")
        if idx + 1 < len(parts):
            owner = parts[idx + 1]
    elif len(parts) >= 2:
        owner = parts[-2]

    raw_prefix = f"{browser_key}_{owner}_{profile_path.name}"
    safe_prefix = "".join(char.lower() if char.isalnum() else "_" for char in raw_prefix)
    while "__" in safe_prefix:
        safe_prefix = safe_prefix.replace("__", "_")
    return safe_prefix.strip("_")


def execute_extraction(output=None, do_chrome=False, do_firefox=False, do_edge=False, do_safari=False,
                       do_brave=False, do_opera=False, do_tor=False, do_all=False,
                       do_cloud_sync=False,
                       quarantine=True, deep_recovery=False,
                       fetch_history=True, fetch_cookies=True, fetch_bookmarks=True,
                       fetch_passwords=True, fetch_forms=True, fetch_extensions=True,
                       fetch_sessions=True, logger_callback=None,
                       case_id="N/A", investigator="Unknown", evidence_id="N/A",
                       warrant_id="N/A", jurisdiction="N/A", redact_pii=False,
                       image_path="", do_mobile=False, firefox_master_password="",
                       analyze_intent=False, hijack_session=False, hijack_confirm=False, allow_threat_intel=False,
                       fetch_hardware_fingerprint=True, export_downloads=True):
    def log(msg):
        if logger_callback:
            logger_callback(msg)
        print(msg)

    # Setup Directories
    if output is None:
        output_dir = Path(os.path.join(get_desktop_path(), "forensics_output"))
    else:
        sanitized_output = sanitize_path(output)
        if not sanitized_output:
            log("[-] Error: Invalid or unsafe output directory specified.")
            return False
        output_dir = Path(sanitized_output)

    sanitized_image_path = sanitize_path(image_path)
    if image_path and not sanitized_image_path:
        log("[-] Error: Invalid or unsafe image path specified.")
        return False
    image_path = sanitized_image_path

    if not str(output_dir):
        log("[-] Error: Invalid or unsafe output directory specified.")
        return False
    output_dir.mkdir(parents=True, exist_ok=True)
    evidence_dir = output_dir / "extracted_databases"
    evidence_dir.mkdir(parents=True, exist_ok=True)
    reports_dir = output_dir / "reports"
    reports_dir.mkdir(parents=True, exist_ok=True)
    (evidence_dir / "hash_manifest.txt").write_text("", encoding="utf-8")

    log("\n" + "="*60)
    log("      COMPREHENSIVE BROWSER FORENSIC TOOL      ")
    log("="*60 + "\n")

    if not (do_chrome or do_firefox or do_edge or do_safari or do_brave or do_opera or do_tor or do_all):
        log("[-] Error: Please specify at least one browser to analyze.")
        return False

    # 0. Start Forensic Audit Log & Integrity Check
    execution_start = datetime.datetime.now(datetime.timezone.utc)
    tool_self_hash = get_tool_hash()
    env_info = verify_environment()
    
    audit_log_path = output_dir / "forensic_execution_log.txt"
    with open(audit_log_path, "a", encoding="utf-8") as audit:
        audit.write("="*60 + "\n")
        audit.write("FORENSIC TOOL EXECUTION AUDIT LOG (LEA-Standard)\n")
        audit.write(f"Timestamp (UTC): {execution_start}\n")
        audit.write(f"Investigator: {investigator}\n")
        audit.write(f"Case ID: {case_id} | Evidence ID: {evidence_id}\n")
        audit.write(f"Executing Machine User: {getpass.getuser()}\n")
        audit.write(f"Tool Self-Integrity (SHA-256): {tool_self_hash}\n")
        audit.write(f"Admin Privileges: {env_info['is_admin']}\n")
        audit.write(f"Operating System: {platform.system()} {platform.release()} ({platform.version()})\n")
        audit.write(f"Execution Command: {' '.join(sys.argv)}\n")
        audit.write(f"Warrant ID: {warrant_id}\n")
        audit.write(f"Jurisdiction: {jurisdiction}\n")
        audit.write("="*60 + "\n\n")
        audit.write("[*] Collection Phase Started\n")

    custody_log_path = output_dir / "chain_of_custody_signed.jsonl"

    # Initial Chain of Custody Log
    log_custody_event(custody_log_path, 
                      "Investigation Started", 
                      f"Collection initialized for {', '.join([b for b, v in {'Chrome': do_chrome, 'Firefox': do_firefox, 'Edge': do_edge, 'Safari': do_safari, 'Brave': do_brave, 'Opera': do_opera, 'Tor': do_tor}.items() if v])}",
                      investigator=investigator)

    # 1. Collection Phase
    import concurrent.futures
    log("\n[*] Starting Parallel Collection Phase...")

    image_source_root = None
    discovered_profiles = {}

    # Image Acquisition
    if image_path:
        log(f"[*] Analyzing Forensic Image: {image_path}")
        imager = DiskImager(logger_callback=log, workspace_root=output_dir / "_image_materialized")
        imager.ingest_raw_image(image_path)
        image_source_root = imager.prepare_source_root(image_path)
        if image_source_root:
            discovered_profiles = imager.discover_browser_profiles(image_source_root)
            discovered_count = sum(len(paths) for paths in discovered_profiles.values())
            log(f"[*] Image profile discovery complete. Found {discovered_count} profile path(s).")
        else:
            log("[-] Unable to mount or use the provided image path as a source root. Aborting to avoid live-host contamination.")
            with open(audit_log_path, "a", encoding="utf-8") as audit:
                audit.write("[!] Image preparation failed. Extraction aborted before live collection.\n")
            log_custody_event(
                custody_log_path,
                "Investigation Aborted",
                f"Image source preparation failed for {image_path}",
                investigator=investigator,
            )
            return False

    collectors = []

    def add_collectors(enabled, browser_key, collector_cls):
        if not enabled:
            return

        if image_source_root:
            profiles = discovered_profiles.get(browser_key, [])
            if browser_key == "firefox":
                if profiles:
                    collectors.append(FirefoxCollector(evidence_dir, profile_paths=profiles))
                else:
                    log(f"    [-] No {browser_key} profiles discovered in mounted image.")
                return

            if profiles:
                for profile in profiles:
                    collectors.append(
                        collector_cls(
                            evidence_dir,
                            profile_path=profile,
                            artifact_prefix=_build_image_artifact_prefix(browser_key, profile),
                        )
                    )
            else:
                log(f"    [-] No {browser_key} profiles discovered in mounted image.")
        else:
            if browser_key == "firefox":
                collectors.append(FirefoxCollector(evidence_dir))
            else:
                collectors.append(collector_cls(evidence_dir))

    add_collectors(do_chrome or do_all, "chrome", ChromeCollector)
    add_collectors(do_firefox or do_all, "firefox", FirefoxCollector)
    add_collectors(do_edge or do_all, "edge", EdgeCollector)
    add_collectors(do_safari or do_all, "safari", SafariCollector)
    add_collectors(do_brave or do_all, "brave", BraveCollector)
    add_collectors(do_opera or do_all, "opera", OperaCollector)
    add_collectors(do_tor or do_all, "tor", TorCollector)

    # Cloud Sync Artifacts
    if do_cloud_sync:
        log("[*] Initializing Cloud Sync Collector...")
        collectors.append(CloudSyncCollector(evidence_dir, source_root=image_source_root))

    # Mobile Acquisition
    if do_mobile:
        log("[*] Initializing Mobile Forensic Acquisition (Android)...")
        mobile = AndroidBrowserCollector(evidence_dir, logger_callback=log)
        mobile.collect()

    def run_collector(collector):
        try:
            if collector.collect():
                # For simplicity, we'll re-glob later to get the definitive list
                return True
        except Exception as e:
            log(f"    [-] Error running {collector.__class__.__name__}: {e}")
        return False

    with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(collectors), 8) or 1) as executor:
        executor.map(run_collector, collectors)

    # Definitive list of all successfully collected artifact files
    collected_entries = list(evidence_dir.glob("*"))
    collected_files = [f for f in collected_entries if f.is_file()]
    collected_dirs = [f for f in collected_entries if f.is_dir()]
    
    log(f"[+] Collection Phase Complete. Found {len(collected_files)} artifacts.")

    if audit_log_path:
        with open(audit_log_path, "a", encoding="utf-8") as audit:
            audit.write(f"[*] Collection Phase Complete. Total artifacts: {len(collected_files)}\n")
            audit.write("[*] Moving to Parsing Phase...\n\n")

    # 2. Parsing Phase
    log("\n[*] Starting Parsing Phase...")

    all_history = []
    all_cookies = []
    all_downloads = []
    all_bookmarks = []
    all_passwords = []
    all_forms = []
    all_extensions = []
    all_sessions = []
    all_cloud_sync = []
    all_cloud_storage = []
    all_browser_storage = []
    all_service_workers = []
    all_hardware_fingerprints = []

    for db_file in collected_files:
        if db_file.exists():
            name = db_file.name.lower()
            browser_key = detect_browser(db_file.name)

            # Skip WAL and SHM files during primary parsing (they are for recovery)
            if name.endswith("-wal") or name.endswith("-shm"):
                continue

            # History
            should_parse_history = (
                (is_chromium(browser_key) and "history" in name)
                or (is_firefox_family(browser_key) and "places" in name)
                or (browser_key == "safari" and name.endswith("history.db"))
            )
            if should_parse_history and fetch_history:
                log(f"    -> Parsing History from {name}...")
                hp = HistoryParser(db_file)
                all_history.extend(hp.parse())

            # Cookies
            if "cookie" in name and fetch_cookies:
                log(f"    -> Parsing Cookies from {name}...")
                cp = CookiesParser(db_file)
                all_cookies.extend(cp.parse())

            # Bookmarks
            should_parse_bookmarks = (
                ("bookmark" in name and browser_key in {"chrome", "edge", "brave", "opera", "safari"})
                or (is_firefox_family(browser_key) and "places" in name)
            )
            if should_parse_bookmarks and fetch_bookmarks:
                log(f"    -> Parsing Bookmarks from {name}...")
                bp = BookmarksParser(db_file)
                all_bookmarks.extend(bp.parse())

            # Passwords (Login Data)
            if ("login_data" in name or name.endswith("logins.json")) and fetch_passwords:
                log(f"    -> Parsing Password Artifacts from {name}...")
                local_state_path = None
                key_db_path = None

                if "login_data" in name:
                    if db_file.name.endswith("_login_data.sqlite"):
                        local_state_name = db_file.name[:-len("_login_data.sqlite")] + "_local_state.json"
                    else:
                        local_state_name = f"{name.split('_')[0]}_local_state.json"
                    local_state_path = evidence_dir / local_state_name
                else:
                    key_db_name = db_file.name.replace("logins.json", "key4.db")
                    key_db_path = evidence_dir / key_db_name
                    if not key_db_path.exists():
                        key_db_path = evidence_dir / db_file.name.replace("logins.json", "key3.db")

                pp = PasswordsParser(
                    db_file,
                    local_state_path=local_state_path,
                    key_db_path=key_db_path,
                    master_password=firefox_master_password,
                )
                all_passwords.extend(pp.parse())

            # Forms / Autofill (Web Data or formhistory)
            if ("autofill" in name or "formhistory" in name or "web_data" in name) and fetch_forms:
                log(f"    -> Parsing Forms/Autofill from {name}...")
                fp = FormParser(db_file)
                all_forms.extend(fp.parse())

            # Extensions (Preferences or addons.json)
            if ("preferences" in name or "addons" in name) and fetch_extensions:
                log(f"    -> Parsing Extensions from {name}...")
                ep = ExtensionsParser(db_file)
                all_extensions.extend(ep.parse())

            # Sessions (Session, Tabs, or jsonlz4)
            if any(k in name for k in ["session", "tabs", "jsonlz4"]) and fetch_sessions:
                log(f"    -> Parsing Session/Tabs from {name}...")
                sp = SessionParser(db_file)
                all_sessions.extend(sp.parse())

            # Cloud Sync / Cross-Device artifacts
            if any(k in name for k in ["sync_data", "sync_state", "cloud_tabs", "synced_rules"]):
                log(f"    -> Parsing Cloud Sync artifact from {name}...")
                csp = CloudSyncParser(db_file)
                all_cloud_sync.extend(csp.parse())

            # Downloads (Chromium/Firefox/Safari)
            should_parse_downloads = (
                (is_chromium(browser_key) and "history" in name)
                or (is_firefox_family(browser_key) and "places" in name)
                or name.endswith("downloads.plist")
            )
            if should_parse_downloads:
                log(f"    -> Parsing Downloads from {name}...")
                dp = DownloadsParser(db_file)
                all_downloads.extend(dp.parse())


    for artifact_dir in collected_dirs:
        name = artifact_dir.name.lower()
        if any(token in name for token in ["sync_data", "sync_state", "cloud_tabs", "synced_rules"]):
            log(f"    -> Parsing Cloud Sync artifact directory from {name}...")
            csp = CloudSyncParser(artifact_dir)
            all_cloud_sync.extend(csp.parse())

    cloud_storage_parser = CloudStorageParser()

    for artifact_dir in collected_dirs:
        name = artifact_dir.name.lower()
        
        if fetch_hardware_fingerprint and any(k in name for k in ["default", "profile", "webrtc"]):
            log(f"    -> Parsing Hardware Permissions from {name}...")
            pp = PermissionsParser(artifact_dir)
            all_hardware_fingerprints.extend(pp.parse())
            
        if not any(token in name for token in ["local_storage", "indexeddb", "service_worker", "browser_storage", "website_data"]):
            continue
        
        # Split Service Worker parsing from general browser storage parsing for precision
        if "service_worker" in name or "serviceworker" in name:
            log(f"    -> Parsing Ghost Sessions from {name}...")
            sw_parser = ServiceWorkerParser(artifact_dir)
            all_service_workers.extend(sw_parser.parse())
            
        log(f"    -> Parsing Browser Storage from {name}...")
        bsp = BrowserStorageParser(artifact_dir)
        all_browser_storage.extend(bsp.parse())

    all_cloud_storage = cloud_storage_parser.parse(
        history_records=all_history,
        download_records=all_downloads,
        bookmark_records=all_bookmarks,
        cookie_records=all_cookies,
        session_records=all_sessions,
        storage_records=all_browser_storage,
    )

    # 2.5 Optional Deep Recovery (Phase 4)
    all_recovered = []
    if deep_recovery:
        log("\n[*] Initializing Deep Recovery (Data Carving)...")
        
        # 1. WAL/SHM Carving and File Scavenging
        carver = ByteCarver(reports_dir / "recovered_files", logger_callback=log)
        for db_file in list(evidence_dir.glob("*")):
            name = db_file.name.lower()
            if name.endswith("-wal") or name.endswith("-shm"):
                # Carve strings/rows
                rp = RecoveryParser(db_file)
                carved_strings = rp.parse()
                if carved_strings:
                    log(f"    -> [!] Carved {len(carved_strings)} item(s) from {name}")
                    all_recovered.extend(carved_strings)
                
                # Carve physical files (scavenge JPG/PDF etc from WAL remnants)
                log(f"    -> [!] Scavenging raw files from {name}...")
                carved_files = carver.carve_file(db_file)
                if carved_files:
                    log(f"        [+] Scavenged {len(carved_files)} physical file fragments from {name}")
                    all_recovered.extend(carved_files)

        # Cache Reconstruction: scan evidence dir for cache data directories
        for cache_dir in evidence_dir.iterdir():
            name = cache_dir.name.lower()
            if "cache_data" in name and cache_dir.is_dir():
                log(f"    -> [!] Attempting Cache Reconstruction for {name}...")
                reconstruction_dir = reports_dir / "reconstructed_cache" / name.replace("_cache_data", "")
                cr = CacheReconstructor(cache_dir, reconstruction_dir)
                count = cr.reconstruct()
                if count > 0:
                    log(f"        [+] Successfully recovered {count} files from {name}")
                    all_recovered.append({
                        "Category": "Reconstructed Cache",
                        "Source File": name,
                        "Data": f"Extracted {count} files (Images/Docs) to reports/reconstructed_cache/",
                        "Confidence": "High"
                    })
                else:
                    log(f"        [-] No recognizable file signatures in cache for {name}")


    # 3. Reporting Phase
    log("\n[*] Generating Multi-Artifact CSV Reports...")
    redactor = PIIRedactor()
    csv_reporter = CSVReportGenerator(reports_dir)

    def process_data(data):
        if redact_pii:
            return redactor.redact_dict(data)
        return data

    if all_history:
        all_history.sort(key=lambda x: str(x.get("Last Visit Time", "")), reverse=True)
        csv_reporter.generate_report(process_data(all_history), "1_Browser_History.csv")

    if all_downloads:
        all_downloads.sort(key=lambda x: str(x.get("Start Time", "")), reverse=True)
        csv_reporter.generate_report(process_data(all_downloads), "2_Downloads.csv")

    if all_cookies:
        csv_reporter.generate_report(process_data(all_cookies), "3_Cookies.csv")

    if all_bookmarks:
        csv_reporter.generate_report(process_data(all_bookmarks), "4_Bookmarks.csv")

    if all_passwords:
        csv_reporter.generate_report(process_data(all_passwords), "5_Password_Artifacts.csv")

    if all_forms:
        csv_reporter.generate_report(process_data(all_forms), "6_Form_Autofill_Data.csv")

    if all_extensions:
        csv_reporter.generate_report(process_data(all_extensions), "7_Installed_Extensions.csv")

    if all_sessions:
        csv_reporter.generate_report(process_data(all_sessions), "8_Session_Tabs.csv")

    if all_recovered:
        all_recovered.sort(key=lambda x: x.get("Category", ""))
        csv_reporter.generate_report(process_data(all_recovered), "9_Recovered_Deleted_Data.csv")

    if all_cloud_sync:
        csv_reporter.generate_report(process_data(all_cloud_sync), "10_Cloud_Sync_Artifacts.csv")

    if all_browser_storage:
        csv_reporter.generate_report(process_data(all_browser_storage), "13_Browser_Storage_Artifacts.csv")

    if all_cloud_storage:
        csv_reporter.generate_report(process_data(all_cloud_storage), "14_Cloud_Storage_Artifacts.csv")

    # 3.1 AI Intent Reconstruction (Local LLM) - Position 15
    if analyze_intent and all_history:
        log("\n[*] Initializing Local LLM for Intent Reconstruction...")
        analyzer = LLMIntentAnalyzer(logger_callback=log)
        intent_results = analyzer.analyze_timeline(all_history)
        if not intent_results:
             # Create a placeholder indicating no sessions met the criteria
             intent_results = [{
                 "Session Start": "N/A",
                 "Session End": "N/A",
                 "URLs Visited": 0,
                 "Reconstructed Intent": "Insufficient browsing history density to reconstruct intent for this period."
             }]
        csv_reporter.generate_report(intent_results, "15_Intent_Analysis_Report.csv")

    if all_service_workers:
        csv_reporter.generate_report(process_data(all_service_workers), "16_Ghost_Sessions.csv")

    if all_hardware_fingerprints:
        csv_reporter.generate_report(process_data(all_hardware_fingerprints), "17_Hardware_Fingerprints.csv")

    # Generate XLSX Super Timeline
    if any([all_history, all_downloads, all_cookies, all_passwords, all_bookmarks, all_forms]):
         log("\n[*] Generating Forensic Super-Timeline (XLSX)...")
         timeline = TimelineGenerator(reports_dir)
         if all_history:
             timeline.ingest_history(process_data(all_history))
         if all_cookies:
             timeline.ingest_cookies(process_data(all_cookies))
         if all_downloads:
             timeline.ingest_downloads(process_data(all_downloads))
         if all_passwords:
             timeline.ingest_passwords(process_data(all_passwords))
         if all_bookmarks:
             timeline.ingest_bookmarks(process_data(all_bookmarks))
         if all_forms:
             timeline.ingest_forms(process_data(all_forms))

         outfile = timeline.export_timeline()
         if outfile:
              log(f"[+] Successfully generated Super Timeline: {outfile}")

    # 3.2 Automated Session Hijacking ("Golden Ticket")
    if hijack_session and all_cookies:
        log("\n[*] Building Cryptographic Spoofed Session Containers...")
        hijacker = SessionHijackerTheForge(output_dir, logger_callback=log)
        # Attempt to build a session for the first major profile found.
        # Could loop over multiple if needed, but we'll aggregate cookies into one giant forensic profile for convenience.
        hijacker.create_hijacked_session("Target_Default", all_cookies, confirm=hijack_confirm)

    # 3.5 AI Anomaly Detection & Threat Intel
    if all_history:
        log("\n[*] Running AI Anomaly Detection...")
        detector = AnomalyDetector()
        anomalies = detector.analyze_history(all_history)
        if anomalies:
            log(f"    -> [!] ALERT: Detected {len(anomalies)} behavioral anomalies.")
            csv_reporter.generate_report(anomalies, "11_Behavioral_Anomalies.csv")
            
            with open(audit_log_path, "a", encoding="utf-8") as audit:
                audit.write(f"[*] AI Anomaly Analysis: Found {len(anomalies)} high-risk patterns.\n")
                for a in anomalies[:10]: # Log first 10 for audit
                    audit.write(f"    - {a['Type']}: {a['Evidence']}\n")

        log("\n[*] Running Threat Intel URL Checks...")
        if allow_threat_intel:
            vt_api_key = os.getenv("VT_API_KEY")
            if vt_api_key:
                threat_intel = ThreatIntel(vt_api_key=vt_api_key)
                threat_results = []
                unique_urls = []
                seen_urls = set()
                for entry in anomalies if anomalies else all_history:
                    url = entry.get("Evidence") if "Evidence" in entry else entry.get("URL")
                    if url and url not in seen_urls:
                        seen_urls.add(url)
                        unique_urls.append(url)
                    if len(unique_urls) >= 25:
                        break

                for url in unique_urls:
                    vt_result = threat_intel.check_url_vt(url)
                    threat_results.append({
                        "URL": url,
                        "Status": vt_result.get("status", "unknown"),
                        "Malicious": vt_result.get("malicious", ""),
                        "Suspicious": vt_result.get("suspicious", ""),
                        "Harmless": vt_result.get("harmless", ""),
                        "Undetected": vt_result.get("undetected", ""),
                        "Last Analysis": vt_result.get("last_analysis_date", ""),
                    })

                if threat_results:
                    csv_reporter.generate_report(threat_results, "12_Threat_Intel.csv")
                    log(f"    [+] Threat Intel results written for {len(threat_results)} URL(s).")
            else:
                log("    [-] VT_API_KEY not configured; skipping VirusTotal lookups.")
        else:
            log("    [-] Threat Intel skipped. Enable it explicitly with --threat-intel and set VT_API_KEY.")

    # 3.6 CMS Interoperability Export (Phase 11)
    log("\n[*] Generating Enterprise CMS/NIST Interchange Packages...")
    exporter = CMSExporter(reports_dir)
    if all_history:
        exporter.export_to_nist__derd(all_history)
        exporter.export_for_axiom(all_history)
        log("    [+] Exported CMS-compatible packages to reports/cms_export/")

    # Malware Sandbox / Quarantine (Optional)
    if quarantine and all_downloads:
        log("\n[*] Initializing Malware Sandbox & Quarantine Protocol...")
        sandbox = WindowsSandboxGenerator(output_dir, logger_callback=log)
        isolated_count = sandbox.quarantine_downloads(all_downloads)

        if isolated_count > 0:
             sandbox.generate_wsb()
             log(f"    -> [!] Extracted {isolated_count} suspect files to Quarantine.")
        else:
             log("    -> No physical downloads found on disk to quarantine.")
             
    # Export all Physical Downloads
    if export_downloads and all_downloads:
        log("\n[*] Exporting Physical Downloaded Documents...")
        exported_count = export_physical_downloads(all_downloads, output_dir, logger_callback=log)
        if exported_count > 0:
            log(f"    [+] Successfully copied {exported_count} physical documents to exported_downloads/")
        else:
            log("    [-] No target files existed on disk to copy.")

    # PDF Executive Summary
    log("\n[*] Generating Professional PDF Report...")
    pdf_reporter = PDFReportGenerator(reports_dir)
    stats = {
        "History Records": len(all_history),
        "Live Cookies": len(all_cookies),
        "Downloads": len(all_downloads),
        "Bookmarks": len(all_bookmarks),
        "Password Records": len(all_passwords),
        "Form Entries": len(all_forms),
        "Extensions": len(all_extensions),
        "Active Session URLs": len(all_sessions),
        "Cloud Sync Records": len(all_cloud_sync),
        "Browser Storage Records": len(all_browser_storage),
        "Cloud Storage Events": len(all_cloud_storage),
        "Ghost Sessions": len(all_service_workers),
        "Hardware Fingerprints": len(all_hardware_fingerprints),
    }
    manifest_path = evidence_dir / "hash_manifest.txt"
    pdf_reporter.generate_executive_summary(
        "Forensic_Executive_Summary.pdf", 
        execution_start, 
        stats, 
        manifest_path,
        case_id=case_id,
        investigator=investigator,
        evidence_id=evidence_id,
        warrant_id=warrant_id,
        jurisdiction=jurisdiction,
        audit_log_path=audit_log_path,
        custody_log_path=custody_log_path,
    )

    # Final Chain of Custody Log
    log_custody_event(custody_log_path, 
                      "Investigation Finalized", 
                      f"Reporting complete. Total artifacts: {len(collected_files)}", 
                      investigator=investigator)

    # Finalize Audit log
    execution_end = datetime.datetime.now(datetime.timezone.utc)
    with open(audit_log_path, "a", encoding="utf-8") as audit:
        audit.write(f"\n[*] Parsing and Reporting Complete at {execution_end}\n")
        audit.write(f"    Total History Records: {len(all_history)}\n")
        audit.write(f"    Total Cookies Extracted: {len(all_cookies)}\n")
        audit.write(f"    Total Downloads Extracted: {len(all_downloads)}\n")
        audit.write(f"    Total Bookmarks Extracted: {len(all_bookmarks)}\n")
        audit.write(f"    Total Password Records: {len(all_passwords)}\n")
        audit.write(f"    Total Form Entries: {len(all_forms)}\n")
        audit.write(f"    Total Extensions: {len(all_extensions)}\n")
        audit.write(f"    Total Session URLs: {len(all_sessions)}\n")
        audit.write(f"    Total Cloud Sync Records: {len(all_cloud_sync)}\n")
        audit.write(f"    Total Browser Storage Records: {len(all_browser_storage)}\n")
        audit.write(f"    Total Cloud Storage Events: {len(all_cloud_storage)}\n")
        audit.write(f"    Total Ghost Sessions: {len(all_service_workers)}\n")
        audit.write(f"    Total Hardware Fingerprints: {len(all_hardware_fingerprints)}\n")
        audit.write("="*60 + "\n")

    log("\n[+] Analysis Complete!")
    log(f"[+] Output Directory: {output_dir.absolute()}")
    return True

def get_desktop_path():
    """ Dynamically finds the true desktop folder even if OneDrive is hijacking it. """
    onedrive_desktop = Path.home() / "OneDrive" / "Desktop"
    if onedrive_desktop.exists():
        return str(onedrive_desktop)
    return str(Path.home() / "Desktop")

def main():
    parser = argparse.ArgumentParser(description="Comprehensive Browser Forensic Tool")
    default_out = os.path.join(get_desktop_path(), "forensics_output")
    parser.add_argument("-o", "--output", default=default_out, help="Output directory")
    parser.add_argument("--chrome", action="store_true", help="Extract Chrome")
    parser.add_argument("--firefox", action="store_true", help="Extract Firefox")
    parser.add_argument("--edge", action="store_true", help="Extract Edge")
    parser.add_argument("--safari", action="store_true", help="Extract Safari")
    parser.add_argument("--brave", action="store_true", help="Extract Brave")
    parser.add_argument("--opera", action="store_true", help="Extract Opera")
    parser.add_argument("--tor", action="store_true", help="Extract Tor")
    parser.add_argument("--all", action="store_true", help="Extract from all")
    parser.add_argument("--quarantine", action="store_true", default=True, help="Quarantine physical downloads into sandbox (Default: True) generate detonatable Windows Sandbox (.wsb)")
    parser.add_argument("--no-quarantine", action="store_false", dest="quarantine", help="Disable sandbox quarantine")
    parser.add_argument("--cloud-sync", action="store_true", default=False, help="Enable cloud sync artifact collection")
    parser.add_argument("--threat-intel", action="store_true", default=False, help="Enable VirusTotal threat intelligence lookups when VT_API_KEY is configured")
    parser.add_argument("--deep-recovery", action="store_true", help="Enable byte-carving of WAL/SHM and Cache reconstruction (Slow)")
    parser.add_argument("--image", default="", help="Mounted directory or image file to analyze")
    parser.add_argument("--mobile", action="store_true", help="Attempt Android ADB acquisition")
    parser.add_argument("--firefox-master-password", default="", help="Optional Firefox/Tor master password for NSS login decryption")
    parser.add_argument("--case-id", default="N/A", help="Forensic Case Identifier")
    parser.add_argument("--investigator", default="Unknown", help="Investigator Name")
    parser.add_argument("--evidence-id", default="N/A", help="Evidence Identifier")
    parser.add_argument("--warrant-id", default="N/A", help="Authorized Warrant ID")
    parser.add_argument("--jurisdiction", default="N/A", help="Legal Jurisdiction")
    parser.add_argument("--redact-pii", action="store_true", help="Enable PII Redaction for privacy compliance")
    parser.add_argument("--intent", action="store_true", help="Enable Local LLM behavioral intent reconstruction summary based on chronological history.")
    parser.add_argument("--hijack-session", action="store_true", help="Generate an executable Cryptographic Spoofed Session profile from extracted cookies.")
    parser.add_argument("--confirm-hijack", action="store_true", default=False, help="Explicitly confirm programmatic creation of hijacked session containers (required to enable --hijack-session).")
    parser.add_argument("--hardware-fingerprint", action="store_true", default=True, help="Extract WebRTC leaks and hardware permissions (Camera/Mic).")

    # Granular Artifact Flags (Enabled by default)
    parser.add_argument("--no-history", action="store_false", dest="history", help="Skip history extraction")
    parser.add_argument("--no-cookies", action="store_false", dest="cookies", help="Skip cookies extraction")
    parser.add_argument("--no-bookmarks", action="store_false", dest="bookmarks", help="Skip bookmarks extraction")
    parser.add_argument("--no-passwords", action="store_false", dest="passwords", help="Skip passwords extraction")
    parser.add_argument("--no-forms", action="store_false", dest="forms", help="Skip forms/autofill extraction")
    parser.add_argument("--no-extensions", action="store_false", dest="extensions", help="Skip extension analysis")
    parser.add_argument("--no-sessions", action="store_false", dest="sessions", help="Skip session reconstruction")
    parser.set_defaults(history=True, cookies=True, bookmarks=True, passwords=True, forms=True, extensions=True, sessions=True)

    args = parser.parse_args()

    # Auto-fallback: if no browser flags are set, run them all
    if not any([args.chrome, args.firefox, args.edge, args.safari, args.brave, args.opera, args.tor, args.all]):
        args.all = True

    execute_extraction(output=args.output, do_chrome=args.chrome, do_firefox=args.firefox,
                       do_edge=args.edge, do_safari=args.safari, do_brave=args.brave,
                       do_opera=args.opera, do_tor=args.tor, do_all=args.all,
                       quarantine=args.quarantine, deep_recovery=args.deep_recovery,
                       fetch_history=args.history, fetch_cookies=args.cookies,
                       fetch_bookmarks=args.bookmarks, fetch_passwords=args.passwords,
                       fetch_forms=args.forms, fetch_extensions=args.extensions,
                       fetch_sessions=args.sessions,
                       case_id=args.case_id, investigator=args.investigator, evidence_id=args.evidence_id,
                       warrant_id=args.warrant_id, jurisdiction=args.jurisdiction, redact_pii=args.redact_pii,
                       image_path=args.image, do_mobile=args.mobile,
                       firefox_master_password=args.firefox_master_password,
                       analyze_intent=args.intent, hijack_session=args.hijack_session, hijack_confirm=args.confirm_hijack,
                       do_cloud_sync=args.cloud_sync,
                       allow_threat_intel=args.threat_intel,
                       fetch_hardware_fingerprint=args.hardware_fingerprint)

if __name__ == "__main__":
    main()

