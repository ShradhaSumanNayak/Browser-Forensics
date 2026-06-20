import datetime
import hmac
import http.server
import ipaddress
import json
import os
import socketserver
import ssl
import threading
from pathlib import Path


class _ThreadedTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


class RemoteForensicAgent:
    """
    Hardened REST API for remote triage and distributed forensic acquisition.
    """

    def __init__(
        self,
        port=8888,
        extraction_callback=None,
        auth_token=None,
        allowed_ips=None,
        tls_cert_path=None,
        tls_key_path=None,
        audit_log_path=None,
        max_payload_bytes=65536,
    ):
        self.port = port
        self.callback = extraction_callback
        self.auth_token = auth_token or os.getenv("REMOTE_AGENT_TOKEN", "")
        self.allowed_ip_specs = allowed_ips or os.getenv("REMOTE_AGENT_ALLOWED_IPS", "127.0.0.1,::1")
        self.tls_cert_path = tls_cert_path or os.getenv("REMOTE_AGENT_TLS_CERT", "")
        self.tls_key_path = tls_key_path or os.getenv("REMOTE_AGENT_TLS_KEY", "")
        self.audit_log_path = Path(audit_log_path or os.getenv("REMOTE_AGENT_AUDIT_LOG", "remote_agent_audit.jsonl"))
        self.max_payload_bytes = max_payload_bytes
        self.server = None
        self.is_running = False
        self._trigger_lock = threading.Lock()
        self.is_extracting = False
        self.thread = None
        self.allowed_networks = self._parse_allowed_ips(self.allowed_ip_specs)
        self.auth_required = bool(self.auth_token)
        self.tls_enabled = bool(self.tls_cert_path and self.tls_key_path)
        self.allowed_payload_keys = {
            "output",
            "do_chrome",
            "do_firefox",
            "do_edge",
            "do_safari",
            "do_brave",
            "do_opera",
            "do_tor",
            "do_all",
            "quarantine",
            "deep_recovery",
            "fetch_history",
            "fetch_cookies",
            "fetch_bookmarks",
            "fetch_passwords",
            "fetch_forms",
            "fetch_extensions",
            "fetch_sessions",
            "case_id",
            "investigator",
            "evidence_id",
            "warrant_id",
            "jurisdiction",
            "redact_pii",
            "image_path",
            "do_mobile",
            "firefox_master_password",
        }

    def _parse_allowed_ips(self, value):
        entries = []
        for raw in str(value or "").split(","):
            item = raw.strip()
            if not item:
                continue
            try:
                entries.append(ipaddress.ip_network(item, strict=False))
            except ValueError:
                try:
                    entries.append(ipaddress.ip_network(f"{item}/32", strict=False))
                except ValueError:
                    try:
                        entries.append(ipaddress.ip_network(f"{item}/128", strict=False))
                    except ValueError:
                        continue
        return entries

    def _is_ip_allowed(self, client_ip):
        try:
            address = ipaddress.ip_address(client_ip)
        except ValueError:
            return False
        return any(address in network for network in self.allowed_networks)

    def _write_audit(self, event):
        try:
            self.audit_log_path.parent.mkdir(parents=True, exist_ok=True)
            with open(self.audit_log_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, default=str) + "\n")
        except Exception:
            pass

    def _wrap_socket(self, httpd):
        if not self.tls_enabled:
            return httpd
        cert_path = Path(self.tls_cert_path)
        key_path = Path(self.tls_key_path)
        if not cert_path.exists() or not key_path.exists():
            self.tls_enabled = False
            return httpd

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
        return httpd

    class Handler(http.server.BaseHTTPRequestHandler):
        server_version = "BrowserForensicsAgent/2026.2"

        def _audit(self, status_code, message, payload_keys=None):
            agent = getattr(self.server, "agent", None)
            if not agent:
                return
            event = {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "client_ip": self.client_address[0],
                "path": self.path,
                "method": self.command,
                "status": status_code,
                "message": message,
                "payload_keys": payload_keys or [],
            }
            agent._write_audit(event)

        def _send_json(self, status_code, payload):
            self.send_response(status_code)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(payload, default=str).encode("utf-8"))

        def _reject(self, status_code, message):
            self._audit(status_code, message)
            self._send_json(status_code, {"error": message})

        def _authorize(self, require_token=False):
            agent = getattr(self.server, "agent", None)
            if not agent:
                self._reject(503, "Agent not configured")
                return False

            if not agent._is_ip_allowed(self.client_address[0]):
                self._reject(403, "Client IP not allowed")
                return False

            if require_token and agent.auth_required:
                provided = self.headers.get("Authorization", "")
                if provided.startswith("Bearer "):
                    provided = provided[7:]
                else:
                    provided = self.headers.get("X-API-Key", "")
                if not provided or not hmac.compare_digest(provided, agent.auth_token):
                    self._reject(401, "Missing or invalid API token")
                    return False
            return True

        def _validate_payload(self, payload):
            agent = getattr(self.server, "agent", None)
            if not isinstance(payload, dict):
                return False, "Payload must be a JSON object"
            unknown = [key for key in payload.keys() if key not in agent.allowed_payload_keys]
            if unknown:
                return False, f"Unsupported payload keys: {', '.join(sorted(unknown))}"
            for key, value in payload.items():
                if isinstance(value, (dict, list)):
                    return False, f"Nested values are not allowed for '{key}'"
            return True, ""

        def log_message(self, format, *args):
            return

        def do_GET(self):
            if self.path != "/status":
                self._reject(404, "Not Found")
                return
            if not self._authorize(require_token=False):
                return

            agent = getattr(self.server, "agent", None)
            payload = {
                "agent": "Active",
                "triage_ready": True,
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "auth_required": agent.auth_required,
                "tls_enabled": agent.tls_enabled,
                "allowed_ips": agent.allowed_ip_specs,
            }
            self._audit(200, "status")
            self._send_json(200, payload)

        def do_POST(self):
            if self.path != "/trigger":
                self._reject(404, "Not Found")
                return
            if not self._authorize(require_token=True):
                return

            agent = getattr(self.server, "agent", None)
            content_length = int(self.headers.get("Content-Length", "0"))
            if content_length <= 0:
                self._reject(400, "Empty payload")
                return
            if content_length > agent.max_payload_bytes:
                self._reject(413, "Payload too large")
                return

            body = self.rfile.read(content_length)
            try:
                payload = json.loads(body.decode("utf-8"))
            except json.JSONDecodeError:
                self._reject(400, "Invalid JSON payload")
                return

            valid, message = self._validate_payload(payload)
            if not valid:
                self._reject(400, message)
                return

            with agent._trigger_lock:
                if agent.is_extracting:
                    self._reject(429, "An extraction is already in progress. Please wait.")
                    return
                agent.is_extracting = True

            callback = getattr(self.server, "agent_callback", None)
            if not callback:
                with agent._trigger_lock:
                    agent.is_extracting = False
                self._reject(503, "No extraction callback configured")
                return

            def _wrapped_callback(payload):
                try:
                    callback(payload)
                finally:
                    with agent._trigger_lock:
                        agent.is_extracting = False

            threading.Thread(target=_wrapped_callback, args=(payload,), daemon=True).start()
            self._audit(202, "trigger_accepted", payload_keys=sorted(payload.keys()))
            self._send_json(202, {"message": "Remote extraction started", "payload_keys": sorted(payload.keys())})

    def start(self):
        if self.is_running:
            return

        def serve():
            try:
                with _ThreadedTCPServer(("", self.port), self.Handler) as httpd:
                    httpd.agent_callback = self.callback
                    httpd.agent = self
                    self.server = self._wrap_socket(httpd)
                    self.is_running = True
                    mode = "HTTPS" if self.tls_enabled else "HTTP"
                    print(f"[*] Remote Forensic Agent listening on port {self.port} ({mode})")
                    httpd.serve_forever()
            except Exception as e:
                print(f"[-] Agent Error: {e}")
            finally:
                self.is_running = False

        self.thread = threading.Thread(target=serve, daemon=True)
        self.thread.start()

    def stop(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            self.is_running = False
            self.server = None
            self.thread = None
            print("[*] Remote Agent stopped.")
