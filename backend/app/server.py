"""
FraudNexus Integrated Server
Provides zero-dependency, lightning-fast HTTP API and Dashboard service.
Runs out of the box with standard Python 3.13 without needing external packages!
"""

import http.server
import json
import urllib.parse
from pathlib import Path
from typing import Dict, Any

from .api import handler

PORT = 8000
FRONTEND_DIR = Path(__file__).resolve().parent.parent.parent / "frontend"

class FraudNexusRequestHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Cache-Control", "no-cache, no-store, must-revalidate")
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def send_json(self, status_code: int, data: Dict[str, Any]):
        response_bytes = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status_code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response_bytes)))
        self.end_headers()
        self.wfile.write(response_bytes)

    def read_json_body(self) -> Dict[str, Any]:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > 0:
            raw_body = self.rfile.read(content_length).decode("utf-8")
            try:
                return json.loads(raw_body)
            except Exception:
                return {}
        return {}

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        parts = path.split("/")[1:]  # e.g. ['api', 'risk-score', 'TXN-48291']

        if len(parts) >= 2 and parts[0] == "api":
            # API Routing
            if parts[1] == "demo" and len(parts) >= 3 and parts[2] == "cases":
                status, data = handler.handle_get_demo_cases()
                self.send_json(status, data)
                return

            if parts[1] == "risk-score" and len(parts) >= 3:
                txn_id = parts[2]
                if len(parts) == 3:
                    status, data = handler.handle_get_risk_score(txn_id)
                    self.send_json(status, data)
                    return
                elif parts[3] == "signals":
                    status, data = handler.handle_get_signals(txn_id)
                    self.send_json(status, data)
                    return
                elif parts[3] == "entities":
                    status, data = handler.handle_get_entities(txn_id)
                    self.send_json(status, data)
                    return
                elif parts[3] == "timeline":
                    status, data = handler.handle_get_timeline(txn_id)
                    self.send_json(status, data)
                    return

            if parts[1] == "investigate" and len(parts) >= 4:
                sub = parts[2]
                txn_id = parts[3]
                if sub == "network":
                    status, data = handler.handle_get_network_graph(txn_id)
                    self.send_json(status, data)
                    return
                elif sub == "money-flow":
                    status, data = handler.handle_get_money_flow(txn_id)
                    self.send_json(status, data)
                    return

            self.send_json(404, {"error": "ENDPOINT_NOT_FOUND", "path": path})
            return

        # Serve static frontend files
        static_file = FRONTEND_DIR / "dist" / (path.lstrip("/") or "index.html")
        if not static_file.exists():
            static_file = FRONTEND_DIR / (path.lstrip("/") or "index.html")

        if static_file.exists() and static_file.is_file():
            self.serve_file(static_file)
        else:
            # Fallback to index.html for Single Page App
            fallback = FRONTEND_DIR / "index.html"
            if fallback.exists():
                self.serve_file(fallback)
            else:
                self.send_error(404, "Frontend files not found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path.rstrip("/")
        parts = path.split("/")[1:]
        body = self.read_json_body()

        if len(parts) >= 2 and parts[0] == "api":
            if parts[1] == "demo":
                if len(parts) >= 3 and parts[2] == "tweak":
                    status, data = handler.handle_demo_tweak(body)
                    self.send_json(status, data)
                    return
                elif len(parts) >= 3 and parts[2] == "reset":
                    status, data = handler.handle_demo_tweak({"action": "reset"})
                    self.send_json(status, data)
                    return

            if parts[1] == "risk-score" and len(parts) >= 4:
                txn_id = parts[2]
                action = parts[3]
                if action == "recalculate":
                    status, data = handler.handle_recalculate(txn_id)
                    self.send_json(status, data)
                    return
                elif action == "what-if":
                    status, data = handler.handle_what_if(txn_id, body)
                    self.send_json(status, data)
                    return

            if parts[1] == "investigate" and len(parts) >= 4:
                if parts[2] == "evidence-pack":
                    txn_id = parts[3]
                    status, data = handler.handle_generate_evidence_pack(txn_id, body)
                    self.send_json(status, data)
                    return

            self.send_json(404, {"error": "POST_ENDPOINT_NOT_FOUND", "path": path})
            return

        self.send_json(400, {"error": "BAD_REQUEST"})

    def serve_file(self, file_path: Path):
        suffix = file_path.suffix.lower()
        content_types = {
            ".html": "text/html",
            ".css": "text/css",
            ".js": "application/javascript",
            ".json": "application/json",
            ".svg": "image/svg+xml",
            ".png": "image/png",
            ".jpg": "image/jpeg",
            ".ico": "image/x-icon",
        }
        content_type = content_types.get(suffix, "application/octet-stream")

        try:
            with open(file_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
        except Exception as e:
            self.send_error(500, f"Error reading file: {str(e)}")

def run_server(port: int = PORT):
    server_address = ("", port)
    httpd = http.server.ThreadingHTTPServer(server_address, FraudNexusRequestHandler)
    print(f"\n=======================================================")
    print(f"  FRAUDNEXUS EXPLAINABLE FRAUD RISK INTELLIGENCE ENGINE")
    print(f"  Server listening on http://localhost:{port}")
    print(f"  REST API Base: http://localhost:{port}/api")
    print(f"  Primary Demo Case: http://localhost:{port}/api/risk-score/TXN-48291")
    print(f"=======================================================\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down FraudNexus server.")
        httpd.server_close()

if __name__ == "__main__":
    run_server()
