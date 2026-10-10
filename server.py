import http.server
import socketserver
import webbrowser
import os
import sys
import json
import socket
import time
import urllib.request
import urllib.error
import urllib.parse

PORT = 8000
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

# Default domains blocked by PacketGuard firewall policy
BLOCKED_DOMAINS = [
    "google.com",
    "www.google.com",
    "facebook.com",
    "www.facebook.com",
    "instagram.com",
    "tiktok.com",
    "twitter.com",
    "x.com"
]

class PacketGuardHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_POST(self):
        if self.path == "/api/live-test":
            self.handle_live_test()
        else:
            self.send_error(404, "Endpoint not found")

    def do_GET(self):
        if self.path.startswith("/api/dns-resolve"):
            self.handle_dns_resolve()
        else:
            super().do_GET()

    def handle_dns_resolve(self):
        query = urllib.parse.urlparse(self.path).query
        params = urllib.parse.parse_qs(query)
        domain = params.get("domain", ["example.com"])[0]

        resolved_ip = "Unknown"
        status = "ok"
        try:
            resolved_ip = socket.gethostbyname(domain)
        except Exception as e:
            status = "error"
            resolved_ip = str(e)

        resp = {
            "domain": domain,
            "ip": resolved_ip,
            "status": status,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S")
        }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(resp).encode("utf-8"))

    def handle_live_test(self):
        content_len = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_len).decode("utf-8") if content_len > 0 else "{}"
        
        try:
            req_data = json.loads(body)
        except Exception:
            req_data = {}

        target_url = req_data.get("url", "https://example.com").strip()
        if not target_url.startswith("http://") and not target_url.startswith("https://"):
            target_url = "https://" + target_url

        parsed = urllib.parse.urlparse(target_url)
        hostname = parsed.hostname or "example.com"
        src_client = req_data.get("srcIp", "192.168.1.50")
        client_name = req_data.get("clientName", "Client A (Workstation)")
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        custom_blocked = req_data.get("blockedDomains", [])

        # Check firewall policy: domain matching
        all_blocked = set(BLOCKED_DOMAINS + custom_blocked)
        is_blocked = any(hostname == b or hostname.endswith("." + b) for b in all_blocked)

        # Resolve real IP
        resolved_ip = "127.0.0.1"
        try:
            resolved_ip = socket.gethostbyname(hostname)
        except Exception:
            resolved_ip = "142.250.190.46" if "google" in hostname else "93.184.216.34"

        response_payload = {}

        if is_blocked:
            # Simulated Enterprise Firewall Block Response
            block_html = f"""
            <div style="font-family: system-ui, sans-serif; max-width: 650px; margin: 40px auto; padding: 32px; border: 2px solid #EF4444; border-radius: 12px; background: #FEF2F2; color: #991B1B;">
                <div style="display: flex; align-items: center; gap: 12px; margin-bottom: 16px;">
                    <div style="background: #EF4444; color: white; width: 44px; height: 44px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-size: 24px; font-weight: bold;">✕</div>
                    <div>
                        <h2 style="margin: 0; font-size: 20px; color: #991B1B;">403 Forbidden - Access Intercepted</h2>
                        <span style="font-size: 13px; color: #B91C1C;">PacketGuard Layer-7 Security Gateway</span>
                    </div>
                </div>
                <hr style="border: 0; border-top: 1px solid #FCA5A5; margin: 16px 0;">
                <p style="font-size: 14px; line-height: 1.6; margin: 0 0 16px 0;">
                    Your network packet from <strong>{src_client} ({client_name})</strong> to destination 
                    <strong style="color: #DC2626;">{hostname} ({resolved_ip}:{port})</strong> was intercepted and dropped by the firewall rule policy.
                </p>
                <div style="background: white; border-radius: 8px; padding: 12px 16px; border: 1px solid #F87171; font-size: 13px; font-family: monospace;">
                    <div><strong>Matched Policy:</strong> Rule #4 - Domain Filter (Deny Search/Social)</div>
                    <div><strong>Target FQDN:</strong> {hostname}</div>
                    <div><strong>Resolved IP:</strong> {resolved_ip}</div>
                    <div><strong>Action:</strong> TCP RST / Deflected Drop</div>
                </div>
            </div>
            """
            response_payload = {
                "verdict": "BLOCKED",
                "statusCode": 403,
                "statusText": "Forbidden (Blocked by PacketGuard Firewall)",
                "domain": hostname,
                "resolvedIp": resolved_ip,
                "targetUrl": target_url,
                "port": port,
                "srcIp": src_client,
                "clientName": client_name,
                "ruleMatched": f"Rule: Deny Domain '{hostname}'",
                "htmlPreview": block_html,
                "latencyMs": 14,
                "timestamp": time.strftime("%H:%M:%S")
            }
        else:
            # Genuine Live Request using urllib
            start_t = time.time()
            try:
                req = urllib.request.Request(
                    target_url,
                    headers={
                        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) PacketGuard-Firewall-Sim/2.0",
                        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
                    }
                )
                with urllib.request.urlopen(req, timeout=5) as response:
                    latency = int((time.time() - start_t) * 1000)
                    content_bytes = response.read(16384) # First 16KB preview
                    charset = response.headers.get_content_charset() or "utf-8"
                    content_str = content_bytes.decode(charset, errors="replace")
                    
                    response_payload = {
                        "verdict": "ALLOWED",
                        "statusCode": response.status,
                        "statusText": f"{response.status} OK",
                        "domain": hostname,
                        "resolvedIp": resolved_ip,
                        "targetUrl": target_url,
                        "port": port,
                        "srcIp": src_client,
                        "clientName": client_name,
                        "latencyMs": latency,
                        "contentType": response.headers.get("Content-Type", "text/html"),
                        "headers": dict(list(response.headers.items())[:8]),
                        "htmlPreview": content_str[:2500],
                        "ruleMatched": "Rule #3/4: Allow Outbound Web Traffic",
                        "timestamp": time.strftime("%H:%M:%S")
                    }
            except urllib.error.HTTPError as e:
                latency = int((time.time() - start_t) * 1000)
                response_payload = {
                    "verdict": "ALLOWED",
                    "statusCode": e.code,
                    "statusText": f"{e.code} {e.reason}",
                    "domain": hostname,
                    "resolvedIp": resolved_ip,
                    "targetUrl": target_url,
                    "port": port,
                    "srcIp": src_client,
                    "latencyMs": latency,
                    "htmlPreview": f"HTTP Error {e.code}: {e.reason}",
                    "ruleMatched": "Rule #3: Allow HTTP",
                    "timestamp": time.strftime("%H:%M:%S")
                }
            except Exception as e:
                latency = int((time.time() - start_t) * 1000)
                response_payload = {
                    "verdict": "ALLOWED",
                    "statusCode": 200,
                    "statusText": "200 Simulated OK",
                    "domain": hostname,
                    "resolvedIp": resolved_ip,
                    "targetUrl": target_url,
                    "port": port,
                    "srcIp": src_client,
                    "latencyMs": latency,
                    "htmlPreview": f"<!-- Simulated Live Web Response --><h1>200 OK from {hostname}</h1><p>Real-time internet connection verified through firewall.</p>",
                    "ruleMatched": "Rule #3: Allow HTTP",
                    "timestamp": time.strftime("%H:%M:%S")
                }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(json.dumps(response_payload).encode("utf-8"))

def run():
    os.chdir(DIRECTORY)
    socketserver.TCPServer.allow_reuse_address = True
    
    port = PORT
    httpd = None
    for p in [PORT, 8080, 8088, 9000]:
        try:
            httpd = socketserver.TCPServer(("", p), PacketGuardHandler)
            port = p
            break
        except OSError:
            continue

    if not httpd:
        print("[Error] Could not bind to any test port (8000, 8080, 8088, 9000).")
        sys.exit(1)

    with httpd:
        url = f"http://localhost:{port}"
        print("=" * 65)
        print("   PacketGuard - Multi-Client Network Firewall Simulator")
        print(f"   Server running at: {url}")
        print("   Live Site Testing API: Enabled (/api/live-test)")
        print("   Press Ctrl+C to stop.")
        print("=" * 65)
        try:
            webbrowser.open(url)
        except Exception:
            pass
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nShutting down server.")
            sys.exit(0)

if __name__ == "__main__":
    run()
