import http.server
import socketserver
import webbrowser
import os
import sys

PORT = 8000
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

def run():
    os.chdir(DIRECTORY)
    socketserver.TCPServer.allow_reuse_address = True
    
    port = PORT
    httpd = None
    for p in [PORT, 8080, 8088, 9000]:
        try:
            httpd = socketserver.TCPServer(("", p), Handler)
            port = p
            break
        except OSError:
            continue

    if not httpd:
        print("[Error] Could not bind to any test port (8000, 8080, 8088, 9000).")
        sys.exit(1)

    with httpd:
        url = f"http://localhost:{port}"
        print("=" * 60)
        print("   PacketGuard - Network Firewall Simulator")
        print(f"   Server running at: {url}")
        print("   Press Ctrl+C to stop.")
        print("=" * 60)
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
