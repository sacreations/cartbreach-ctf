import http.server
import os
import subprocess
import urllib.parse

PORT = 3001
GIT_PROJECT_ROOT = "/var/git"

# Discover git-http-backend executable path
try:
    exec_path = subprocess.check_output(["git", "--exec-path"], text=True).strip()
    GIT_HTTP_BACKEND = os.path.join(exec_path, "git-http-backend")
except Exception:
    GIT_HTTP_BACKEND = "/usr/libexec/git-core/git-http-backend"


class GitHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.handle_git_request()

    def do_POST(self):
        self.handle_git_request()

    def handle_git_request(self):
        parsed = urllib.parse.urlparse(self.path)
        path_info = parsed.path
        query_string = parsed.query or ""

        # Environment required by git-http-backend CGI
        env = os.environ.copy()
        env.update({
            "GIT_PROJECT_ROOT": GIT_PROJECT_ROOT,
            "GIT_HTTP_EXPORT_ALL": "1",
            "REQUEST_METHOD": self.command,
            "PATH_INFO": path_info,
            "QUERY_STRING": query_string,
            "CONTENT_TYPE": self.headers.get("Content-Type", ""),
            "REMOTE_ADDR": self.client_address[0],
            "SERVER_NAME": "cartbreach-git",
            "SERVER_PORT": str(PORT),
        })

        content_length = int(self.headers.get("Content-Length", 0))
        input_data = self.rfile.read(content_length) if content_length > 0 else None

        try:
            proc = subprocess.Popen(
                [GIT_HTTP_BACKEND],
                stdin=subprocess.PIPE if input_data else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=env,
            )
            stdout, stderr = proc.communicate(input=input_data)
        except Exception as e:
            self.send_error(500, f"Git backend execution error: {e}")
            return

        if not stdout:
            self.send_error(404, "Repository or object not found")
            return

        # Separate CGI headers from payload body
        header_end = stdout.find(b"\r\n\r\n")
        delimiter_len = 4
        if header_end == -1:
            header_end = stdout.find(b"\n\n")
            delimiter_len = 2

        if header_end == -1:
            self.send_response(200)
            self.end_headers()
            self.wfile.write(stdout)
            return

        raw_headers = stdout[:header_end].decode("latin1", errors="replace")
        body = stdout[header_end + delimiter_len:]

        status_code = 200
        headers_to_send = []
        for line in raw_headers.splitlines():
            line = line.strip()
            if not line:
                continue
            if line.lower().startswith("status:"):
                parts = line.split(":", 1)[1].strip().split(" ", 1)
                try:
                    status_code = int(parts[0])
                except ValueError:
                    pass
            elif ":" in line:
                k, v = line.split(":", 1)
                headers_to_send.append((k.strip(), v.strip()))

        self.send_response(status_code)
        for k, v in headers_to_send:
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        # Keep server logs concise
        super().log_message(format, *args)


if __name__ == "__main__":
    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), GitHTTPRequestHandler)
    print(f"Git Smart HTTP server listening on port {PORT}")
    server.serve_forever()
