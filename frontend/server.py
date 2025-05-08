from http.server import HTTPServer, SimpleHTTPRequestHandler
import os

class CORSRequestHandler(SimpleHTTPRequestHandler):
    def end_headers(self):
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'X-Requested-With')
        super().end_headers()

    def do_OPTIONS(self):
        self.send_response(200)
        self.end_headers()

    def do_GET(self):
        if self.path == '/':
            self.send_response(200)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            
            # Read the index.html file
            with open('index.html', 'r') as f:
                content = f.read()
            
            # Inject environment variable
            api_gateway_url = os.getenv('REACT_APP_API_GATEWAY_URL', 'http://localhost:8004')
            script_tag = f'<script>window.ENV_API_GATEWAY_URL = "{api_gateway_url}";</script>'
            content = content.replace('<script>', f'{script_tag}\n<script>')
            
            self.wfile.write(content.encode())
        else:
            super().do_GET()

if __name__ == '__main__':
    port = 3000
    server_address = ('', port)
    httpd = HTTPServer(server_address, CORSRequestHandler)
    print(f"Serving frontend at http://localhost:{port}")
    httpd.serve_forever() 