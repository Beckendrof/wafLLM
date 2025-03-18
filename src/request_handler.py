from http.server import BaseHTTPRequestHandler
import requests

class WAFRequestHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        self._body = None  # Store body for reuse
        super().__init__(*args, **kwargs)
    
    def _get_request_body(self):
        """Extract request body if present."""
        if self._body:
            return self._body
            
        content_length = int(self.headers.get('Content-Length', 0))
        return self.rfile.read(content_length) if content_length > 0 else b''
    
    def _analyze_request(self):
        """Analyze the request using LLM-based detection."""
        # Parse and analyze the request
        request_data = self.server.request_analyzer.parse_request(self)
        is_allowed, reason = self.server.request_analyzer.analyze_request(request_data)
        
        return is_allowed, reason
    
    def _send_error_response(self, message):
        """Send an error response when a request is blocked."""
        self.send_response(403)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        
        response = f"""
        <html>
        <head><title>403 Forbidden</title></head>
        <body>
        <h1>Forbidden</h1>
        <p>The request was blocked by the WAF Police!</p>
        </body>
        </html>
        """
        self.wfile.write(response.encode('utf-8'))
    
    def _forward_request(self):
        """Forward the request to the target server."""
        if not self.server.target_url:
            self.send_response(500)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(b"WAF misconfiguration: No target URL specified")
            return
        
        target = f"{self.server.target_url}{self.path}"
        method = self.command
        headers = {key: val for key, val in self.headers.items()}
        body = self._get_request_body()
        
        try:
            if method == 'GET':
                response = requests.get(target, headers=headers)
            elif method == 'POST':
                response = requests.post(target, headers=headers, data=body)
            elif method == 'PUT':
                response = requests.put(target, headers=headers, data=body)
            elif method == 'DELETE':
                response = requests.delete(target, headers=headers)
            else:
                # Default fallback
                response = requests.request(method, target, headers=headers, data=body)
            
            # Forward the response back to the client
            self.send_response(response.status_code)
            for key, val in response.headers.items():
                self.send_header(key, val)
            self.end_headers()
            self.wfile.write(response.content)
            
        except Exception as e:
            self.server.logger.error(f"Error forwarding request: {str(e)}")
            self.send_response(502)
            self.send_header('Content-type', 'text/html')
            self.end_headers()
            self.wfile.write(f"Error forwarding request: {str(e)}".encode('utf-8'))
    
    def do_GET(self):
        """Handle GET requests."""
        allowed, message = self._analyze_request()
        if allowed:
            self._forward_request()
        else:
            self._send_error_response(message)
    
    def do_POST(self):
        """Handle POST requests."""
        allowed, message = self._analyze_request()
        if allowed:
            self._forward_request()
        else:
            self._send_error_response(message)
    
    def do_PUT(self):
        """Handle PUT requests."""
        allowed, message = self._analyze_request()
        if allowed:
            self._forward_request()
        else:
            self._send_error_response(message)
    
    def do_DELETE(self):
        """Handle DELETE requests."""
        allowed, message = self._analyze_request()
        if allowed:
            self._forward_request()
        else:
            self._send_error_response(message)
