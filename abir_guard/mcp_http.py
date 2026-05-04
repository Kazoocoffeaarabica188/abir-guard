"""
Abir-Guard: MCP HTTP Server (Hardened)

Security features:
- API key authentication (required for all POST endpoints)
- Rate limiting (configurable requests per minute per IP)
- Request body size limit (default 1MB)
- Health check endpoint is public (no auth required)
- Default binds to 127.0.0.1 (require --public flag for 0.0.0.0)
- Optional TLS support
"""

import json
import time
import hashlib
import hmac
import threading
import ipaddress
from typing import Optional, Dict, Tuple
from collections import defaultdict
from http.server import HTTPServer, BaseHTTPRequestHandler

from . import McpServer, VERSION

MAX_BODY_SIZE = 1024 * 1024  # 1MB max request body
DEFAULT_RATE_LIMIT = 100  # requests per minute per IP
RATE_WINDOW = 60  # seconds


class RateLimiter:
    """Token bucket rate limiter per IP"""
    
    def __init__(self, max_requests: int = DEFAULT_RATE_LIMIT, window: int = RATE_WINDOW):
        self.max_requests = max_requests
        self.window = window
        self._requests: Dict[str, list] = defaultdict(list)
        self._lock = threading.Lock()
    
    def is_allowed(self, ip: str) -> Tuple[bool, int]:
        """Check if request is allowed. Returns (allowed, remaining)."""
        now = time.time()
        with self._lock:
            # Clean old entries
            cutoff = now - self.window
            self._requests[ip] = [
                t for t in self._requests[ip] if t > cutoff
            ]
            
            count = len(self._requests[ip])
            if count >= self.max_requests:
                return False, 0
            
            self._requests[ip].append(now)
            return True, self.max_requests - count - 1
    
    def reset(self, ip: str):
        with self._lock:
            self._requests.pop(ip, None)


class AuthValidator:
    """HMAC-based API key authentication"""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        self._valid_keys = set()
        if api_key:
            self._valid_keys.add(api_key)
    
    def add_key(self, key: str):
        self._valid_keys.add(key)
    
    def validate(self, provided_key: Optional[str]) -> bool:
        if not self._valid_keys:
            return True  # No keys configured = open (warn in production)
        if not provided_key:
            return False
        return any(
            hmac.compare_digest(provided_key, k) for k in self._valid_keys
        )


class McpHttpHandler(BaseHTTPRequestHandler):
    """Hardened HTTP request handler for MCP JSON-RPC"""
    
    server_instance: Optional[McpServer] = None
    rate_limiter: Optional[RateLimiter] = None
    auth: Optional[AuthValidator] = None
    max_body_size: int = MAX_BODY_SIZE
    server_start_time: float = time.time()
    
    # Class-level audit log
    audit_log: list = []
    
    def _get_client_ip(self) -> str:
        """Get real client IP (supports X-Forwarded-For)"""
        forwarded = self.headers.get("X-Forwarded-For")
        if forwarded:
            return forwarded.split(",")[0].strip()
        return self.client_address[0]
    
    def _log_audit(self, action: str, ip: str, success: bool, details: str = ""):
        """Tamper-evident audit log entry"""
        entry = {
            "timestamp": time.time(),
            "action": action,
            "ip": ip,
            "success": success,
            "details": details,
        }
        # Hash chain: each entry includes hash of previous entry
        if self.audit_log:
            prev = json.dumps(self.audit_log[-1], sort_keys=True)
            entry["prev_hash"] = hashlib.sha256(prev.encode()).hexdigest()
        entry["hash"] = hashlib.sha256(
            json.dumps(entry, sort_keys=True).encode()
        ).hexdigest()
        self.audit_log.append(entry)
    
    def do_POST(self):
        """Handle POST requests with auth, rate limit, body size checks"""
        client_ip = self._get_client_ip()
        
        # Rate limiting
        if self.rate_limiter:
            allowed, remaining = self.rate_limiter.is_allowed(client_ip)
            if not allowed:
                self._log_audit("rate_limit_exceeded", client_ip, False)
                self.send_response(429)
                self.send_header("Content-Type", "application/json")
                self.send_header("Retry-After", str(RATE_WINDOW))
                self.end_headers()
                self.wfile.write(json.dumps({
                    "error": {"code": 429, "message": "Rate limit exceeded"}
                }).encode())
                return
        
        # Authentication
        if self.auth:
            auth_header = self.headers.get("Authorization", "")
            api_key = None
            if auth_header.startswith("Bearer "):
                api_key = auth_header[7:]
            elif auth_header.startswith("X-Api-Key: "):
                api_key = auth_header[11:]
            else:
                api_key = self.headers.get("X-Api-Key")
            
            if not self.auth.validate(api_key):
                self._log_audit("auth_failure", client_ip, False)
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "error": {"code": 401, "message": "Unauthorized"}
                }).encode())
                return
        
        # Body size check
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length > self.max_body_size:
            self._log_audit("body_too_large", client_ip, False,
                          f"size={content_length}")
            self.send_response(413)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({
                "error": {"code": 413, "message": "Request body too large (max 1MB)"}
            }).encode())
            return
        
        # Read and parse body
        try:
            body = self.rfile.read(content_length)
            request = json.loads(body)
        except json.JSONDecodeError as e:
            self._log_audit("parse_error", client_ip, False, str(e))
            self._send_json_error(-32700, f"Parse error: {e}")
            return
        
        # Dispatch to MCP server
        if self.server_instance:
            response = self.server_instance.handle(request)
            self._log_audit("mcp_request", client_ip, "error" not in response,
                          request.get("method", "unknown"))
        else:
            self._log_audit("server_error", client_ip, False)
            self._send_json_error(-32603, "Server not initialized")
            return
        
        # Send response with rate limit header BEFORE end_headers
        if self.rate_limiter:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-RateLimit-Remaining", str(remaining))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Cache-Control", "no-store")
            response_bytes = json.dumps(response).encode("utf-8")
            self.send_header("Content-Length", str(len(response_bytes)))
            self.end_headers()
            self.wfile.write(response_bytes)
        else:
            self._send_json(response)
    
    def do_GET(self):
        """Handle GET requests"""
        if self.path == "/health":
            uptime = time.time() - self.server_start_time
            self._send_json({
                "status": "ok",
                "version": VERSION,
                "name": "Abir-Guard MCP",
                "uptime_seconds": round(uptime, 2)
            })
        elif self.path == "/audit":
            # Check auth for audit endpoint
            auth_header = self.headers.get("Authorization", "")
            api_key = None
            if auth_header.startswith("Bearer "):
                api_key = auth_header[7:]
            if self.auth and self.auth.validate(api_key):
                self._send_json({"log": self.audit_log[-100:]})
            else:
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Unauthorized"}).encode())
        else:
            self._send_json_error(-32601, "Method not found")
    
    def _send_json(self, data: dict):
        """Send JSON response with security headers"""
        response = json.dumps(data).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(response)
    
    def _send_json_error(self, code: int, message: str):
        """Send JSON-RPC error response"""
        self._send_json({
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": code, "message": message}
        })
    
    def log_message(self, format, *args):
        """Log to stderr only (not stdout to avoid info leaks)"""
        import sys
        sys.stderr.write(f"[MCP HTTP] {self._get_client_ip()} - {format % args}\n")


class McpHttpServer:
    """
    Hardened MCP HTTP Server
    
    Usage:
        from abir_guard.mcp_http import McpHttpServer
        
        # Secure: localhost only, requires API key
        server = McpHttpServer(
            port=9090,
            api_key="your-secret-key-here"
        )
        server.start()
        
        # For testing only (binds to all interfaces):
        server = McpHttpServer(port=9090, public=True)
    """
    
    def __init__(
        self,
        port: int = 9090,
        host: str = "127.0.0.1",
        public: bool = False,
        api_key: Optional[str] = None,
        rate_limit: int = DEFAULT_RATE_LIMIT,
        max_body: int = MAX_BODY_SIZE,
        ssl_cert: Optional[str] = None,
        ssl_key: Optional[str] = None,
    ):
        self.port = port
        self.host = "0.0.0.0" if public else host
        self.api_key = api_key
        self.rate_limit = rate_limit
        self.max_body = max_body
        self.ssl_cert = ssl_cert
        self.ssl_key = ssl_key
        self.server = None
        self.thread = None
        self.mcp = McpServer()
        self.rate_limiter = RateLimiter(rate_limit)
        self.auth = AuthValidator(api_key)
    
    def start(self, blocking: bool = False):
        """Start the HTTP server"""
        McpHttpHandler.server_instance = self.mcp
        McpHttpHandler.rate_limiter = self.rate_limiter
        McpHttpHandler.auth = self.auth
        McpHttpHandler.max_body_size = self.max_body
        
        self.server = HTTPServer((self.host, self.port), McpHttpHandler)
        
        if self.ssl_cert and self.ssl_key:
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self.ssl_cert, self.ssl_key)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
            self.server.socket = ctx.wrap_socket(
                self.server.socket, server_side=True
            )
            scheme = "https"
        else:
            scheme = "http"
        
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()
        
        print(f"MCP HTTP server running on {scheme}://{self.host}:{self.port}")
        print(f"Health check: {scheme}://{self.host}:{self.port}/health")
        if self.api_key:
            print("Authentication: enabled (Bearer token required)")
        else:
            print("WARNING: Authentication disabled (not for production)")
        
        if blocking:
            try:
                self.server.serve_forever()
            except KeyboardInterrupt:
                self.stop()
    
    def stop(self):
        """Stop the HTTP server"""
        if self.server:
            self.server.shutdown()
            print("MCP HTTP server stopped")


def demo():
    """Demo MCP HTTP server"""
    print("=" * 50)
    print("Abir-Guard: MCP HTTP Server Demo")
    print("=" * 50)
    
    server = McpHttpServer(port=9090, api_key="demo-key")
    server.start()
    
    import time
    print("\nServer running for 5 seconds...")
    time.sleep(5)
    
    server.stop()


if __name__ == "__main__":
    demo()
