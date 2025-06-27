"""
CodeGuardian AI - Enterprise Security Middleware
Multi-layered security middleware for defense in depth
"""

import time
import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from typing import Dict, Any, Optional, List, Callable
from functools import wraps
from flask import request, jsonify, g, current_app
from werkzeug.exceptions import TooManyRequests, Unauthorized, Forbidden
import ipaddress
import re
import json
import logging

from src.audit.audit_system import get_audit_manager, EventType, LogLevel, SecurityLevel

class SecurityMiddleware:
    """Enterprise security middleware with multiple protection layers"""
    
    def __init__(self, app=None):
        self.app = app
        self.audit_manager = get_audit_manager()
        self.blocked_ips = set()
        self.suspicious_patterns = [
            r'<script[^>]*>.*?</script>',  # XSS
            r'union\s+select',  # SQL injection
            r'drop\s+table',  # SQL injection
            r'exec\s*\(',  # Code injection
            r'eval\s*\(',  # Code injection
            r'\.\./',  # Path traversal
            r'<iframe',  # XSS
            r'javascript:',  # XSS
            r'vbscript:',  # XSS
        ]
        
        if app:
            self.init_app(app)
    
    def init_app(self, app):
        """Initialize security middleware with Flask app"""
        app.before_request(self.before_request)
        app.after_request(self.after_request)
        app.errorhandler(429)(self.handle_rate_limit)
        app.errorhandler(401)(self.handle_unauthorized)
        app.errorhandler(403)(self.handle_forbidden)
    
    def before_request(self):
        """Execute security checks before each request"""
        start_time = time.time()
        
        # Generate request ID for tracing
        g.request_id = secrets.token_hex(16)
        g.start_time = start_time
        
        # IP validation and blocking
        client_ip = self._get_client_ip()
        if self._is_ip_blocked(client_ip):
            self._log_security_event(
                EventType.SECURITY_IP_BLOCKED,
                f"Blocked IP attempted access: {client_ip}",
                {"ip": client_ip, "user_agent": request.headers.get('User-Agent')}
            )
            return jsonify({"error": "Access denied"}), 403
        
        # Request size validation
        if self._is_request_too_large():
            self._log_security_event(
                EventType.SECURITY_REQUEST_TOO_LARGE,
                f"Request too large from {client_ip}",
                {"ip": client_ip, "content_length": request.content_length}
            )
            return jsonify({"error": "Request too large"}), 413
        
        # Content type validation
        if not self._is_content_type_valid():
            self._log_security_event(
                EventType.SECURITY_INVALID_CONTENT_TYPE,
                f"Invalid content type from {client_ip}",
                {"ip": client_ip, "content_type": request.content_type}
            )
            return jsonify({"error": "Invalid content type"}), 400
        
        # Input validation and sanitization
        if self._contains_malicious_patterns():
            self._log_security_event(
                EventType.SECURITY_MALICIOUS_INPUT,
                f"Malicious input detected from {client_ip}",
                {"ip": client_ip, "path": request.path, "method": request.method}
            )
            return jsonify({"error": "Invalid input detected"}), 400
        
        # CSRF protection for state-changing operations
        if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
            if not self._validate_csrf_token():
                self._log_security_event(
                    EventType.SECURITY_CSRF_VIOLATION,
                    f"CSRF token validation failed from {client_ip}",
                    {"ip": client_ip, "path": request.path}
                )
                return jsonify({"error": "CSRF token validation failed"}), 403
        
        # Rate limiting check
        if self._is_rate_limited(client_ip):
            self._log_security_event(
                EventType.SECURITY_RATE_LIMIT_EXCEEDED,
                f"Rate limit exceeded for {client_ip}",
                {"ip": client_ip, "path": request.path}
            )
            raise TooManyRequests("Rate limit exceeded")
        
        # Store security context
        g.client_ip = client_ip
        g.security_validated = True
    
    def after_request(self, response):
        """Execute security measures after request processing"""
        
        # Add security headers
        response = self._add_security_headers(response)
        
        # Log request completion
        if hasattr(g, 'start_time'):
            duration = time.time() - g.start_time
            self._log_performance_metrics(duration, response.status_code)
        
        return response
    
    def _get_client_ip(self) -> str:
        """Get real client IP address considering proxies"""
        # Check for forwarded headers (in order of preference)
        forwarded_headers = [
            'X-Forwarded-For',
            'X-Real-IP',
            'X-Client-IP',
            'CF-Connecting-IP',  # Cloudflare
            'True-Client-IP',    # Akamai
        ]
        
        for header in forwarded_headers:
            if header in request.headers:
                # Take the first IP in case of multiple
                ip = request.headers[header].split(',')[0].strip()
                if self._is_valid_ip(ip):
                    return ip
        
        return request.remote_addr or '127.0.0.1'
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IP address format"""
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def _is_ip_blocked(self, ip: str) -> bool:
        """Check if IP is in blocked list"""
        return ip in self.blocked_ips
    
    def _is_request_too_large(self) -> bool:
        """Check if request size exceeds limits"""
        max_content_length = current_app.config.get('MAX_CONTENT_LENGTH', 16 * 1024 * 1024)  # 16MB
        
        if request.content_length and request.content_length > max_content_length:
            return True
        
        return False
    
    def _is_content_type_valid(self) -> bool:
        """Validate request content type"""
        if request.method in ['GET', 'HEAD', 'OPTIONS']:
            return True
        
        allowed_types = [
            'application/json',
            'application/x-www-form-urlencoded',
            'multipart/form-data',
            'text/plain'
        ]
        
        if not request.content_type:
            return request.method == 'POST' and request.content_length == 0
        
        content_type = request.content_type.split(';')[0].strip()
        return content_type in allowed_types
    
    def _contains_malicious_patterns(self) -> bool:
        """Check for malicious patterns in request data"""
        # Check URL path
        if self._scan_for_patterns(request.path):
            return True
        
        # Check query parameters
        for key, value in request.args.items():
            if self._scan_for_patterns(f"{key}={value}"):
                return True
        
        # Check form data
        if request.form:
            for key, value in request.form.items():
                if self._scan_for_patterns(f"{key}={value}"):
                    return True
        
        # Check JSON data
        if request.is_json:
            try:
                json_str = json.dumps(request.get_json())
                if self._scan_for_patterns(json_str):
                    return True
            except Exception:
                pass
        
        # Check headers for suspicious content
        suspicious_headers = ['User-Agent', 'Referer', 'X-Forwarded-For']
        for header in suspicious_headers:
            value = request.headers.get(header, '')
            if self._scan_for_patterns(value):
                return True
        
        return False
    
    def _scan_for_patterns(self, text: str) -> bool:
        """Scan text for malicious patterns"""
        text_lower = text.lower()
        
        for pattern in self.suspicious_patterns:
            if re.search(pattern, text_lower, re.IGNORECASE):
                return True
        
        return False
    
    def _validate_csrf_token(self) -> bool:
        """Validate CSRF token for state-changing operations"""
        # Skip CSRF for API endpoints with proper authentication
        if request.path.startswith('/api/') and 'Authorization' in request.headers:
            return True
        
        # Skip CSRF for specific endpoints
        csrf_exempt_paths = [
            '/api/auth/login',
            '/api/auth/register',
            '/api/health',
            '/api/ready',
            '/api/live'
        ]
        
        if request.path in csrf_exempt_paths:
            return True
        
        # Check for CSRF token in headers or form data
        csrf_token = (
            request.headers.get('X-CSRF-Token') or
            request.form.get('csrf_token') or
            request.json.get('csrf_token') if request.is_json else None
        )
        
        if not csrf_token:
            return False
        
        # Validate CSRF token (simplified - in production use proper CSRF library)
        expected_token = self._generate_csrf_token()
        return hmac.compare_digest(csrf_token, expected_token)
    
    def _generate_csrf_token(self) -> str:
        """Generate CSRF token (simplified implementation)"""
        # In production, use a proper CSRF library like Flask-WTF
        secret = current_app.config.get('SECRET_KEY', 'default-secret')
        timestamp = str(int(time.time() // 3600))  # Valid for 1 hour
        return hashlib.sha256(f"{secret}:{timestamp}".encode()).hexdigest()
    
    def _is_rate_limited(self, ip: str) -> bool:
        """Check if IP is rate limited (simplified implementation)"""
        # This is a basic implementation - in production use Redis-based rate limiting
        rate_limit_key = f"rate_limit:{ip}"
        
        # For now, return False - actual rate limiting is handled by Flask-Limiter
        return False
    
    def _add_security_headers(self, response):
        """Add security headers to response"""
        security_headers = {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'",
            'Referrer-Policy': 'strict-origin-when-cross-origin',
            'Permissions-Policy': 'geolocation=(), microphone=(), camera=()',
            'X-Request-ID': getattr(g, 'request_id', 'unknown')
        }
        
        for header, value in security_headers.items():
            response.headers[header] = value
        
        return response
    
    def _log_security_event(self, event_type: EventType, message: str, details: Dict[str, Any]):
        """Log security event to audit system"""
        audit_logger = self.audit_manager.get_audit_logger()
        audit_logger.log_event(
            event_type,
            LogLevel.WARNING,
            message,
            details,
            security_level=SecurityLevel.HIGH
        )
    
    def _log_performance_metrics(self, duration: float, status_code: int):
        """Log performance metrics"""
        audit_logger = self.audit_manager.get_audit_logger()
        audit_logger.log_event(
            EventType.API_REQUEST_COMPLETED,
            LogLevel.INFO,
            f"Request completed in {duration:.3f}s",
            {
                "duration_ms": round(duration * 1000, 2),
                "status_code": status_code,
                "path": request.path,
                "method": request.method,
                "ip": getattr(g, 'client_ip', 'unknown')
            }
        )
    
    def handle_rate_limit(self, error):
        """Handle rate limit exceeded errors"""
        return jsonify({
            "error": "Rate limit exceeded",
            "message": "Too many requests. Please try again later.",
            "retry_after": getattr(error, 'retry_after', 60)
        }), 429
    
    def handle_unauthorized(self, error):
        """Handle unauthorized access errors"""
        return jsonify({
            "error": "Unauthorized",
            "message": "Authentication required"
        }), 401
    
    def handle_forbidden(self, error):
        """Handle forbidden access errors"""
        return jsonify({
            "error": "Forbidden",
            "message": "Access denied"
        }), 403
    
    def block_ip(self, ip: str, reason: str = "Security violation"):
        """Block an IP address"""
        self.blocked_ips.add(ip)
        self._log_security_event(
            EventType.SECURITY_IP_BLOCKED,
            f"IP {ip} blocked: {reason}",
            {"ip": ip, "reason": reason}
        )
    
    def unblock_ip(self, ip: str):
        """Unblock an IP address"""
        self.blocked_ips.discard(ip)
        self._log_security_event(
            EventType.SECURITY_IP_UNBLOCKED,
            f"IP {ip} unblocked",
            {"ip": ip}
        )

def require_api_key(f):
    """Decorator to require API key authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            return jsonify({"error": "API key required"}), 401
        
        # Validate API key (implement your validation logic)
        if not _validate_api_key(api_key):
            return jsonify({"error": "Invalid API key"}), 401
        
        return f(*args, **kwargs)
    
    return decorated_function

def require_admin(f):
    """Decorator to require admin privileges"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if user has admin role
        user = getattr(request, 'current_user', None)
        if not user or not hasattr(user, 'role') or user.role != 'admin':
            return jsonify({"error": "Admin privileges required"}), 403
        
        return f(*args, **kwargs)
    
    return decorated_function

def _validate_api_key(api_key: str) -> bool:
    """Validate API key (implement your validation logic)"""
    # This is a placeholder - implement actual API key validation
    return len(api_key) >= 32

# Global security middleware instance
security_middleware = SecurityMiddleware()

