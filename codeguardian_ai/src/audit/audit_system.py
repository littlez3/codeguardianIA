"""
CodeGuardian AI - Advanced Audit and Logging System
Enterprise-grade structured logging and audit trail for complete system observability
"""

import json
import time
import uuid
import threading
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Union, Callable
from dataclasses import dataclass, field, asdict
from enum import Enum
from pathlib import Path
import logging
import logging.handlers
from contextlib import contextmanager
import traceback
import psutil
import os

class LogLevel(Enum):
    """Log levels for structured logging"""
    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

class EventType(Enum):
    """Types of events that can be logged"""
    # Authentication events
    AUTH_LOGIN_SUCCESS = "auth.login.success"
    AUTH_LOGIN_FAILURE = "auth.login.failure"
    AUTH_LOGOUT = "auth.logout"
    AUTH_TOKEN_REFRESH = "auth.token.refresh"
    AUTH_TOKEN_REVOKE = "auth.token.revoke"
    AUTH_PASSWORD_CHANGE = "auth.password.change"
    AUTH_API_KEY_CREATE = "auth.api_key.create"
    AUTH_API_KEY_REVOKE = "auth.api_key.revoke"
    
    # Code execution events
    CODE_EXECUTION_START = "code.execution.start"
    CODE_EXECUTION_SUCCESS = "code.execution.success"
    CODE_EXECUTION_FAILURE = "code.execution.failure"
    CODE_EXECUTION_TIMEOUT = "code.execution.timeout"
    CODE_EXECUTION_BLOCKED = "code.execution.blocked"
    
    # Security analysis events
    SECURITY_ANALYSIS_START = "security.analysis.start"
    SECURITY_ANALYSIS_COMPLETE = "security.analysis.complete"
    SECURITY_VULNERABILITY_DETECTED = "security.vulnerability.detected"
    SECURITY_THREAT_BLOCKED = "security.threat.blocked"
    
    # System events
    SYSTEM_STARTUP = "system.startup"
    SYSTEM_SHUTDOWN = "system.shutdown"
    SYSTEM_ERROR = "system.error"
    SYSTEM_HEALTH_CHECK = "system.health.check"
    
    # Rate limiting events
    RATE_LIMIT_EXCEEDED = "rate_limit.exceeded"
    RATE_LIMIT_WARNING = "rate_limit.warning"
    
    # API events
    API_REQUEST = "api.request"
    API_RESPONSE = "api.response"
    API_ERROR = "api.error"
    
    # Performance events
    PERFORMANCE_SLOW_QUERY = "performance.slow_query"
    PERFORMANCE_HIGH_MEMORY = "performance.high_memory"
    PERFORMANCE_HIGH_CPU = "performance.high_cpu"

class SecurityLevel(Enum):
    """Security levels for audit events"""
    PUBLIC = "public"           # No sensitive data
    INTERNAL = "internal"       # Internal use only
    CONFIDENTIAL = "confidential"  # Sensitive data
    RESTRICTED = "restricted"   # Highly sensitive data

@dataclass
class AuditContext:
    """Context information for audit events"""
    user_id: Optional[int] = None
    username: Optional[str] = None
    session_id: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    request_id: Optional[str] = None
    api_key_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {k: v for k, v in asdict(self).items() if v is not None}

@dataclass
class PerformanceMetrics:
    """Performance metrics for operations"""
    execution_time: float = 0.0
    memory_usage: int = 0  # bytes
    cpu_usage: float = 0.0  # percentage
    disk_io: int = 0  # bytes
    network_io: int = 0  # bytes
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class AuditEvent:
    """Structured audit event"""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    event_type: EventType = EventType.SYSTEM_ERROR
    level: LogLevel = LogLevel.INFO
    security_level: SecurityLevel = SecurityLevel.INTERNAL
    message: str = ""
    details: Dict[str, Any] = field(default_factory=dict)
    context: AuditContext = field(default_factory=AuditContext)
    performance: PerformanceMetrics = field(default_factory=PerformanceMetrics)
    tags: List[str] = field(default_factory=list)
    correlation_id: Optional[str] = None
    parent_event_id: Optional[str] = None
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'event_id': self.event_id,
            'timestamp': self.timestamp.isoformat(),
            'event_type': self.event_type.value,
            'level': self.level.value,
            'security_level': self.security_level.value,
            'message': self.message,
            'details': self.details,
            'context': self.context.to_dict(),
            'performance': self.performance.to_dict(),
            'tags': self.tags,
            'correlation_id': self.correlation_id,
            'parent_event_id': self.parent_event_id
        }
    
    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str, separators=(',', ':'))

class AuditLogger:
    """Enterprise-grade audit logger with structured logging"""
    
    def __init__(self, 
                 log_file: str = "audit.jsonl",
                 max_file_size: int = 100 * 1024 * 1024,  # 100MB
                 backup_count: int = 10,
                 enable_console: bool = True,
                 enable_syslog: bool = False,
                 syslog_address: str = '/dev/log'):
        
        self.log_file = log_file
        self.enable_console = enable_console
        self.enable_syslog = enable_syslog
        
        # Create logs directory if it doesn't exist
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Setup structured logger
        self.logger = logging.getLogger('codeguardian_audit')
        self.logger.setLevel(logging.DEBUG)
        
        # Clear existing handlers
        self.logger.handlers.clear()
        
        # File handler with rotation
        file_handler = logging.handlers.RotatingFileHandler(
            log_file, maxBytes=max_file_size, backupCount=backup_count
        )
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter('%(message)s')
        file_handler.setFormatter(file_formatter)
        self.logger.addHandler(file_handler)
        
        # Console handler
        if enable_console:
            console_handler = logging.StreamHandler()
            console_handler.setLevel(logging.INFO)
            console_formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            console_handler.setFormatter(console_formatter)
            self.logger.addHandler(console_handler)
        
        # Syslog handler
        if enable_syslog:
            try:
                syslog_handler = logging.handlers.SysLogHandler(address=syslog_address)
                syslog_handler.setLevel(logging.WARNING)
                syslog_formatter = logging.Formatter(
                    'CodeGuardian[%(process)d]: %(levelname)s - %(message)s'
                )
                syslog_handler.setFormatter(syslog_formatter)
                self.logger.addHandler(syslog_handler)
            except Exception as e:
                print(f"Failed to setup syslog handler: {e}")
        
        # Thread-local storage for context
        self._local = threading.local()
        
        # Performance monitoring
        self._start_time = time.time()
        self._process = psutil.Process()
    
    def set_context(self, context: AuditContext):
        """Set audit context for current thread"""
        self._local.context = context
    
    def get_context(self) -> AuditContext:
        """Get audit context for current thread"""
        return getattr(self._local, 'context', AuditContext())
    
    def clear_context(self):
        """Clear audit context for current thread"""
        if hasattr(self._local, 'context'):
            delattr(self._local, 'context')
    
    @contextmanager
    def audit_context(self, context: AuditContext):
        """Context manager for audit context"""
        old_context = getattr(self._local, 'context', None)
        self.set_context(context)
        try:
            yield
        finally:
            if old_context:
                self.set_context(old_context)
            else:
                self.clear_context()
    
    def _get_performance_metrics(self) -> PerformanceMetrics:
        """Get current performance metrics"""
        try:
            memory_info = self._process.memory_info()
            cpu_percent = self._process.cpu_percent()
            io_counters = self._process.io_counters()
            
            return PerformanceMetrics(
                memory_usage=memory_info.rss,
                cpu_usage=cpu_percent,
                disk_io=io_counters.read_bytes + io_counters.write_bytes
            )
        except Exception:
            return PerformanceMetrics()
    
    def log_event(self, 
                  event_type: EventType,
                  message: str,
                  level: LogLevel = LogLevel.INFO,
                  security_level: SecurityLevel = SecurityLevel.INTERNAL,
                  details: Optional[Dict[str, Any]] = None,
                  context: Optional[AuditContext] = None,
                  tags: Optional[List[str]] = None,
                  correlation_id: Optional[str] = None,
                  parent_event_id: Optional[str] = None):
        """Log a structured audit event"""
        
        # Use provided context or thread-local context
        audit_context = context or self.get_context()
        
        # Create audit event
        event = AuditEvent(
            event_type=event_type,
            level=level,
            security_level=security_level,
            message=message,
            details=details or {},
            context=audit_context,
            performance=self._get_performance_metrics(),
            tags=tags or [],
            correlation_id=correlation_id,
            parent_event_id=parent_event_id
        )
        
        # Log the event
        log_level = getattr(logging, level.value.upper())
        self.logger.log(log_level, event.to_json())
        
        return event.event_id
    
    def log_auth_success(self, username: str, user_id: int, ip_address: str, 
                        session_id: str, details: Optional[Dict[str, Any]] = None):
        """Log successful authentication"""
        context = AuditContext(
            user_id=user_id,
            username=username,
            ip_address=ip_address,
            session_id=session_id
        )
        
        return self.log_event(
            event_type=EventType.AUTH_LOGIN_SUCCESS,
            message=f"User {username} logged in successfully",
            level=LogLevel.INFO,
            security_level=SecurityLevel.CONFIDENTIAL,
            details=details,
            context=context,
            tags=['authentication', 'success']
        )
    
    def log_auth_failure(self, username: str, ip_address: str, reason: str,
                        details: Optional[Dict[str, Any]] = None):
        """Log failed authentication"""
        context = AuditContext(
            username=username,
            ip_address=ip_address
        )
        
        return self.log_event(
            event_type=EventType.AUTH_LOGIN_FAILURE,
            message=f"Authentication failed for {username}: {reason}",
            level=LogLevel.WARNING,
            security_level=SecurityLevel.CONFIDENTIAL,
            details=details,
            context=context,
            tags=['authentication', 'failure', 'security']
        )
    
    def log_code_execution(self, code_hash: str, language: str, 
                          execution_time: float, success: bool,
                          details: Optional[Dict[str, Any]] = None):
        """Log code execution event"""
        event_type = EventType.CODE_EXECUTION_SUCCESS if success else EventType.CODE_EXECUTION_FAILURE
        level = LogLevel.INFO if success else LogLevel.WARNING
        
        execution_details = {
            'code_hash': code_hash,
            'language': language,
            'execution_time': execution_time,
            'success': success
        }
        if details:
            execution_details.update(details)
        
        return self.log_event(
            event_type=event_type,
            message=f"Code execution {'succeeded' if success else 'failed'} in {execution_time:.3f}s",
            level=level,
            security_level=SecurityLevel.INTERNAL,
            details=execution_details,
            tags=['code_execution', 'success' if success else 'failure']
        )
    
    def log_security_analysis(self, code_hash: str, vulnerability_count: int,
                             max_severity: str, analysis_time: float,
                             details: Optional[Dict[str, Any]] = None):
        """Log security analysis event"""
        analysis_details = {
            'code_hash': code_hash,
            'vulnerability_count': vulnerability_count,
            'max_severity': max_severity,
            'analysis_time': analysis_time
        }
        if details:
            analysis_details.update(details)
        
        level = LogLevel.WARNING if vulnerability_count > 0 else LogLevel.INFO
        
        return self.log_event(
            event_type=EventType.SECURITY_ANALYSIS_COMPLETE,
            message=f"Security analysis found {vulnerability_count} vulnerabilities (max: {max_severity})",
            level=level,
            security_level=SecurityLevel.CONFIDENTIAL,
            details=analysis_details,
            tags=['security', 'analysis', max_severity]
        )
    
    def log_vulnerability_detected(self, vulnerability_type: str, severity: str,
                                  line_number: int, code_snippet: str,
                                  details: Optional[Dict[str, Any]] = None):
        """Log detected vulnerability"""
        vuln_details = {
            'vulnerability_type': vulnerability_type,
            'severity': severity,
            'line_number': line_number,
            'code_snippet': code_snippet[:100] + '...' if len(code_snippet) > 100 else code_snippet
        }
        if details:
            vuln_details.update(details)
        
        level_mapping = {
            'critical': LogLevel.CRITICAL,
            'high': LogLevel.ERROR,
            'medium': LogLevel.WARNING,
            'low': LogLevel.INFO
        }
        level = level_mapping.get(severity.lower(), LogLevel.WARNING)
        
        return self.log_event(
            event_type=EventType.SECURITY_VULNERABILITY_DETECTED,
            message=f"{severity.upper()} vulnerability detected: {vulnerability_type}",
            level=level,
            security_level=SecurityLevel.RESTRICTED,
            details=vuln_details,
            tags=['security', 'vulnerability', severity, vulnerability_type]
        )
    
    def log_rate_limit_exceeded(self, endpoint: str, limit: int, window: int,
                               details: Optional[Dict[str, Any]] = None):
        """Log rate limit exceeded event"""
        limit_details = {
            'endpoint': endpoint,
            'limit': limit,
            'window': window
        }
        if details:
            limit_details.update(details)
        
        return self.log_event(
            event_type=EventType.RATE_LIMIT_EXCEEDED,
            message=f"Rate limit exceeded for {endpoint}: {limit} requests per {window}s",
            level=LogLevel.WARNING,
            security_level=SecurityLevel.INTERNAL,
            details=limit_details,
            tags=['rate_limit', 'security', 'abuse']
        )
    
    def log_api_request(self, method: str, endpoint: str, status_code: int,
                       response_time: float, details: Optional[Dict[str, Any]] = None):
        """Log API request"""
        request_details = {
            'method': method,
            'endpoint': endpoint,
            'status_code': status_code,
            'response_time': response_time
        }
        if details:
            request_details.update(details)
        
        level = LogLevel.ERROR if status_code >= 500 else LogLevel.WARNING if status_code >= 400 else LogLevel.INFO
        
        return self.log_event(
            event_type=EventType.API_REQUEST,
            message=f"{method} {endpoint} - {status_code} ({response_time:.3f}s)",
            level=level,
            security_level=SecurityLevel.INTERNAL,
            details=request_details,
            tags=['api', 'request', str(status_code)]
        )
    
    def log_system_error(self, error: Exception, context_info: Optional[Dict[str, Any]] = None):
        """Log system error with full traceback"""
        error_details = {
            'error_type': type(error).__name__,
            'error_message': str(error),
            'traceback': traceback.format_exc()
        }
        if context_info:
            error_details.update(context_info)
        
        return self.log_event(
            event_type=EventType.SYSTEM_ERROR,
            message=f"System error: {type(error).__name__}: {str(error)}",
            level=LogLevel.ERROR,
            security_level=SecurityLevel.INTERNAL,
            details=error_details,
            tags=['system', 'error', type(error).__name__]
        )
    
    @contextmanager
    def operation_timer(self, operation_name: str, 
                       event_type: EventType = EventType.SYSTEM_HEALTH_CHECK,
                       level: LogLevel = LogLevel.INFO):
        """Context manager to time operations and log performance"""
        start_time = time.time()
        start_memory = self._process.memory_info().rss
        
        try:
            yield
            success = True
            error = None
        except Exception as e:
            success = False
            error = e
            raise
        finally:
            end_time = time.time()
            end_memory = self._process.memory_info().rss
            execution_time = end_time - start_time
            memory_delta = end_memory - start_memory
            
            details = {
                'operation': operation_name,
                'execution_time': execution_time,
                'memory_delta': memory_delta,
                'success': success
            }
            
            if error:
                details['error'] = str(error)
                details['error_type'] = type(error).__name__
            
            # Log slow operations as warnings
            if execution_time > 5.0:  # 5 seconds threshold
                level = LogLevel.WARNING
                details['slow_operation'] = True
            
            self.log_event(
                event_type=event_type,
                message=f"Operation {operation_name} {'completed' if success else 'failed'} in {execution_time:.3f}s",
                level=level,
                details=details,
                tags=['performance', 'operation', 'success' if success else 'failure']
            )

class AuditManager:
    """Centralized audit management"""
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        config = config or {}
        
        # Initialize audit logger
        self.audit_logger = AuditLogger(
            log_file=config.get('audit_log_file', 'logs/audit.jsonl'),
            max_file_size=config.get('max_file_size', 100 * 1024 * 1024),
            backup_count=config.get('backup_count', 10),
            enable_console=config.get('enable_console', True),
            enable_syslog=config.get('enable_syslog', False)
        )
        
        # Initialize performance logger
        self.performance_logger = AuditLogger(
            log_file=config.get('performance_log_file', 'logs/performance.jsonl'),
            enable_console=False
        )
        
        # Initialize security logger
        self.security_logger = AuditLogger(
            log_file=config.get('security_log_file', 'logs/security.jsonl'),
            enable_console=True,
            enable_syslog=config.get('enable_syslog', False)
        )
        
        # Log system startup
        self.audit_logger.log_event(
            event_type=EventType.SYSTEM_STARTUP,
            message="CodeGuardian AI system started",
            level=LogLevel.INFO,
            security_level=SecurityLevel.INTERNAL,
            details={'config': config},
            tags=['system', 'startup']
        )
    
    def get_audit_logger(self) -> AuditLogger:
        """Get the main audit logger"""
        return self.audit_logger
    
    def get_performance_logger(self) -> AuditLogger:
        """Get the performance logger"""
        return self.performance_logger
    
    def get_security_logger(self) -> AuditLogger:
        """Get the security logger"""
        return self.security_logger
    
    def shutdown(self):
        """Shutdown audit system"""
        self.audit_logger.log_event(
            event_type=EventType.SYSTEM_SHUTDOWN,
            message="CodeGuardian AI system shutting down",
            level=LogLevel.INFO,
            security_level=SecurityLevel.INTERNAL,
            tags=['system', 'shutdown']
        )

# Global audit manager instance
audit_manager = None

def initialize_audit_system(config: Optional[Dict[str, Any]] = None) -> AuditManager:
    """Initialize the global audit system"""
    global audit_manager
    audit_manager = AuditManager(config)
    return audit_manager

def get_audit_manager() -> AuditManager:
    """Get the global audit manager"""
    global audit_manager
    if audit_manager is None:
        audit_manager = initialize_audit_system()
    return audit_manager

# Example usage and testing
if __name__ == "__main__":
    # Initialize audit system
    manager = initialize_audit_system({
        'audit_log_file': 'test_audit.jsonl',
        'enable_console': True
    })
    
    logger = manager.get_audit_logger()
    
    # Test various audit events
    context = AuditContext(
        user_id=1,
        username="test_user",
        ip_address="192.168.1.100",
        session_id="sess_123"
    )
    
    with logger.audit_context(context):
        # Test authentication events
        logger.log_auth_success("test_user", 1, "192.168.1.100", "sess_123")
        logger.log_auth_failure("bad_user", "192.168.1.100", "Invalid password")
        
        # Test code execution
        logger.log_code_execution("abc123", "python", 0.5, True, {"lines": 10})
        
        # Test security analysis
        logger.log_security_analysis("abc123", 2, "high", 0.1, {"ast_violations": 1})
        
        # Test vulnerability detection
        logger.log_vulnerability_detected("code_injection", "critical", 5, "eval(user_input)")
        
        # Test rate limiting
        logger.log_rate_limit_exceeded("/api/execute", 10, 60)
        
        # Test API request
        logger.log_api_request("POST", "/api/execute", 200, 0.5)
        
        # Test operation timing
        with logger.operation_timer("test_operation"):
            time.sleep(0.1)  # Simulate work
        
        # Test error logging
        try:
            raise ValueError("Test error")
        except Exception as e:
            logger.log_system_error(e, {"context": "testing"})
    
    print("Audit system test completed. Check test_audit.jsonl for logs.")

