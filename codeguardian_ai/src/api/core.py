"""
CodeGuardian AI - Enterprise API Core
High-performance, secure API endpoints with comprehensive validation, monitoring, and error handling
"""

import time
import uuid
import asyncio
from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timezone, timedelta
from functools import wraps
import json
import logging

from flask import Blueprint, request, jsonify, g, current_app
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import redis

from src.middleware.security import SecurityMiddleware, require_api_key, require_admin
from src.middleware.rate_limiting import get_rate_limiter, RateLimitScope
from src.middleware.validation import (
    validate_request, CommonValidationRules, ValidationLevel, 
    ValidationRule, SanitizationMode, enterprise_validator
)
from src.auth.authentication import require_auth, get_current_user, UserRole
from src.audit.audit_system import get_audit_manager, EventType, LogLevel, SecurityLevel
from src.engines.security_analysis_enhanced import SecurityAnalysisEngine
from src.engines.code_execution import CodeExecutionEngine

# Create blueprint
api_core_bp = Blueprint('api_core', __name__)

# Initialize components
audit_manager = get_audit_manager()
rate_limiter = get_rate_limiter()

class APIResponse:
    """Standardized API response format"""
    
    @staticmethod
    def success(data: Any = None, message: str = "Success", meta: Dict[str, Any] = None) -> Dict[str, Any]:
        """Create success response"""
        response = {
            "success": True,
            "message": message,
            "data": data,
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "request_id": getattr(g, 'request_id', str(uuid.uuid4()))
        }
        
        if meta:
            response["meta"] = meta
        
        return response
    
    @staticmethod
    def error(message: str, code: str = "GENERIC_ERROR", details: Any = None, 
             status_code: int = 400) -> tuple[Dict[str, Any], int]:
        """Create error response"""
        response = {
            "success": False,
            "error": {
                "code": code,
                "message": message,
                "details": details
            },
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "request_id": getattr(g, 'request_id', str(uuid.uuid4()))
        }
        
        return response, status_code
    
    @staticmethod
    def validation_error(validation_result) -> tuple[Dict[str, Any], int]:
        """Create validation error response"""
        return APIResponse.error(
            message="Validation failed",
            code="VALIDATION_ERROR",
            details={
                "errors": validation_result.errors,
                "warnings": validation_result.warnings,
                "threat_score": validation_result.threat_score
            },
            status_code=400
        )

def performance_monitor(f):
    """Decorator to monitor API performance"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = time.time()
        
        try:
            result = f(*args, **kwargs)
            
            # Log successful request
            duration = time.time() - start_time
            audit_logger = audit_manager.get_audit_logger()
            audit_logger.log_event(
                EventType.API_REQUEST_COMPLETED,
                LogLevel.INFO,
                f"API request completed: {request.endpoint}",
                {
                    "endpoint": request.endpoint,
                    "method": request.method,
                    "duration_ms": round(duration * 1000, 2),
                    "status": "success",
                    "user_id": getattr(get_current_user(), 'id', None) if get_current_user() else None
                }
            )
            
            return result
            
        except Exception as e:
            # Log failed request
            duration = time.time() - start_time
            audit_logger = audit_manager.get_audit_logger()
            audit_logger.log_event(
                EventType.API_REQUEST_FAILED,
                LogLevel.ERROR,
                f"API request failed: {request.endpoint}",
                {
                    "endpoint": request.endpoint,
                    "method": request.method,
                    "duration_ms": round(duration * 1000, 2),
                    "error": str(e),
                    "user_id": getattr(get_current_user(), 'id', None) if get_current_user() else None
                },
                security_level=SecurityLevel.MEDIUM
            )
            
            raise
    
    return decorated_function

def rate_limit_check(scope: RateLimitScope = RateLimitScope.IP):
    """Decorator for rate limiting checks"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            # Determine identifier based on scope
            if scope == RateLimitScope.IP:
                identifier = request.remote_addr
            elif scope == RateLimitScope.USER:
                user = get_current_user()
                identifier = str(user.id) if user else request.remote_addr
            elif scope == RateLimitScope.API_KEY:
                api_key = request.headers.get('X-API-Key')
                identifier = api_key if api_key else request.remote_addr
            else:
                identifier = "global"
            
            # Check rate limit
            result = rate_limiter.check_rate_limit(identifier, request.path, request.method)
            
            if not result.allowed:
                return APIResponse.error(
                    message="Rate limit exceeded",
                    code="RATE_LIMIT_EXCEEDED",
                    details={
                        "retry_after": result.retry_after,
                        "reset_time": result.reset_time.isoformat()
                    },
                    status_code=429
                )
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

# API Endpoints

@api_core_bp.route('/analyze', methods=['POST'])
@performance_monitor
@rate_limit_check(RateLimitScope.USER)
@require_auth
def analyze_code():
    """Analyze code for security vulnerabilities and quality issues"""
    
    # Validate input
    validation_result = validate_request(
        CommonValidationRules.code_analysis(),
        ValidationLevel.STRICT
    )
    
    if not validation_result.is_valid:
        return APIResponse.validation_error(validation_result)
    
    data = validation_result.sanitized_data
    user = get_current_user()
    
    try:
        # Initialize security analysis engine
        security_engine = SecurityAnalysisEngine()
        
        # Perform analysis
        analysis_result = security_engine.analyze_code(
            code=data['code'],
            language=data['language'],
            analysis_type=data.get('analysis_type', 'all')
        )
        
        # Log analysis request
        audit_logger = audit_manager.get_audit_logger()
        audit_logger.log_event(
            EventType.CODE_ANALYSIS_REQUESTED,
            LogLevel.INFO,
            f"Code analysis completed for user {user.username}",
            {
                "user_id": user.id,
                "language": data['language'],
                "analysis_type": data.get('analysis_type', 'all'),
                "code_length": len(data['code']),
                "vulnerabilities_found": len(analysis_result.get('vulnerabilities', [])),
                "severity_high": len([v for v in analysis_result.get('vulnerabilities', []) if v.get('severity') == 'high'])
            }
        )
        
        return jsonify(APIResponse.success(
            data=analysis_result,
            message="Code analysis completed successfully",
            meta={
                "analysis_time": analysis_result.get('analysis_time'),
                "language": data['language'],
                "lines_analyzed": analysis_result.get('lines_analyzed', 0)
            }
        ))
        
    except Exception as e:
        current_app.logger.error(f"Code analysis failed: {str(e)}")
        return APIResponse.error(
            message="Code analysis failed",
            code="ANALYSIS_ERROR",
            details=str(e),
            status_code=500
        )

@api_core_bp.route('/execute', methods=['POST'])
@performance_monitor
@rate_limit_check(RateLimitScope.USER)
@require_auth
def execute_code():
    """Execute code in secure sandbox environment"""
    
    # Validate input
    validation_rules = [
        ValidationRule(
            field_name="code",
            required=True,
            data_type=str,
            min_length=1,
            max_length=50000,
            sanitization_mode=SanitizationMode.ESCAPE,
            validation_level=ValidationLevel.STRICT
        ),
        ValidationRule(
            field_name="language",
            required=True,
            data_type=str,
            allowed_values=["python", "javascript", "bash"],
            sanitization_mode=SanitizationMode.STRIP
        ),
        ValidationRule(
            field_name="timeout",
            required=False,
            data_type=int,
            min_value=1,
            max_value=30,
            sanitization_mode=SanitizationMode.STRIP
        )
    ]
    
    validation_result = validate_request(validation_rules, ValidationLevel.STRICT)
    
    if not validation_result.is_valid:
        return APIResponse.validation_error(validation_result)
    
    data = validation_result.sanitized_data
    user = get_current_user()
    
    # Check user permissions for code execution
    if user.role not in [UserRole.ADMIN, UserRole.PREMIUM]:
        return APIResponse.error(
            message="Code execution requires premium subscription",
            code="INSUFFICIENT_PERMISSIONS",
            status_code=403
        )
    
    try:
        # Initialize code execution engine
        execution_engine = CodeExecutionEngine()
        
        # Execute code
        execution_result = execution_engine.execute_code(
            code=data['code'],
            language=data['language'],
            timeout=data.get('timeout', 10)
        )
        
        # Log execution request
        audit_logger = audit_manager.get_audit_logger()
        audit_logger.log_event(
            EventType.CODE_EXECUTION_REQUESTED,
            LogLevel.INFO,
            f"Code execution completed for user {user.username}",
            {
                "user_id": user.id,
                "language": data['language'],
                "timeout": data.get('timeout', 10),
                "code_length": len(data['code']),
                "execution_time": execution_result.get('execution_time'),
                "success": execution_result.get('success', False)
            },
            security_level=SecurityLevel.MEDIUM
        )
        
        return jsonify(APIResponse.success(
            data=execution_result,
            message="Code execution completed successfully",
            meta={
                "language": data['language'],
                "execution_time": execution_result.get('execution_time'),
                "memory_used": execution_result.get('memory_used')
            }
        ))
        
    except Exception as e:
        current_app.logger.error(f"Code execution failed: {str(e)}")
        return APIResponse.error(
            message="Code execution failed",
            code="EXECUTION_ERROR",
            details=str(e),
            status_code=500
        )

@api_core_bp.route('/validate', methods=['POST'])
@performance_monitor
@rate_limit_check(RateLimitScope.IP)
def validate_input():
    """Validate input data without processing"""
    
    # Get validation rules from request
    try:
        request_data = request.get_json()
        if not request_data or 'data' not in request_data:
            return APIResponse.error(
                message="Request must contain 'data' field",
                code="INVALID_REQUEST",
                status_code=400
            )
        
        validation_level = ValidationLevel(
            request_data.get('validation_level', 'standard')
        )
        
        # Perform validation
        validation_result = enterprise_validator.validate_data(
            request_data['data'],
            [],  # No specific rules, just threat detection
            validation_level
        )
        
        return jsonify(APIResponse.success(
            data={
                "is_valid": validation_result.is_valid,
                "threat_score": validation_result.threat_score,
                "blocked_patterns": validation_result.blocked_patterns,
                "errors": validation_result.errors,
                "warnings": validation_result.warnings
            },
            message="Input validation completed"
        ))
        
    except Exception as e:
        return APIResponse.error(
            message="Validation failed",
            code="VALIDATION_ERROR",
            details=str(e),
            status_code=500
        )

@api_core_bp.route('/status', methods=['GET'])
@performance_monitor
def get_api_status():
    """Get API status and health information"""
    
    try:
        # Get system metrics
        import psutil
        
        status = {
            "api_version": "1.0.0",
            "status": "healthy",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "uptime": time.time() - getattr(current_app, 'start_time', time.time()),
            "system": {
                "cpu_usage": psutil.cpu_percent(),
                "memory_usage": psutil.virtual_memory().percent,
                "disk_usage": psutil.disk_usage('/').percent
            },
            "features": {
                "code_analysis": True,
                "code_execution": True,
                "threat_detection": True,
                "rate_limiting": True,
                "audit_logging": True
            }
        }
        
        return jsonify(APIResponse.success(
            data=status,
            message="API status retrieved successfully"
        ))
        
    except Exception as e:
        return APIResponse.error(
            message="Failed to retrieve API status",
            code="STATUS_ERROR",
            details=str(e),
            status_code=500
        )

@api_core_bp.route('/metrics', methods=['GET'])
@performance_monitor
@require_auth
def get_metrics():
    """Get API usage metrics (requires authentication)"""
    
    user = get_current_user()
    
    # Only admin users can access global metrics
    if user.role != UserRole.ADMIN:
        return APIResponse.error(
            message="Admin privileges required",
            code="INSUFFICIENT_PERMISSIONS",
            status_code=403
        )
    
    try:
        # Get rate limiter status
        rate_limit_status = rate_limiter.get_rate_limit_status(
            str(user.id), 
            request.path
        )
        
        metrics = {
            "rate_limits": rate_limit_status,
            "active_sessions": 0,  # Implement session tracking
            "total_requests": 0,   # Implement request counting
            "error_rate": 0.0,     # Implement error rate calculation
            "average_response_time": 0.0  # Implement response time tracking
        }
        
        return jsonify(APIResponse.success(
            data=metrics,
            message="Metrics retrieved successfully"
        ))
        
    except Exception as e:
        return APIResponse.error(
            message="Failed to retrieve metrics",
            code="METRICS_ERROR",
            details=str(e),
            status_code=500
        )

@api_core_bp.route('/admin/users', methods=['GET'])
@performance_monitor
@require_admin
def list_users():
    """List all users (admin only)"""
    
    try:
        from src.auth.authentication import AuthUser
        
        users = AuthUser.query.all()
        user_data = []
        
        for user in users:
            user_data.append({
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "role": user.role.value,
                "is_active": user.is_active,
                "created_at": user.created_at.isoformat(),
                "last_login": user.last_login.isoformat() if user.last_login else None
            })
        
        return jsonify(APIResponse.success(
            data=user_data,
            message="Users retrieved successfully",
            meta={"total_users": len(user_data)}
        ))
        
    except Exception as e:
        return APIResponse.error(
            message="Failed to retrieve users",
            code="USER_LIST_ERROR",
            details=str(e),
            status_code=500
        )

@api_core_bp.route('/admin/audit-logs', methods=['GET'])
@performance_monitor
@require_admin
def get_audit_logs():
    """Get audit logs (admin only)"""
    
    try:
        # Get query parameters
        limit = min(int(request.args.get('limit', 100)), 1000)
        offset = int(request.args.get('offset', 0))
        event_type = request.args.get('event_type')
        start_date = request.args.get('start_date')
        end_date = request.args.get('end_date')
        
        # This is a placeholder - implement actual audit log retrieval
        logs = []
        
        return jsonify(APIResponse.success(
            data=logs,
            message="Audit logs retrieved successfully",
            meta={
                "limit": limit,
                "offset": offset,
                "total": len(logs)
            }
        ))
        
    except Exception as e:
        return APIResponse.error(
            message="Failed to retrieve audit logs",
            code="AUDIT_LOG_ERROR",
            details=str(e),
            status_code=500
        )

# Error handlers
@api_core_bp.errorhandler(400)
def handle_bad_request(error):
    """Handle bad request errors"""
    return APIResponse.error(
        message="Bad request",
        code="BAD_REQUEST",
        details=str(error),
        status_code=400
    )

@api_core_bp.errorhandler(401)
def handle_unauthorized(error):
    """Handle unauthorized errors"""
    return APIResponse.error(
        message="Authentication required",
        code="UNAUTHORIZED",
        status_code=401
    )

@api_core_bp.errorhandler(403)
def handle_forbidden(error):
    """Handle forbidden errors"""
    return APIResponse.error(
        message="Access forbidden",
        code="FORBIDDEN",
        status_code=403
    )

@api_core_bp.errorhandler(404)
def handle_not_found(error):
    """Handle not found errors"""
    return APIResponse.error(
        message="Resource not found",
        code="NOT_FOUND",
        status_code=404
    )

@api_core_bp.errorhandler(429)
def handle_rate_limit(error):
    """Handle rate limit errors"""
    return APIResponse.error(
        message="Rate limit exceeded",
        code="RATE_LIMIT_EXCEEDED",
        details={"retry_after": getattr(error, 'retry_after', 60)},
        status_code=429
    )

@api_core_bp.errorhandler(500)
def handle_internal_error(error):
    """Handle internal server errors"""
    current_app.logger.error(f"Internal server error: {str(error)}")
    
    return APIResponse.error(
        message="Internal server error",
        code="INTERNAL_ERROR",
        status_code=500
    )

# Initialize blueprint
def init_api_core(app):
    """Initialize API core with Flask app"""
    
    # Register blueprint
    app.register_blueprint(api_core_bp, url_prefix='/api/v1')
    
    # Store app start time for uptime calculation
    app.start_time = time.time()
    
    # Initialize security middleware
    security_middleware = SecurityMiddleware(app)
    
    current_app.logger.info("API Core initialized successfully")

