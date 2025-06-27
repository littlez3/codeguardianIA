"""
CodeGuardian AI - Enhanced API Routes with Robust Validation
Enterprise-grade API with Pydantic validation and comprehensive sanitization
"""

from flask import Blueprint, request, jsonify, g
import time
import uuid
import json
import hashlib
from typing import Dict, Any

from src.engines.code_execution import CodeExecutionEngine, ExecutionLimits
from src.engines.security_analysis_enhanced import SecurityAnalysisEngine
from src.engines.ast_validator import SecurityLevel
from src.auth.simple_auth import require_auth, optional_auth, UserRole, get_client_ip
from src.auth.rate_limiting import rate_limit, RateLimit, RateLimitStrategy
from src.audit.audit_system import get_audit_manager, AuditContext, EventType, LogLevel, SecurityLevel as AuditSecurityLevel
from src.validation.input_validation_v2 import (
    CodeExecutionRequest, SecurityAnalysisRequest, AuthLoginRequest, 
    AuthRegisterRequest, ApiKeyCreateRequest, validate_request_data,
    create_validation_error_response, get_security_headers, sanitize_response_data,
    SanitizationLevel
)
from pydantic import ValidationError

# Create blueprint for API routes
api_bp = Blueprint('api', __name__)

# Initialize engines
execution_engine = CodeExecutionEngine()
security_engine = SecurityAnalysisEngine()

# Get audit manager
audit_manager = get_audit_manager()
audit_logger = audit_manager.get_audit_logger()

def add_security_headers(response):
    """Add security headers to response"""
    headers = get_security_headers()
    for key, value in headers.items():
        response.headers[key] = value
    return response

def handle_validation_error(error: ValidationError) -> tuple:
    """Handle Pydantic validation errors"""
    error_response = create_validation_error_response(error)
    
    # Log validation failure
    audit_logger.log_event(
        event_type=EventType.API_ERROR,
        message="Request validation failed",
        level=LogLevel.WARNING,
        security_level=AuditSecurityLevel.INTERNAL,
        details=error_response,
        tags=['validation', 'error', 'security']
    )
    
    response = jsonify(error_response)
    response.status_code = 400
    return add_security_headers(response), 400

def create_audit_context() -> AuditContext:
    """Create audit context for current request"""
    return AuditContext(
        user_id=getattr(request, 'current_user', {}).get('id') if hasattr(request, 'current_user') else None,
        session_id=getattr(g, 'session_id', None),
        ip_address=get_client_ip(),
        user_agent=request.headers.get('User-Agent', 'Unknown'),
        request_id=str(uuid.uuid4())
    )

@api_bp.before_request
def before_request():
    """Set up request context and logging"""
    g.request_id = str(uuid.uuid4())
    g.start_time = time.time()
    
    # Log API request start
    audit_logger.log_event(
        event_type=EventType.API_REQUEST,
        message=f"{request.method} {request.endpoint} - START",
        level=LogLevel.INFO,
        security_level=AuditSecurityLevel.INTERNAL,
        details={
            'method': request.method,
            'endpoint': request.endpoint,
            'content_length': request.content_length,
            'content_type': request.content_type
        },
        context=create_audit_context(),
        tags=['api', 'request', 'start']
    )

@api_bp.after_request
def after_request(response):
    """Log API request completion and add security headers"""
    response_time = time.time() - g.start_time
    
    # Log API request completion
    audit_logger.log_event(
        event_type=EventType.API_REQUEST,
        message=f"{request.method} {request.endpoint} - {response.status_code} ({response_time:.3f}s)",
        level=LogLevel.INFO,
        security_level=AuditSecurityLevel.INTERNAL,
        details={
            'method': request.method,
            'endpoint': request.endpoint,
            'status_code': response.status_code,
            'response_time': response_time,
            'request_id': g.request_id,
            'content_length': response.content_length,
            'content_type': response.content_type
        },
        context=create_audit_context(),
        tags=['api', 'request', str(response.status_code)]
    )
    
    return add_security_headers(response)

@api_bp.route('/health', methods=['GET'])
@rate_limit(RateLimit(requests=60, window_seconds=60, strategy=RateLimitStrategy.FIXED_WINDOW))
def health():
    """Health check endpoint with validation"""
    try:
        result = {
            'status': 'healthy',
            'service': 'CodeGuardian AI',
            'version': '1.0.0',
            'timestamp': time.time(),
            'components': {
                'execution_engine': 'operational',
                'security_engine': 'operational',
                'audit_system': 'operational',
                'validation_system': 'operational'
            }
        }
        
        # Sanitize response
        sanitized_result = sanitize_response_data(result, SanitizationLevel.BASIC)
        
        response = jsonify(sanitized_result)
        return add_security_headers(response)
        
    except Exception as e:
        audit_logger.log_event(
            event_type=EventType.API_ERROR,
            message=f"Health check failed: {str(e)}",
            level=LogLevel.ERROR,
            security_level=AuditSecurityLevel.INTERNAL,
            details={'error': str(e)},
            tags=['health', 'error']
        )
        
        error_response = jsonify({'error': 'Health check failed', 'message': 'Internal server error'})
        error_response.status_code = 500
        return add_security_headers(error_response), 500

@api_bp.route('/execute', methods=['POST'])
@rate_limit(RateLimit(requests=10, window_seconds=60, strategy=RateLimitStrategy.SLIDING_WINDOW))
@optional_auth()
def execute_code():
    """Execute code with robust validation and sanitization"""
    try:
        # Validate request data
        try:
            validated_request = validate_request_data(request.get_json() or {}, CodeExecutionRequest)
        except ValidationError as e:
            return handle_validation_error(e)
        
        # Extract validated data
        code = validated_request.code
        language = validated_request.language
        custom_limits = validated_request.limits
        
        # Create code hash for tracking
        code_hash = hashlib.md5(code.encode()).hexdigest()[:16]
        
        # Log code execution start
        audit_logger.log_event(
            event_type=EventType.CODE_EXECUTION_START,
            message="Code execution started",
            level=LogLevel.INFO,
            security_level=AuditSecurityLevel.CONFIDENTIAL,
            details={
                'code_hash': code_hash,
                'language': language,
                'code_length': len(code),
                'has_custom_limits': custom_limits is not None
            },
            context=create_audit_context(),
            tags=['execution', 'start']
        )
        
        # Execute code with performance tracking
        user = getattr(request, 'current_user', None)
        limits = ExecutionLimits()
        
        # Apply user-specific limits
        if user and user.role == UserRole.ADMIN:
            limits.timeout_seconds = 30
            limits.max_memory_mb = 512
        elif user and user.role == UserRole.DEVELOPER:
            limits.timeout_seconds = 20
            limits.max_memory_mb = 256
        elif user and user.role == UserRole.ANALYST:
            limits.timeout_seconds = 15
            limits.max_memory_mb = 192
        else:  # Viewer or anonymous
            limits.timeout_seconds = 10
            limits.max_memory_mb = 128
        
        # Apply custom limits if provided (with validation)
        if custom_limits:
            if 'timeout_seconds' in custom_limits:
                limits.timeout_seconds = min(custom_limits['timeout_seconds'], limits.timeout_seconds)
            if 'max_memory_mb' in custom_limits:
                limits.max_memory_mb = min(custom_limits['max_memory_mb'], limits.max_memory_mb)
        
        execution_start = time.time()
        
        # Create execution engine with custom limits if needed
        if custom_limits or (user and user.role in [UserRole.ADMIN, UserRole.DEVELOPER]):
            custom_engine = CodeExecutionEngine(limits=limits)
            result = custom_engine.execute(code, language)
        else:
            result = execution_engine.execute(code, language)
        
        execution_time = time.time() - execution_start
        
        # Log execution result
        audit_logger.log_event(
            event_type=EventType.CODE_EXECUTION_COMPLETED if result.success else EventType.CODE_EXECUTION_FAILED,
            message=f"Code execution {'completed' if result.success else 'failed'}",
            level=LogLevel.INFO if result.success else LogLevel.WARNING,
            security_level=AuditSecurityLevel.CONFIDENTIAL,
            details={
                'code_hash': code_hash,
                'success': result.success,
                'execution_time': execution_time,
                'exit_code': result.exit_code,
                'stdout_length': len(result.stdout) if result.stdout else 0,
                'stderr_length': len(result.stderr) if result.stderr else 0,
                'memory_used': result.memory_used
            },
            context=create_audit_context(),
            tags=['execution', 'completed' if result.success else 'failed']
        )
        
        # Prepare response
        response_data = {
            'success': result.success,
            'stdout': result.stdout,
            'stderr': result.stderr,
            'exit_code': result.exit_code,
            'execution_time': result.execution_time,
            'memory_used': result.memory_used,
            'language': language,
            'code': code,
            'execution_id': result.execution_id,
            'timestamp': result.timestamp,
            'error_message': result.error_message,
            'audit': {
                'code_hash': code_hash,
                'request_id': g.request_id,
                'execution_time': execution_time
            }
        }
        
        # Sanitize response data
        sanitized_response = sanitize_response_data(response_data, SanitizationLevel.BASIC)
        
        response = jsonify(sanitized_response)
        return add_security_headers(response)
        
    except Exception as e:
        audit_logger.log_event(
            event_type=EventType.API_ERROR,
            message=f"Code execution error: {str(e)}",
            level=LogLevel.ERROR,
            security_level=AuditSecurityLevel.RESTRICTED,
            details={'error': str(e), 'code_hash': locals().get('code_hash', 'unknown')},
            context=create_audit_context(),
            tags=['execution', 'error']
        )
        
        error_response = jsonify({
            'error': 'Execution failed',
            'message': 'An error occurred during code execution',
            'success': False
        })
        error_response.status_code = 500
        return add_security_headers(error_response), 500

@api_bp.route('/analyze', methods=['POST'])
@rate_limit(RateLimit(requests=20, window_seconds=60, strategy=RateLimitStrategy.SLIDING_WINDOW))
@optional_auth()
def analyze_security():
    """Analyze code security with robust validation"""
    try:
        # Validate request data
        try:
            validated_request = validate_request_data(request.get_json() or {}, SecurityAnalysisRequest)
        except ValidationError as e:
            return handle_validation_error(e)
        
        # Extract validated data
        code = validated_request.code
        language = validated_request.language
        security_level = validated_request.security_level
        
        # Create code hash for tracking
        code_hash = hashlib.md5(code.encode()).hexdigest()[:16]
        
        # Log analysis start
        audit_logger.log_event(
            event_type=EventType.SECURITY_ANALYSIS_START,
            message="Security analysis started",
            level=LogLevel.INFO,
            security_level=AuditSecurityLevel.CONFIDENTIAL,
            details={
                'code_hash': code_hash,
                'language': language,
                'security_level': security_level,
                'code_length': len(code)
            },
            context=create_audit_context(),
            tags=['security', 'analysis', 'start']
        )
        
        # Perform security analysis
        analysis_start = time.time()
        result = security_engine.analyze(code, language)
        analysis_time = time.time() - analysis_start
        
        # Log vulnerabilities found
        for vulnerability in result.vulnerabilities:
            if vulnerability['severity'] in ['critical', 'high']:
                audit_logger.log_event(
                    event_type=EventType.SECURITY_VULNERABILITY_DETECTED,
                    message=f"{vulnerability['severity'].upper()} vulnerability detected: {vulnerability['type']}",
                    level=LogLevel.ERROR if vulnerability['severity'] == 'critical' else LogLevel.WARNING,
                    security_level=AuditSecurityLevel.RESTRICTED,
                    details={
                        'vulnerability_type': vulnerability['type'],
                        'severity': vulnerability['severity'],
                        'line_number': vulnerability['line_number'],
                        'code_snippet': vulnerability['code_snippet'],
                        'description': vulnerability['description'],
                        'confidence': vulnerability['confidence'],
                        'cwe_id': vulnerability['cwe_id'],
                        'cvss_score': vulnerability['cvss_score'],
                        'mitigation': vulnerability['mitigation']
                    },
                    context=create_audit_context(),
                    tags=['security', 'vulnerability', vulnerability['severity'], vulnerability['type']]
                )
        
        # Log analysis completion
        audit_logger.log_event(
            event_type=EventType.SECURITY_ANALYSIS_COMPLETED,
            message=f"Security analysis completed: {result.summary['total_vulnerabilities']} vulnerabilities found",
            level=LogLevel.INFO,
            security_level=AuditSecurityLevel.CONFIDENTIAL,
            details={
                'code_hash': code_hash,
                'analysis_time': analysis_time,
                'total_vulnerabilities': result.summary['total_vulnerabilities'],
                'critical_count': result.summary['critical_count'],
                'high_count': result.summary['high_count'],
                'medium_count': result.summary['medium_count'],
                'low_count': result.summary['low_count']
            },
            context=create_audit_context(),
            tags=['security', 'analysis', 'completed']
        )
        
        # Prepare response
        response_data = result.to_dict()
        response_data['audit'] = {
            'code_hash': code_hash,
            'request_id': g.request_id,
            'analysis_time': analysis_time
        }
        
        # Sanitize response data
        sanitized_response = sanitize_response_data(response_data, SanitizationLevel.BASIC)
        
        response = jsonify(sanitized_response)
        return add_security_headers(response)
        
    except Exception as e:
        audit_logger.log_event(
            event_type=EventType.API_ERROR,
            message=f"Security analysis error: {str(e)}",
            level=LogLevel.ERROR,
            security_level=AuditSecurityLevel.RESTRICTED,
            details={'error': str(e), 'code_hash': locals().get('code_hash', 'unknown')},
            context=create_audit_context(),
            tags=['security', 'analysis', 'error']
        )
        
        error_response = jsonify({
            'error': 'Analysis failed',
            'message': 'An error occurred during security analysis'
        })
        error_response.status_code = 500
        return add_security_headers(error_response), 500

@api_bp.route('/validate', methods=['POST'])
@rate_limit(RateLimit(requests=15, window_seconds=60, strategy=RateLimitStrategy.SLIDING_WINDOW))
@optional_auth()
def validate_code():
    """Comprehensive code validation (security + execution) with robust input validation"""
    try:
        # Validate request data
        try:
            validated_request = validate_request_data(request.get_json() or {}, CodeExecutionRequest)
        except ValidationError as e:
            return handle_validation_error(e)
        
        # Extract validated data
        code = validated_request.code
        language = validated_request.language
        
        # Create code hash for tracking
        code_hash = hashlib.md5(code.encode()).hexdigest()[:16]
        
        # Log validation start
        audit_logger.log_event(
            event_type=EventType.CODE_VALIDATION_START,
            message="Code validation started",
            level=LogLevel.INFO,
            security_level=AuditSecurityLevel.CONFIDENTIAL,
            details={
                'code_hash': code_hash,
                'language': language,
                'code_length': len(code)
            },
            context=create_audit_context(),
            tags=['validation', 'start']
        )
        
        # Security analysis first
        analysis_start = time.time()
        security_result = security_engine.analyze(code, language)
        analysis_time = time.time() - analysis_start
        
        # Code execution if security allows
        execution_result = None
        execution_time = 0
        
        # Only execute if no critical vulnerabilities
        if security_result.critical_count == 0:
            user = getattr(request, 'current_user', None)
            limits = ExecutionLimits()
            if user and user.role == UserRole.ADMIN:
                limits.timeout_seconds = 30
                limits.max_memory_mb = 512
            
            execution_start = time.time()
            
            # Create execution engine with custom limits
            if user and user.role == UserRole.ADMIN:
                limits.timeout_seconds = 30
                limits.max_memory_mb = 512
                custom_engine = CodeExecutionEngine(limits=limits)
                execution_result = custom_engine.execute(code, language)
            else:
                execution_result = execution_engine.execute(code, language)
            
            execution_time = time.time() - execution_start
        else:
            audit_logger.log_event(
                event_type=EventType.CODE_EXECUTION_BLOCKED,
                message=f"Code execution blocked due to {security_result.critical_count} critical vulnerabilities",
                level=LogLevel.WARNING,
                security_level=AuditSecurityLevel.CONFIDENTIAL,
                details={
                    'code_hash': code_hash,
                    'critical_vulnerabilities': security_result.critical_count
                },
                context=create_audit_context(),
                tags=['security', 'blocked', 'critical']
            )
        
        # Prepare comprehensive result
        result = {
            'security_analysis': security_result.to_dict(),
            'execution_result': execution_result.to_dict() if execution_result else None,
            'validation_summary': {
                'security_passed': security_result.critical_count == 0,
                'execution_attempted': execution_result is not None,
                'execution_passed': execution_result.success if execution_result else False,
                'overall_status': 'passed' if (security_result.critical_count == 0 and 
                                             execution_result and execution_result.success) else 'failed'
            },
            'audit': {
                'code_hash': code_hash,
                'request_id': g.request_id,
                'analysis_time': analysis_time,
                'execution_time': execution_time,
                'total_time': analysis_time + execution_time
            }
        }
        
        # Sanitize response data
        sanitized_result = sanitize_response_data(result, SanitizationLevel.BASIC)
        
        response = jsonify(sanitized_result)
        return add_security_headers(response)
        
    except Exception as e:
        audit_logger.log_event(
            event_type=EventType.API_ERROR,
            message=f"Code validation error: {str(e)}",
            level=LogLevel.ERROR,
            security_level=AuditSecurityLevel.RESTRICTED,
            details={'error': str(e), 'code_hash': locals().get('code_hash', 'unknown')},
            context=create_audit_context(),
            tags=['validation', 'error']
        )
        
        error_response = jsonify({
            'error': 'Validation failed',
            'message': 'An error occurred during code validation'
        })
        error_response.status_code = 500
        return add_security_headers(error_response), 500

@api_bp.route('/stats', methods=['GET'])
@rate_limit(RateLimit(requests=30, window_seconds=60, strategy=RateLimitStrategy.FIXED_WINDOW))
@require_auth()
def get_stats():
    """Get system statistics with authentication required"""
    try:
        user = getattr(request, 'current_user', None)
        if not user:
            error_response = jsonify({'error': 'Authentication required'})
            error_response.status_code = 401
            return add_security_headers(error_response), 401
        
        # Get audit statistics
        stats = audit_manager.get_statistics()
        
        # Add system information
        stats.update({
            'system': {
                'version': '1.0.0',
                'uptime': time.time() - audit_manager.start_time,
                'components': {
                    'execution_engine': 'operational',
                    'security_engine': 'operational',
                    'audit_system': 'operational',
                    'validation_system': 'operational'
                }
            },
            'user_info': {
                'username': user.username,
                'role': user.role.value,
                'permissions': ['execute', 'analyze', 'validate', 'stats']
            }
        })
        
        # Sanitize response data
        sanitized_stats = sanitize_response_data(stats, SanitizationLevel.BASIC)
        
        response = jsonify(sanitized_stats)
        return add_security_headers(response)
        
    except Exception as e:
        audit_logger.log_event(
            event_type=EventType.API_ERROR,
            message=f"Stats retrieval error: {str(e)}",
            level=LogLevel.ERROR,
            security_level=AuditSecurityLevel.INTERNAL,
            details={'error': str(e)},
            context=create_audit_context(),
            tags=['stats', 'error']
        )
        
        error_response = jsonify({
            'error': 'Stats retrieval failed',
            'message': 'An error occurred while retrieving statistics'
        })
        error_response.status_code = 500
        return add_security_headers(error_response), 500

