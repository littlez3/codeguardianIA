"""
CodeGuardian AI - Enhanced API Routes with Comprehensive Audit Integration
REST API endpoints with full audit trail, performance monitoring and security logging
"""

from flask import Blueprint, request, jsonify, g
from flask_cors import cross_origin
import time
import json
import hashlib
from typing import Dict, Any

from src.engines.code_execution import CodeExecutionEngine, ExecutionLimits
from src.engines.security_analysis_enhanced import SecurityAnalysisEngine
from src.engines.ast_validator import SecurityLevel
from src.auth.simple_auth import require_auth, optional_auth, UserRole, get_client_ip
from src.auth.rate_limiting import rate_limit, RateLimit, RateLimitStrategy
from src.audit.audit_system import get_audit_manager, AuditContext, EventType, LogLevel, SecurityLevel as AuditSecurityLevel

# Create blueprint for API routes
api_bp = Blueprint('api', __name__)

# Initialize engines with enhanced security
execution_engine = CodeExecutionEngine()
security_engine = SecurityAnalysisEngine(SecurityLevel.MODERATE)

# Get audit manager
audit_manager = get_audit_manager()

def setup_audit_context():
    """Setup audit context for the current request"""
    user = getattr(request, 'current_user', None)
    context = AuditContext(
        user_id=user.id if user else None,
        username=user.username if user else None,
        session_id=getattr(request, 'session_id', None),
        ip_address=get_client_ip(),
        user_agent=request.headers.get('User-Agent'),
        request_id=getattr(g, 'request_id', None),
        api_key_id=getattr(request, 'api_key_id', None)
    )
    
    # Set context in audit logger
    audit_logger = audit_manager.get_audit_logger()
    audit_logger.set_context(context)
    
    return context

@api_bp.before_request
def before_request():
    """Setup request tracking and audit context"""
    import uuid
    g.request_id = str(uuid.uuid4())
    g.request_start_time = time.time()
    
    # Setup audit context
    setup_audit_context()

@api_bp.after_request
def after_request(response):
    """Log API request completion"""
    if hasattr(g, 'request_start_time'):
        response_time = time.time() - g.request_start_time
        
        # Log API request
        audit_logger = audit_manager.get_audit_logger()
        audit_logger.log_api_request(
            method=request.method,
            endpoint=request.endpoint or request.path,
            status_code=response.status_code,
            response_time=response_time,
            details={
                'request_id': getattr(g, 'request_id', None),
                'content_length': response.content_length,
                'content_type': response.content_type
            }
        )
    
    return response

@api_bp.route('/health', methods=['GET'])
@cross_origin()
def health_check():
    """Health check endpoint with audit logging"""
    audit_logger = audit_manager.get_audit_logger()
    
    with audit_logger.operation_timer("health_check", EventType.SYSTEM_HEALTH_CHECK):
        health_status = {
            'status': 'healthy',
            'timestamp': time.time(),
            'services': {
                'code_execution': 'operational',
                'security_analysis': 'operational',
                'authentication': 'operational',
                'rate_limiting': 'operational',
                'audit_system': 'operational'
            },
            'request_id': getattr(g, 'request_id', None)
        }
    
    return jsonify(health_status)

@api_bp.route('/execute', methods=['POST'])
@cross_origin()
@optional_auth()
@rate_limit('execute', RateLimit(10, 60, RateLimitStrategy.SLIDING_WINDOW))
def execute_code():
    """Execute code in secure sandbox with comprehensive audit trail"""
    audit_logger = audit_manager.get_audit_logger()
    security_logger = audit_manager.get_security_logger()
    performance_logger = audit_manager.get_performance_logger()
    
    try:
        data = request.get_json()
        
        if not data:
            audit_logger.log_event(
                event_type=EventType.API_ERROR,
                message="No JSON data provided for code execution",
                level=LogLevel.WARNING,
                details={'endpoint': '/execute', 'error': 'missing_json_data'}
            )
            return jsonify({'error': 'No JSON data provided'}), 400
        
        code = data.get('code')
        language = data.get('language', 'python')
        
        if not code:
            audit_logger.log_event(
                event_type=EventType.API_ERROR,
                message="Code parameter is required",
                level=LogLevel.WARNING,
                details={'endpoint': '/execute', 'error': 'missing_code'}
            )
            return jsonify({'error': 'Code is required'}), 400
        
        # Generate code hash for tracking
        code_hash = hashlib.sha256(code.encode()).hexdigest()[:16]
        
        # Check if user is authenticated for enhanced limits
        user = getattr(request, 'current_user', None)
        
        # Setup execution limits based on user role
        limits = ExecutionLimits()
        if user:
            if user.role == UserRole.ADMIN:
                limits.timeout_seconds = 30
                limits.max_memory_mb = 512
            elif user.role == UserRole.DEVELOPER:
                limits.timeout_seconds = 20
                limits.max_memory_mb = 256
            elif user.role == UserRole.ANALYST:
                limits.timeout_seconds = 15
                limits.max_memory_mb = 192
        
        # Override with custom limits if provided
        if 'limits' in data:
            limit_data = data['limits']
            if 'timeout_seconds' in limit_data:
                limits.timeout_seconds = min(limit_data['timeout_seconds'], limits.timeout_seconds)
            if 'max_memory_mb' in limit_data:
                limits.max_memory_mb = min(limit_data['max_memory_mb'], limits.max_memory_mb)
        
        # Log code execution start
        audit_logger.log_event(
            event_type=EventType.CODE_EXECUTION_START,
            message=f"Starting code execution for {language}",
            level=LogLevel.INFO,
            security_level=AuditSecurityLevel.INTERNAL,
            details={
                'code_hash': code_hash,
                'language': language,
                'code_length': len(code),
                'limits': {
                    'timeout_seconds': limits.timeout_seconds,
                    'max_memory_mb': limits.max_memory_mb
                }
            },
            tags=['code_execution', 'start', language]
        )
        
        # Execute code with performance monitoring
        with performance_logger.operation_timer("code_execution", EventType.CODE_EXECUTION_SUCCESS):
            start_time = time.time()
            
            # Create new execution engine with custom limits if needed
            if user and limits != ExecutionLimits():
                custom_engine = CodeExecutionEngine(limits=limits)
                result = custom_engine.execute(code, language)
            else:
                result = execution_engine.execute(code, language)
            
            execution_time = time.time() - start_time
        
        # Log execution result
        success = result.success
        if success:
            audit_logger.log_code_execution(
                code_hash=code_hash,
                language=language,
                execution_time=execution_time,
                success=True,
                details={
                    'output_length': len(result.stdout),
                    'exit_code': result.exit_code,
                    'memory_used': result.memory_used,
                    'execution_id': result.execution_id
                }
            )
        else:
            error_msg = result.error_message or 'Unknown error'
            audit_logger.log_event(
                event_type=EventType.CODE_EXECUTION_FAILURE,
                message=f"Code execution failed: {error_msg}",
                level=LogLevel.ERROR,
                security_level=AuditSecurityLevel.INTERNAL,
                details={
                    'code_hash': code_hash,
                    'language': language,
                    'execution_time': execution_time,
                    'error': error_msg,
                    'exit_code': result.exit_code,
                    'stderr': result.stderr
                },
                tags=['code_execution', 'failure', language]
            )
        
        # Convert ExecutionResult to dict and add audit metadata
        result_dict = result.to_dict()
        result_dict['audit'] = {
            'code_hash': code_hash,
            'request_id': getattr(g, 'request_id', None),
            'execution_time': execution_time
        }
        
        return jsonify(result_dict)
        
    except Exception as e:
        # Log system error
        audit_logger.log_system_error(e, {
            'endpoint': '/execute',
            'code_hash': locals().get('code_hash', 'unknown'),
            'language': locals().get('language', 'unknown')
        })
        
        return jsonify({
            'error': 'Internal server error',
            'request_id': getattr(g, 'request_id', None)
        }), 500

@api_bp.route('/analyze', methods=['POST'])
@cross_origin()
@optional_auth()
@rate_limit('analyze', RateLimit(20, 60, RateLimitStrategy.SLIDING_WINDOW))
def analyze_security():
    """Analyze code for security vulnerabilities with comprehensive audit trail"""
    audit_logger = audit_manager.get_audit_logger()
    security_logger = audit_manager.get_security_logger()
    
    try:
        data = request.get_json()
        
        if not data:
            audit_logger.log_event(
                event_type=EventType.API_ERROR,
                message="No JSON data provided for security analysis",
                level=LogLevel.WARNING,
                details={'endpoint': '/analyze', 'error': 'missing_json_data'}
            )
            return jsonify({'error': 'No JSON data provided'}), 400
        
        code = data.get('code')
        language = data.get('language', 'python')
        
        if not code:
            audit_logger.log_event(
                event_type=EventType.API_ERROR,
                message="Code parameter is required for analysis",
                level=LogLevel.WARNING,
                details={'endpoint': '/analyze', 'error': 'missing_code'}
            )
            return jsonify({'error': 'Code is required'}), 400
        
        # Generate code hash for tracking
        code_hash = hashlib.sha256(code.encode()).hexdigest()[:16]
        
        # Log security analysis start
        security_logger.log_event(
            event_type=EventType.SECURITY_ANALYSIS_START,
            message=f"Starting security analysis for {language} code",
            level=LogLevel.INFO,
            security_level=AuditSecurityLevel.CONFIDENTIAL,
            details={
                'code_hash': code_hash,
                'language': language,
                'code_length': len(code)
            },
            tags=['security', 'analysis', 'start', language]
        )
        
        # Perform security analysis
        start_time = time.time()
        analysis_result = security_engine.analyze(code, language)
        analysis_time = time.time() - start_time
        
        # Log analysis completion
        security_logger.log_security_analysis(
            code_hash=code_hash,
            vulnerability_count=analysis_result.total_vulnerabilities,
            max_severity=analysis_result.max_severity,
            analysis_time=analysis_time,
            details={
                'critical_count': analysis_result.critical_count,
                'high_count': analysis_result.high_count,
                'medium_count': analysis_result.medium_count,
                'low_count': analysis_result.low_count,
                'ast_validation': analysis_result.ast_validation_result is not None
            }
        )
        
        # Log individual vulnerabilities
        for vuln in analysis_result.vulnerabilities:
            security_logger.log_vulnerability_detected(
                vulnerability_type=vuln.type.value,
                severity=vuln.severity,
                line_number=vuln.line_number,
                code_snippet=vuln.code_snippet,
                details={
                    'description': vuln.description,
                    'confidence': vuln.confidence,
                    'cwe_id': vuln.cwe_id,
                    'cvss_score': vuln.cvss_score,
                    'mitigation': vuln.mitigation
                }
            )
        
        # Convert to dict and add audit metadata
        result = analysis_result.to_dict()
        result['audit'] = {
            'code_hash': code_hash,
            'request_id': getattr(g, 'request_id', None),
            'analysis_time': analysis_time
        }
        
        return jsonify(result)
        
    except Exception as e:
        # Log system error
        security_logger.log_system_error(e, {
            'endpoint': '/analyze',
            'code_hash': locals().get('code_hash', 'unknown'),
            'language': locals().get('language', 'unknown')
        })
        
        return jsonify({
            'error': 'Internal server error',
            'request_id': getattr(g, 'request_id', None)
        }), 500

@api_bp.route('/validate', methods=['POST'])
@cross_origin()
@optional_auth()
@rate_limit('validate', RateLimit(15, 60, RateLimitStrategy.SLIDING_WINDOW))
def validate_code():
    """Comprehensive code validation (execution + security analysis) with audit trail"""
    audit_logger = audit_manager.get_audit_logger()
    
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        code = data.get('code')
        language = data.get('language', 'python')
        
        if not code:
            return jsonify({'error': 'Code is required'}), 400
        
        # Generate code hash for tracking
        code_hash = hashlib.sha256(code.encode()).hexdigest()[:16]
        
        # Log validation start
        audit_logger.log_event(
            event_type=EventType.CODE_EXECUTION_START,
            message=f"Starting comprehensive code validation for {language}",
            level=LogLevel.INFO,
            security_level=AuditSecurityLevel.INTERNAL,
            details={
                'code_hash': code_hash,
                'language': language,
                'validation_type': 'comprehensive'
            },
            tags=['validation', 'start', language]
        )
        
        # Perform both security analysis and execution
        with audit_logger.operation_timer("comprehensive_validation"):
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
                'request_id': getattr(g, 'request_id', None),
                'analysis_time': analysis_time,
                'execution_time': execution_time,
                'total_time': analysis_time + execution_time
            }
        }
        
        return jsonify(result)
        
    except Exception as e:
        # Log system error
        audit_logger.log_system_error(e, {
            'endpoint': '/validate',
            'code_hash': locals().get('code_hash', 'unknown'),
            'language': locals().get('language', 'unknown')
        })
        
        return jsonify({
            'error': 'Internal server error',
            'request_id': getattr(g, 'request_id', None)
        }), 500

@api_bp.route('/audit/stats', methods=['GET'])
@cross_origin()
@require_auth()
def audit_stats():
    """Get audit statistics (requires authentication)"""
    try:
        # Check if user has analyst role or higher
        user = getattr(request, 'current_user', None)
        if not user or user.role not in [UserRole.ANALYST, UserRole.DEVELOPER, UserRole.ADMIN]:
            return jsonify({'error': 'Insufficient permissions'}), 403
        # This would typically query a database or log aggregation system
        # For now, return basic stats
        stats = {
            'total_requests': 'N/A - requires log aggregation',
            'security_events': 'N/A - requires log aggregation',
            'performance_metrics': 'N/A - requires log aggregation',
            'error_rate': 'N/A - requires log aggregation',
            'message': 'Audit statistics require log aggregation system (ELK, Splunk, etc.)'
        }
        
        return jsonify(stats)
        
    except Exception as e:
        audit_logger = audit_manager.get_audit_logger()
        audit_logger.log_system_error(e, {'endpoint': '/audit/stats'})
        return jsonify({'error': 'Internal server error'}), 500

# Error handlers with audit logging
@api_bp.errorhandler(429)
def rate_limit_handler(e):
    """Handle rate limit exceeded with audit logging"""
    audit_logger = audit_manager.get_audit_logger()
    audit_logger.log_rate_limit_exceeded(
        endpoint=request.endpoint or request.path,
        limit=0,  # Would need to extract from rate limiter
        window=60,
        details={
            'user_agent': request.headers.get('User-Agent'),
            'request_id': getattr(g, 'request_id', None)
        }
    )
    
    return jsonify({
        'error': 'Rate limit exceeded',
        'message': 'Too many requests. Please try again later.',
        'request_id': getattr(g, 'request_id', None)
    }), 429

@api_bp.errorhandler(401)
def unauthorized_handler(e):
    """Handle unauthorized access with audit logging"""
    audit_logger = audit_manager.get_audit_logger()
    audit_logger.log_event(
        event_type=EventType.AUTH_LOGIN_FAILURE,
        message="Unauthorized API access attempt",
        level=LogLevel.WARNING,
        security_level=AuditSecurityLevel.CONFIDENTIAL,
        details={
            'endpoint': request.endpoint or request.path,
            'user_agent': request.headers.get('User-Agent'),
            'request_id': getattr(g, 'request_id', None)
        },
        tags=['security', 'unauthorized', 'api']
    )
    
    return jsonify({
        'error': 'Unauthorized',
        'message': 'Authentication required',
        'request_id': getattr(g, 'request_id', None)
    }), 401

@api_bp.errorhandler(403)
def forbidden_handler(e):
    """Handle forbidden access with audit logging"""
    audit_logger = audit_manager.get_audit_logger()
    audit_logger.log_event(
        event_type=EventType.AUTH_LOGIN_FAILURE,
        message="Forbidden API access attempt",
        level=LogLevel.WARNING,
        security_level=AuditSecurityLevel.CONFIDENTIAL,
        details={
            'endpoint': request.endpoint or request.path,
            'user_agent': request.headers.get('User-Agent'),
            'request_id': getattr(g, 'request_id', None)
        },
        tags=['security', 'forbidden', 'api']
    )
    
    return jsonify({
        'error': 'Forbidden',
        'message': 'Insufficient permissions',
        'request_id': getattr(g, 'request_id', None)
    }), 403

