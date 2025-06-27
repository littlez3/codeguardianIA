"""
CodeGuardian AI - API Routes
REST API endpoints for code execution and security analysis with authentication
"""

from flask import Blueprint, request, jsonify
from flask_cors import cross_origin
import time
import json
from typing import Dict, Any

from src.engines.code_execution import CodeExecutionEngine, ExecutionLimits
from src.engines.security_analysis_enhanced import SecurityAnalysisEngine
from src.engines.ast_validator import SecurityLevel
from src.auth.authentication import require_auth, optional_auth, UserRole
from src.auth.rate_limiting import rate_limit, RateLimit, RateLimitStrategy
from src.audit.audit_system import get_audit_manager, AuditContext, EventType, LogLevel

# Create blueprint for API routes
api_bp = Blueprint('api', __name__)

# Initialize engines with enhanced security
execution_engine = CodeExecutionEngine()
security_engine = SecurityAnalysisEngine(SecurityLevel.MODERATE)

# Get audit manager
audit_manager = get_audit_manager()

@api_bp.route('/health', methods=['GET'])
@cross_origin()
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': time.time(),
        'services': {
            'code_execution': 'operational',
            'security_analysis': 'operational',
            'authentication': 'operational',
            'rate_limiting': 'operational'
        }
    })

@api_bp.route('/execute', methods=['POST'])
@cross_origin()
@optional_auth()
@rate_limit('execute', RateLimit(10, 60, RateLimitStrategy.SLIDING_WINDOW))  # 10 executions per minute
def execute_code():
    """Execute code in secure sandbox"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        code = data.get('code')
        language = data.get('language', 'python')
        
        if not code:
            return jsonify({'error': 'Code is required'}), 400
        
        # Check if user is authenticated for enhanced limits
        user = getattr(request, 'current_user', None)
        
        # Optional: Custom execution limits based on user role
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
            # Only allow authenticated users to set custom limits
            if user:
                limits.timeout_seconds = min(limit_data.get('timeout_seconds', limits.timeout_seconds), limits.timeout_seconds)
                limits.max_memory_mb = min(limit_data.get('max_memory_mb', limits.max_memory_mb), limits.max_memory_mb)
                limits.max_disk_mb = min(limit_data.get('max_disk_mb', limits.max_disk_mb), limits.max_disk_mb)
        
        # Create engine with custom limits
        engine = CodeExecutionEngine(limits)
        
        # Execute code
        result = engine.execute(code, language)
        
        # Add user context to result if authenticated
        if user:
            result_dict = result.to_dict()
            result_dict['user_context'] = {
                'user_id': user.id,
                'username': user.username,
                'role': user.role.value
            }
            return jsonify(result_dict)
        
        return jsonify(result.to_dict())
        
    except Exception as e:
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500

@api_bp.route('/analyze', methods=['POST'])
@cross_origin()
@optional_auth()
@rate_limit('analyze', RateLimit(20, 60, RateLimitStrategy.SLIDING_WINDOW))  # 20 analyses per minute
def analyze_security():
    """Analyze code for security vulnerabilities"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        code = data.get('code')
        language = data.get('language', 'python')
        
        if not code:
            return jsonify({'error': 'Code is required'}), 400
        
        # Analyze code
        result = security_engine.analyze(code, language)
        
        # Add user context to result if authenticated
        user = getattr(request, 'current_user', None)
        if user:
            result_dict = result.to_dict()
            result_dict['user_context'] = {
                'user_id': user.id,
                'username': user.username,
                'role': user.role.value
            }
            return jsonify(result_dict)
        
        return jsonify(result.to_dict())
        
    except Exception as e:
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500

@api_bp.route('/validate', methods=['POST'])
@cross_origin()
@optional_auth()
@rate_limit('validate', RateLimit(5, 60, RateLimitStrategy.SLIDING_WINDOW))  # 5 validations per minute
def validate_code():
    """Complete validation: execute code and analyze security"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        code = data.get('code')
        language = data.get('language', 'python')
        
        if not code:
            return jsonify({'error': 'Code is required'}), 400
        
        # Get user context
        user = getattr(request, 'current_user', None)
        
        # Set execution limits based on user role
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
        
        # Execute code
        engine = CodeExecutionEngine(limits)
        execution_result = engine.execute(code, language)
        
        # Analyze security
        security_result = security_engine.analyze(code, language)
        
        # Combine results
        validation_result = {
            'validation_id': f"val_{int(time.time())}",
            'timestamp': time.time(),
            'code': code,
            'language': language,
            'execution': execution_result.to_dict(),
            'security': security_result.to_dict(),
            'overall_status': {
                'execution_success': execution_result.success,
                'security_issues_found': security_result.total_vulnerabilities > 0,
                'critical_vulnerabilities': security_result.critical_count,
                'high_vulnerabilities': security_result.high_count,
                'recommendation': _get_recommendation(execution_result, security_result)
            }
        }
        
        # Add user context if authenticated
        if user:
            validation_result['user_context'] = {
                'user_id': user.id,
                'username': user.username,
                'role': user.role.value
            }
        
        return jsonify(validation_result)
        
    except Exception as e:
        return jsonify({
            'error': 'Internal server error',
            'message': str(e)
        }), 500

@api_bp.route('/languages', methods=['GET'])
@cross_origin()
def get_supported_languages():
    """Get list of supported programming languages"""
    return jsonify({
        'supported_languages': [
            {
                'name': 'Python',
                'code': 'python',
                'version': '3.11',
                'features': {
                    'execution': True,
                    'security_analysis': True,
                    'syntax_validation': True
                }
            }
        ],
        'coming_soon': [
            {
                'name': 'JavaScript',
                'code': 'javascript',
                'estimated_release': 'Q2 2024'
            },
            {
                'name': 'Java',
                'code': 'java', 
                'estimated_release': 'Q2 2024'
            },
            {
                'name': 'C++',
                'code': 'cpp',
                'estimated_release': 'Q3 2024'
            }
        ]
    })

@api_bp.route('/stats', methods=['GET'])
@cross_origin()
@require_auth(UserRole.ANALYST)  # Require analyst role or higher for stats
def get_stats():
    """Get system statistics"""
    try:
        # Read execution logs to get stats
        stats = {
            'total_executions': 0,
            'successful_executions': 0,
            'failed_executions': 0,
            'total_vulnerabilities_found': 0,
            'avg_execution_time': 0.0,
            'most_common_vulnerabilities': [],
            'uptime': time.time()  # Simplified uptime
        }
        
        # Try to read logs and calculate real stats
        try:
            with open('execution_logs.jsonl', 'r') as f:
                executions = [json.loads(line) for line in f]
                stats['total_executions'] = len(executions)
                stats['successful_executions'] = sum(1 for e in executions if e.get('success', False))
                stats['failed_executions'] = stats['total_executions'] - stats['successful_executions']
                
                execution_times = [e.get('execution_time', 0) for e in executions if e.get('execution_time')]
                if execution_times:
                    stats['avg_execution_time'] = sum(execution_times) / len(execution_times)
                    
        except FileNotFoundError:
            pass  # Use default stats
        
        # Add user context
        user = request.current_user
        stats['requested_by'] = {
            'user_id': user.id,
            'username': user.username,
            'role': user.role.value
        }
        
        return jsonify(stats)
        
    except Exception as e:
        return jsonify({
            'error': 'Failed to get stats',
            'message': str(e)
        }), 500

@api_bp.route('/admin/system-info', methods=['GET'])
@cross_origin()
@require_auth(UserRole.ADMIN)  # Admin only
def get_system_info():
    """Get detailed system information (admin only)"""
    try:
        import psutil
        import platform
        
        system_info = {
            'system': {
                'platform': platform.platform(),
                'python_version': platform.python_version(),
                'cpu_count': psutil.cpu_count(),
                'memory_total': psutil.virtual_memory().total,
                'memory_available': psutil.virtual_memory().available,
                'disk_usage': psutil.disk_usage('/').percent
            },
            'application': {
                'version': '1.0.0',
                'environment': 'development',  # TODO: Get from env
                'uptime': time.time()
            },
            'database': {
                'type': 'SQLite',  # TODO: Get from config
                'status': 'connected'
            }
        }
        
        return jsonify(system_info)
        
    except ImportError:
        # psutil not available
        return jsonify({
            'system': {
                'platform': 'unknown',
                'status': 'limited_info_available'
            }
        })
    except Exception as e:
        return jsonify({
            'error': 'Failed to get system info',
            'message': str(e)
        }), 500

def _get_recommendation(execution_result, security_result) -> str:
    """Generate recommendation based on execution and security results"""
    if not execution_result.success:
        return "❌ Code has execution errors. Fix syntax and logic issues before deployment."
    
    if security_result.critical_count > 0:
        return "🚨 CRITICAL security vulnerabilities found. Do not deploy until fixed."
    
    if security_result.high_count > 0:
        return "⚠️ HIGH severity vulnerabilities found. Review and fix before deployment."
    
    if security_result.medium_count > 0:
        return "⚡ Medium severity issues found. Consider fixing for better security."
    
    if security_result.low_count > 0:
        return "✅ Code executes successfully. Minor security improvements recommended."
    
    return "✅ Code executes successfully with no security issues detected."

# Error handlers
@api_bp.errorhandler(404)
def not_found(error):
    return jsonify({'error': 'Endpoint not found'}), 404

@api_bp.errorhandler(405)
def method_not_allowed(error):
    return jsonify({'error': 'Method not allowed'}), 405

@api_bp.errorhandler(500)
def internal_error(error):
    return jsonify({'error': 'Internal server error'}), 500

