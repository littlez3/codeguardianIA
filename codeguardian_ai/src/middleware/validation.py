"""
CodeGuardian AI - Enterprise Input Validation System
Advanced input validation, sanitization, and threat detection with zero-trust principles
"""

import re
import json
import html
import urllib.parse
from typing import Any, Dict, List, Optional, Union, Callable, Type
from dataclasses import dataclass, field
from enum import Enum
import ipaddress
from datetime import datetime, timezone
import uuid
import base64
import hashlib
from decimal import Decimal, InvalidOperation
import logging

from pydantic import BaseModel, ValidationError, validator, Field
from marshmallow import Schema, fields, validate, ValidationError as MarshmallowValidationError
from flask import request, jsonify

from src.audit.audit_system import get_audit_manager, EventType, LogLevel, SecurityLevel

class ValidationLevel(Enum):
    """Validation strictness levels"""
    PERMISSIVE = "permissive"
    STANDARD = "standard"
    STRICT = "strict"
    PARANOID = "paranoid"

class SanitizationMode(Enum):
    """Sanitization modes"""
    ESCAPE = "escape"
    STRIP = "strip"
    REJECT = "reject"
    ENCODE = "encode"

@dataclass
class ValidationRule:
    """Input validation rule configuration"""
    field_name: str
    required: bool = True
    data_type: Type = str
    min_length: Optional[int] = None
    max_length: Optional[int] = None
    min_value: Optional[Union[int, float]] = None
    max_value: Optional[Union[int, float]] = None
    pattern: Optional[str] = None
    allowed_values: Optional[List[Any]] = None
    custom_validator: Optional[Callable] = None
    sanitization_mode: SanitizationMode = SanitizationMode.ESCAPE
    validation_level: ValidationLevel = ValidationLevel.STANDARD

@dataclass
class ValidationResult:
    """Validation result with detailed information"""
    is_valid: bool
    sanitized_data: Dict[str, Any]
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    threat_score: float = 0.0
    blocked_patterns: List[str] = field(default_factory=list)

class ThreatDetector:
    """Advanced threat detection for input validation"""
    
    # Comprehensive malicious patterns
    XSS_PATTERNS = [
        r'<script[^>]*>.*?</script>',
        r'javascript:',
        r'vbscript:',
        r'onload\s*=',
        r'onerror\s*=',
        r'onclick\s*=',
        r'onmouseover\s*=',
        r'<iframe[^>]*>',
        r'<object[^>]*>',
        r'<embed[^>]*>',
        r'<link[^>]*>',
        r'<meta[^>]*>',
        r'expression\s*\(',
        r'url\s*\(',
        r'@import',
        r'<svg[^>]*onload',
        r'<img[^>]*onerror',
    ]
    
    SQL_INJECTION_PATTERNS = [
        r'union\s+select',
        r'drop\s+table',
        r'delete\s+from',
        r'insert\s+into',
        r'update\s+.*\s+set',
        r'exec\s*\(',
        r'execute\s*\(',
        r'sp_executesql',
        r'xp_cmdshell',
        r';\s*--',
        r';\s*/\*',
        r'\'\s*or\s*\'',
        r'\'\s*and\s*\'',
        r'1\s*=\s*1',
        r'1\s*=\s*0',
        r'or\s+1\s*=\s*1',
        r'and\s+1\s*=\s*1',
    ]
    
    COMMAND_INJECTION_PATTERNS = [
        r';\s*cat\s+',
        r';\s*ls\s+',
        r';\s*pwd',
        r';\s*whoami',
        r';\s*id\s*;',
        r';\s*uname',
        r';\s*ps\s+',
        r';\s*netstat',
        r';\s*ifconfig',
        r';\s*ping\s+',
        r';\s*wget\s+',
        r';\s*curl\s+',
        r'\|\s*nc\s+',
        r'\|\s*telnet\s+',
        r'`.*`',
        r'\$\(.*\)',
        r'&&\s*cat',
        r'\|\|\s*cat',
    ]
    
    PATH_TRAVERSAL_PATTERNS = [
        r'\.\./',
        r'\.\.\\',
        r'%2e%2e%2f',
        r'%2e%2e%5c',
        r'..%2f',
        r'..%5c',
        r'%252e%252e%252f',
        r'%c0%ae%c0%ae%c0%af',
        r'%c1%9c',
    ]
    
    LDAP_INJECTION_PATTERNS = [
        r'\*\)\(\|',
        r'\*\)\(\&',
        r'\)\(\|',
        r'\)\(\&',
        r'\*\|',
        r'\*\&',
    ]
    
    NOSQL_INJECTION_PATTERNS = [
        r'\$where',
        r'\$ne',
        r'\$gt',
        r'\$lt',
        r'\$regex',
        r'\$or',
        r'\$and',
        r'\$not',
        r'\$nor',
        r'\$exists',
        r'\$type',
        r'\$mod',
        r'\$all',
        r'\$size',
        r'\$elemMatch',
    ]
    
    def __init__(self):
        self.audit_manager = get_audit_manager()
        
        # Compile patterns for performance
        self.compiled_patterns = {
            'xss': [re.compile(pattern, re.IGNORECASE | re.DOTALL) for pattern in self.XSS_PATTERNS],
            'sql': [re.compile(pattern, re.IGNORECASE) for pattern in self.SQL_INJECTION_PATTERNS],
            'command': [re.compile(pattern, re.IGNORECASE) for pattern in self.COMMAND_INJECTION_PATTERNS],
            'path': [re.compile(pattern, re.IGNORECASE) for pattern in self.PATH_TRAVERSAL_PATTERNS],
            'ldap': [re.compile(pattern, re.IGNORECASE) for pattern in self.LDAP_INJECTION_PATTERNS],
            'nosql': [re.compile(pattern, re.IGNORECASE) for pattern in self.NOSQL_INJECTION_PATTERNS],
        }
    
    def detect_threats(self, data: str, validation_level: ValidationLevel = ValidationLevel.STANDARD) -> Dict[str, Any]:
        """Detect threats in input data"""
        
        threats = {
            'xss': [],
            'sql': [],
            'command': [],
            'path': [],
            'ldap': [],
            'nosql': [],
        }
        
        threat_score = 0.0
        data_lower = data.lower()
        
        # Check each threat category
        for category, patterns in self.compiled_patterns.items():
            for pattern in patterns:
                matches = pattern.findall(data)
                if matches:
                    threats[category].extend(matches)
                    
                    # Calculate threat score based on category and validation level
                    category_weight = {
                        'xss': 0.8,
                        'sql': 0.9,
                        'command': 1.0,
                        'path': 0.7,
                        'ldap': 0.6,
                        'nosql': 0.8,
                    }
                    
                    level_multiplier = {
                        ValidationLevel.PERMISSIVE: 0.5,
                        ValidationLevel.STANDARD: 1.0,
                        ValidationLevel.STRICT: 1.5,
                        ValidationLevel.PARANOID: 2.0,
                    }
                    
                    threat_score += len(matches) * category_weight[category] * level_multiplier[validation_level]
        
        # Additional heuristic checks
        threat_score += self._check_encoding_attacks(data)
        threat_score += self._check_length_attacks(data)
        threat_score += self._check_unicode_attacks(data)
        
        # Normalize threat score (0.0 to 1.0)
        threat_score = min(1.0, threat_score / 10.0)
        
        return {
            'threats': threats,
            'threat_score': threat_score,
            'blocked_patterns': [pattern for category_threats in threats.values() for pattern in category_threats]
        }
    
    def _check_encoding_attacks(self, data: str) -> float:
        """Check for encoding-based attacks"""
        score = 0.0
        
        # Multiple URL encoding
        if '%25' in data:
            score += 0.3
        
        # HTML entity encoding
        if '&amp;' in data or '&lt;' in data or '&gt;' in data:
            score += 0.2
        
        # Unicode encoding
        if '\\u' in data or '\\x' in data:
            score += 0.2
        
        # Base64 patterns
        try:
            if len(data) > 20 and len(data) % 4 == 0:
                base64.b64decode(data, validate=True)
                # Potential base64 encoded payload
                score += 0.3
        except Exception:
            pass
        
        return score
    
    def _check_length_attacks(self, data: str) -> float:
        """Check for length-based attacks"""
        score = 0.0
        
        # Extremely long input (potential buffer overflow)
        if len(data) > 10000:
            score += 0.5
        elif len(data) > 5000:
            score += 0.3
        elif len(data) > 1000:
            score += 0.1
        
        # Repeated characters (potential DoS)
        for char in set(data):
            if data.count(char) > len(data) * 0.8:
                score += 0.4
                break
        
        return score
    
    def _check_unicode_attacks(self, data: str) -> float:
        """Check for Unicode-based attacks"""
        score = 0.0
        
        # Check for suspicious Unicode characters
        suspicious_ranges = [
            (0x2000, 0x206F),  # General Punctuation
            (0xFE00, 0xFE0F),  # Variation Selectors
            (0xFFF0, 0xFFFF),  # Specials
        ]
        
        for char in data:
            code_point = ord(char)
            for start, end in suspicious_ranges:
                if start <= code_point <= end:
                    score += 0.1
                    break
        
        return min(score, 0.5)

class InputSanitizer:
    """Advanced input sanitization with multiple modes"""
    
    def __init__(self):
        self.threat_detector = ThreatDetector()
    
    def sanitize(self, data: Any, mode: SanitizationMode = SanitizationMode.ESCAPE, 
                validation_level: ValidationLevel = ValidationLevel.STANDARD) -> Dict[str, Any]:
        """Sanitize input data based on mode and validation level"""
        
        if not isinstance(data, str):
            data = str(data)
        
        # Detect threats first
        threat_analysis = self.threat_detector.detect_threats(data, validation_level)
        
        # Apply sanitization based on mode
        if mode == SanitizationMode.REJECT:
            if threat_analysis['threat_score'] > 0.1:
                raise ValueError("Input contains potentially malicious content")
            sanitized = data
        
        elif mode == SanitizationMode.STRIP:
            sanitized = self._strip_malicious_content(data, threat_analysis)
        
        elif mode == SanitizationMode.ESCAPE:
            sanitized = self._escape_malicious_content(data)
        
        elif mode == SanitizationMode.ENCODE:
            sanitized = self._encode_malicious_content(data)
        
        else:
            sanitized = data
        
        return {
            'sanitized_data': sanitized,
            'threat_score': threat_analysis['threat_score'],
            'blocked_patterns': threat_analysis['blocked_patterns'],
            'original_length': len(data),
            'sanitized_length': len(sanitized)
        }
    
    def _strip_malicious_content(self, data: str, threat_analysis: Dict[str, Any]) -> str:
        """Strip malicious content from input"""
        sanitized = data
        
        # Remove detected patterns
        for category, patterns in threat_analysis['threats'].items():
            for pattern in patterns:
                sanitized = sanitized.replace(pattern, '')
        
        # Remove common malicious characters
        malicious_chars = ['<', '>', '"', "'", '&', ';', '|', '`', '$', '(', ')']
        for char in malicious_chars:
            sanitized = sanitized.replace(char, '')
        
        return sanitized.strip()
    
    def _escape_malicious_content(self, data: str) -> str:
        """Escape malicious content in input"""
        # HTML escape
        sanitized = html.escape(data, quote=True)
        
        # URL encode special characters
        special_chars = {
            ';': '%3B',
            '|': '%7C',
            '`': '%60',
            '$': '%24',
        }
        
        for char, encoded in special_chars.items():
            sanitized = sanitized.replace(char, encoded)
        
        return sanitized
    
    def _encode_malicious_content(self, data: str) -> str:
        """Encode malicious content in input"""
        # URL encode the entire string
        return urllib.parse.quote(data, safe='')

class EnterpriseValidator:
    """Enterprise-grade input validator with comprehensive security checks"""
    
    def __init__(self):
        self.sanitizer = InputSanitizer()
        self.threat_detector = ThreatDetector()
        self.audit_manager = get_audit_manager()
        
        # Common validation patterns
        self.patterns = {
            'email': r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
            'username': r'^[a-zA-Z0-9_-]{3,32}$',
            'password': r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$',
            'uuid': r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
            'ip_address': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
            'url': r'^https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:\w*))?)?$',
            'filename': r'^[a-zA-Z0-9._-]+$',
            'alphanumeric': r'^[a-zA-Z0-9]+$',
            'numeric': r'^[0-9]+$',
            'alpha': r'^[a-zA-Z]+$',
        }
    
    def validate_request_data(self, rules: List[ValidationRule], 
                            validation_level: ValidationLevel = ValidationLevel.STANDARD) -> ValidationResult:
        """Validate request data against rules"""
        
        # Get request data
        if request.is_json:
            data = request.get_json() or {}
        else:
            data = request.form.to_dict()
            data.update(request.args.to_dict())
        
        return self.validate_data(data, rules, validation_level)
    
    def validate_data(self, data: Dict[str, Any], rules: List[ValidationRule], 
                     validation_level: ValidationLevel = ValidationLevel.STANDARD) -> ValidationResult:
        """Validate data against validation rules"""
        
        errors = []
        warnings = []
        sanitized_data = {}
        total_threat_score = 0.0
        all_blocked_patterns = []
        
        # Check for required fields
        for rule in rules:
            if rule.required and rule.field_name not in data:
                errors.append(f"Required field '{rule.field_name}' is missing")
        
        # Validate each field
        for field_name, value in data.items():
            # Find matching rule
            rule = next((r for r in rules if r.field_name == field_name), None)
            
            if rule is None:
                # Unknown field - handle based on validation level
                if validation_level in [ValidationLevel.STRICT, ValidationLevel.PARANOID]:
                    errors.append(f"Unknown field '{field_name}' not allowed")
                    continue
                else:
                    warnings.append(f"Unknown field '{field_name}' ignored")
                    continue
            
            # Validate field
            field_result = self._validate_field(field_name, value, rule, validation_level)
            
            if field_result['is_valid']:
                sanitized_data[field_name] = field_result['sanitized_value']
            else:
                errors.extend(field_result['errors'])
            
            warnings.extend(field_result['warnings'])
            total_threat_score += field_result['threat_score']
            all_blocked_patterns.extend(field_result['blocked_patterns'])
        
        # Log validation results if threats detected
        if total_threat_score > 0.3 or errors:
            self._log_validation_event(data, errors, total_threat_score, all_blocked_patterns)
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            sanitized_data=sanitized_data,
            errors=errors,
            warnings=warnings,
            threat_score=total_threat_score,
            blocked_patterns=all_blocked_patterns
        )
    
    def _validate_field(self, field_name: str, value: Any, rule: ValidationRule, 
                       validation_level: ValidationLevel) -> Dict[str, Any]:
        """Validate a single field"""
        
        errors = []
        warnings = []
        threat_score = 0.0
        blocked_patterns = []
        
        # Convert to string for threat detection
        str_value = str(value) if value is not None else ""
        
        # Threat detection
        if str_value:
            threat_analysis = self.threat_detector.detect_threats(str_value, validation_level)
            threat_score = threat_analysis['threat_score']
            blocked_patterns = threat_analysis['blocked_patterns']
            
            # Reject if threat score is too high
            if validation_level == ValidationLevel.PARANOID and threat_score > 0.1:
                errors.append(f"Field '{field_name}' contains potentially malicious content")
            elif validation_level == ValidationLevel.STRICT and threat_score > 0.3:
                errors.append(f"Field '{field_name}' contains suspicious content")
            elif threat_score > 0.5:
                errors.append(f"Field '{field_name}' contains malicious content")
        
        # Type validation
        try:
            if rule.data_type == int:
                value = int(value)
            elif rule.data_type == float:
                value = float(value)
            elif rule.data_type == bool:
                if isinstance(value, str):
                    value = value.lower() in ['true', '1', 'yes', 'on']
                else:
                    value = bool(value)
            elif rule.data_type == str:
                value = str(value)
            elif rule.data_type == list:
                if not isinstance(value, list):
                    if isinstance(value, str):
                        value = [item.strip() for item in value.split(',')]
                    else:
                        value = [value]
        except (ValueError, TypeError) as e:
            errors.append(f"Field '{field_name}' must be of type {rule.data_type.__name__}")
            value = None
        
        # Length validation for strings
        if isinstance(value, str):
            if rule.min_length is not None and len(value) < rule.min_length:
                errors.append(f"Field '{field_name}' must be at least {rule.min_length} characters")
            
            if rule.max_length is not None and len(value) > rule.max_length:
                if validation_level in [ValidationLevel.STRICT, ValidationLevel.PARANOID]:
                    errors.append(f"Field '{field_name}' must be at most {rule.max_length} characters")
                else:
                    warnings.append(f"Field '{field_name}' truncated to {rule.max_length} characters")
                    value = value[:rule.max_length]
        
        # Numeric range validation
        if isinstance(value, (int, float)):
            if rule.min_value is not None and value < rule.min_value:
                errors.append(f"Field '{field_name}' must be at least {rule.min_value}")
            
            if rule.max_value is not None and value > rule.max_value:
                errors.append(f"Field '{field_name}' must be at most {rule.max_value}")
        
        # Pattern validation
        if rule.pattern and isinstance(value, str):
            if not re.match(rule.pattern, value):
                errors.append(f"Field '{field_name}' does not match required pattern")
        
        # Allowed values validation
        if rule.allowed_values is not None:
            if value not in rule.allowed_values:
                errors.append(f"Field '{field_name}' must be one of: {rule.allowed_values}")
        
        # Custom validation
        if rule.custom_validator:
            try:
                custom_result = rule.custom_validator(value)
                if not custom_result:
                    errors.append(f"Field '{field_name}' failed custom validation")
            except Exception as e:
                errors.append(f"Field '{field_name}' custom validation error: {str(e)}")
        
        # Sanitization
        sanitized_value = value
        if isinstance(value, str) and value:
            try:
                sanitization_result = self.sanitizer.sanitize(value, rule.sanitization_mode, validation_level)
                sanitized_value = sanitization_result['sanitized_data']
                
                # Update threat metrics
                if sanitization_result['threat_score'] > threat_score:
                    threat_score = sanitization_result['threat_score']
                blocked_patterns.extend(sanitization_result['blocked_patterns'])
                
            except ValueError as e:
                errors.append(f"Field '{field_name}' sanitization failed: {str(e)}")
        
        return {
            'is_valid': len(errors) == 0,
            'sanitized_value': sanitized_value,
            'errors': errors,
            'warnings': warnings,
            'threat_score': threat_score,
            'blocked_patterns': blocked_patterns
        }
    
    def _log_validation_event(self, data: Dict[str, Any], errors: List[str], 
                            threat_score: float, blocked_patterns: List[str]):
        """Log validation events for security monitoring"""
        
        audit_logger = self.audit_manager.get_audit_logger()
        
        event_type = EventType.SECURITY_VALIDATION_FAILED if errors else EventType.SECURITY_THREAT_DETECTED
        security_level = SecurityLevel.HIGH if threat_score > 0.7 else SecurityLevel.MEDIUM
        
        audit_logger.log_event(
            event_type,
            LogLevel.WARNING,
            f"Input validation {'failed' if errors else 'detected threats'}",
            {
                "errors": errors,
                "threat_score": threat_score,
                "blocked_patterns": blocked_patterns,
                "field_count": len(data),
                "client_ip": getattr(request, 'remote_addr', 'unknown'),
                "user_agent": request.headers.get('User-Agent', 'unknown'),
                "endpoint": request.path,
                "method": request.method
            },
            security_level=security_level
        )

# Predefined validation rule sets
class CommonValidationRules:
    """Common validation rule sets for typical use cases"""
    
    @staticmethod
    def user_registration() -> List[ValidationRule]:
        """Validation rules for user registration"""
        return [
            ValidationRule(
                field_name="username",
                required=True,
                data_type=str,
                min_length=3,
                max_length=32,
                pattern=r'^[a-zA-Z0-9_-]+$',
                sanitization_mode=SanitizationMode.STRIP
            ),
            ValidationRule(
                field_name="email",
                required=True,
                data_type=str,
                max_length=255,
                pattern=r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
                sanitization_mode=SanitizationMode.STRIP
            ),
            ValidationRule(
                field_name="password",
                required=True,
                data_type=str,
                min_length=8,
                max_length=128,
                pattern=r'^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]+$',
                sanitization_mode=SanitizationMode.REJECT
            )
        ]
    
    @staticmethod
    def code_analysis() -> List[ValidationRule]:
        """Validation rules for code analysis requests"""
        return [
            ValidationRule(
                field_name="code",
                required=True,
                data_type=str,
                min_length=1,
                max_length=100000,
                sanitization_mode=SanitizationMode.ESCAPE,
                validation_level=ValidationLevel.STRICT
            ),
            ValidationRule(
                field_name="language",
                required=True,
                data_type=str,
                allowed_values=["python", "javascript", "java", "cpp", "c", "go", "rust"],
                sanitization_mode=SanitizationMode.STRIP
            ),
            ValidationRule(
                field_name="analysis_type",
                required=False,
                data_type=str,
                allowed_values=["security", "performance", "quality", "all"],
                sanitization_mode=SanitizationMode.STRIP
            )
        ]
    
    @staticmethod
    def api_key_creation() -> List[ValidationRule]:
        """Validation rules for API key creation"""
        return [
            ValidationRule(
                field_name="name",
                required=True,
                data_type=str,
                min_length=1,
                max_length=100,
                pattern=r'^[a-zA-Z0-9\s_-]+$',
                sanitization_mode=SanitizationMode.STRIP
            ),
            ValidationRule(
                field_name="permissions",
                required=True,
                data_type=list,
                sanitization_mode=SanitizationMode.STRIP
            ),
            ValidationRule(
                field_name="expires_in_days",
                required=False,
                data_type=int,
                min_value=1,
                max_value=365,
                sanitization_mode=SanitizationMode.STRIP
            )
        ]

# Global validator instance
enterprise_validator = EnterpriseValidator()

def validate_request(rules: List[ValidationRule], 
                    validation_level: ValidationLevel = ValidationLevel.STANDARD) -> ValidationResult:
    """Validate current request data"""
    return enterprise_validator.validate_request_data(rules, validation_level)

def validate_json_schema(schema_class: Type[BaseModel]):
    """Decorator for Pydantic schema validation"""
    def decorator(f):
        def wrapper(*args, **kwargs):
            try:
                if request.is_json:
                    data = request.get_json()
                    validated_data = schema_class(**data)
                    request.validated_data = validated_data
                else:
                    return jsonify({"error": "JSON data required"}), 400
                
                return f(*args, **kwargs)
                
            except ValidationError as e:
                return jsonify({
                    "error": "Validation failed",
                    "details": e.errors()
                }), 400
        
        wrapper.__name__ = f.__name__
        return wrapper
    return decorator

