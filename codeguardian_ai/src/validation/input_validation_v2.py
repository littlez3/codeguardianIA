"""
CodeGuardian AI - Robust Input Validation and Sanitization System (Pydantic v2)
Enterprise-grade input validation using Pydantic v2 with comprehensive sanitization
"""

import re
import html
import bleach
import base64
import urllib.parse
from typing import Dict, Any, List, Optional, Union, Annotated
from pydantic import BaseModel, Field, field_validator, EmailStr
from pydantic import ValidationError
from enum import Enum
import logging

# Configure logging
logger = logging.getLogger(__name__)

class SanitizationLevel(Enum):
    """Levels of input sanitization"""
    BASIC = "basic"          # Basic HTML escaping
    MODERATE = "moderate"    # HTML cleaning + basic filtering
    STRICT = "strict"        # Aggressive filtering + validation
    PARANOID = "paranoid"    # Maximum security, minimal functionality

class InputSanitizer:
    """Advanced input sanitization with multiple security levels"""
    
    def __init__(self, level: SanitizationLevel = SanitizationLevel.MODERATE):
        self.level = level
        
        # Dangerous patterns to detect/remove
        self.dangerous_patterns = [
            # Code injection patterns
            r'(?i)(eval|exec|compile|__import__|getattr|setattr|delattr|hasattr)',
            r'(?i)(subprocess|os\.system|os\.popen|os\.spawn)',
            r'(?i)(input|raw_input)\s*\(',
            
            # SQL injection patterns
            r'(?i)(union|select|insert|update|delete|drop|create|alter|truncate)',
            r'(?i)(or\s+1\s*=\s*1|and\s+1\s*=\s*1)',
            r'(?i)(\'|\"|;|--|\*|\/\*|\*\/)',
            
            # XSS patterns
            r'(?i)<script[^>]*>.*?</script>',
            r'(?i)javascript:',
            r'(?i)on\w+\s*=',
            r'(?i)<iframe[^>]*>.*?</iframe>',
            
            # Command injection patterns
            r'(?i)(\||&|;|`|\$\(|\${)',
            r'(?i)(wget|curl|nc|netcat|telnet|ssh)',
            
            # Path traversal patterns
            r'\.\./',
            r'\.\.\\',
            r'%2e%2e%2f',
            r'%2e%2e%5c',
            
            # Encoding bypass attempts
            r'%[0-9a-fA-F]{2}',  # URL encoding
            r'&#[0-9]+;',        # HTML entities
            r'\\u[0-9a-fA-F]{4}', # Unicode escapes
        ]
        
        # Compile patterns for performance
        self.compiled_patterns = [re.compile(pattern) for pattern in self.dangerous_patterns]
        
        # Bleach configuration by level
        self.bleach_configs = {
            SanitizationLevel.BASIC: {
                'tags': [],
                'attributes': {},
                'strip': True
            },
            SanitizationLevel.MODERATE: {
                'tags': ['b', 'i', 'u', 'em', 'strong', 'p', 'br'],
                'attributes': {},
                'strip': True
            },
            SanitizationLevel.STRICT: {
                'tags': [],
                'attributes': {},
                'strip': True
            },
            SanitizationLevel.PARANOID: {
                'tags': [],
                'attributes': {},
                'strip': True
            }
        }
    
    def sanitize_string(self, value: str) -> str:
        """Sanitize a string input based on security level"""
        if not isinstance(value, str):
            value = str(value)
        
        # Step 1: Basic HTML escaping
        value = html.escape(value)
        
        # Step 2: URL decode to catch encoded attacks
        try:
            decoded = urllib.parse.unquote(value)
            if decoded != value:
                # If URL decoding changed the string, check for dangerous patterns
                if self._contains_dangerous_patterns(decoded):
                    logger.warning(f"Dangerous pattern detected in URL-decoded input: {decoded[:100]}")
                    raise ValueError("Input contains potentially dangerous URL-encoded content")
        except Exception:
            pass  # Continue with original value if decoding fails
        
        # Step 3: Check for dangerous patterns
        if self._contains_dangerous_patterns(value):
            if self.level in [SanitizationLevel.STRICT, SanitizationLevel.PARANOID]:
                raise ValueError("Input contains potentially dangerous patterns")
            else:
                logger.warning(f"Dangerous pattern detected but allowed: {value[:100]}")
        
        # Step 4: Bleach HTML cleaning
        config = self.bleach_configs[self.level]
        value = bleach.clean(value, **config)
        
        # Step 5: Additional filtering based on level
        if self.level == SanitizationLevel.PARANOID:
            # Remove all non-alphanumeric characters except basic punctuation
            value = re.sub(r'[^\w\s\.\,\!\?\-]', '', value)
        
        # Step 6: Length limits
        max_lengths = {
            SanitizationLevel.BASIC: 10000,
            SanitizationLevel.MODERATE: 5000,
            SanitizationLevel.STRICT: 2000,
            SanitizationLevel.PARANOID: 1000
        }
        
        max_length = max_lengths[self.level]
        if len(value) > max_length:
            logger.warning(f"Input truncated from {len(value)} to {max_length} characters")
            value = value[:max_length]
        
        return value
    
    def _contains_dangerous_patterns(self, value: str) -> bool:
        """Check if value contains any dangerous patterns"""
        for pattern in self.compiled_patterns:
            if pattern.search(value):
                return True
        return False
    
    def sanitize_code(self, code: str, language: str = "python") -> str:
        """Special sanitization for code inputs"""
        if not isinstance(code, str):
            code = str(code)
        
        # Basic length check
        if len(code) > 50000:  # 50KB limit
            raise ValueError("Code input too large (max 50KB)")
        
        # Check for null bytes
        if '\x00' in code:
            raise ValueError("Code contains null bytes")
        
        # Language-specific checks
        if language.lower() == "python":
            # Check for extremely dangerous Python patterns
            dangerous_python = [
                r'(?i)__import__\s*\(',
                r'(?i)eval\s*\(',
                r'(?i)exec\s*\(',
                r'(?i)compile\s*\(',
                r'(?i)open\s*\(',
                r'(?i)file\s*\(',
                r'(?i)input\s*\(',
                r'(?i)raw_input\s*\(',
            ]
            
            for pattern in dangerous_python:
                if re.search(pattern, code):
                    logger.warning(f"Dangerous Python pattern detected: {pattern}")
                    # Don't block here - let AST validator handle it
                    break
        
        return code

# Pydantic v2 Models for API Validation

class CodeExecutionRequest(BaseModel):
    """Validation model for code execution requests"""
    code: Annotated[str, Field(min_length=1, max_length=50000, description="Code to execute")]
    language: Annotated[str, Field(default="python", max_length=20, description="Programming language")]
    limits: Optional[Dict[str, Union[int, float]]] = Field(
        default=None,
        description="Custom execution limits"
    )
    
    @field_validator('code')
    @classmethod
    def validate_code(cls, v):
        sanitizer = InputSanitizer(SanitizationLevel.MODERATE)
        return sanitizer.sanitize_code(v)
    
    @field_validator('language')
    @classmethod
    def validate_language(cls, v):
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', v):
            raise ValueError("Language name contains invalid characters")
        
        allowed_languages = ['python', 'javascript', 'bash', 'sql']
        if v.lower() not in allowed_languages:
            raise ValueError(f"Language must be one of: {allowed_languages}")
        return v.lower()
    
    @field_validator('limits')
    @classmethod
    def validate_limits(cls, v):
        if v is None:
            return v
        
        allowed_keys = ['timeout_seconds', 'max_memory_mb', 'max_disk_mb']
        for key in v.keys():
            if key not in allowed_keys:
                raise ValueError(f"Invalid limit key: {key}")
        
        # Validate ranges
        if 'timeout_seconds' in v:
            if not (1 <= v['timeout_seconds'] <= 300):  # 1 second to 5 minutes
                raise ValueError("timeout_seconds must be between 1 and 300")
        
        if 'max_memory_mb' in v:
            if not (1 <= v['max_memory_mb'] <= 1024):  # 1MB to 1GB
                raise ValueError("max_memory_mb must be between 1 and 1024")
        
        if 'max_disk_mb' in v:
            if not (1 <= v['max_disk_mb'] <= 100):  # 1MB to 100MB
                raise ValueError("max_disk_mb must be between 1 and 100")
        
        return v

class SecurityAnalysisRequest(BaseModel):
    """Validation model for security analysis requests"""
    code: Annotated[str, Field(min_length=1, max_length=50000, description="Code to analyze")]
    language: Annotated[str, Field(default="python", max_length=20, description="Programming language")]
    security_level: Optional[str] = Field(
        default="moderate",
        description="Security analysis level"
    )
    
    @field_validator('code')
    @classmethod
    def validate_code(cls, v):
        sanitizer = InputSanitizer(SanitizationLevel.MODERATE)
        return sanitizer.sanitize_code(v)
    
    @field_validator('language')
    @classmethod
    def validate_language(cls, v):
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]*$', v):
            raise ValueError("Language name contains invalid characters")
        
        allowed_languages = ['python', 'javascript', 'bash', 'sql']
        if v.lower() not in allowed_languages:
            raise ValueError(f"Language must be one of: {allowed_languages}")
        return v.lower()
    
    @field_validator('security_level')
    @classmethod
    def validate_security_level(cls, v):
        if v is None:
            return "moderate"
        allowed_levels = ['permissive', 'moderate', 'strict', 'paranoid']
        if v.lower() not in allowed_levels:
            raise ValueError(f"Security level must be one of: {allowed_levels}")
        return v.lower()

class AuthLoginRequest(BaseModel):
    """Validation model for authentication login"""
    username: Annotated[str, Field(min_length=3, max_length=50, description="Username")]
    password: Annotated[str, Field(min_length=8, max_length=128, description="Password")]
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        sanitizer = InputSanitizer(SanitizationLevel.STRICT)
        sanitized = sanitizer.sanitize_string(v)
        
        # Additional username validation
        if not re.match(r'^[a-zA-Z0-9_.-]+$', sanitized):
            raise ValueError("Username contains invalid characters")
        
        return sanitized
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        # Don't sanitize passwords too aggressively, but check for null bytes
        if '\x00' in v:
            raise ValueError("Password contains invalid characters")
        
        # Basic password strength check
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        
        return v

class AuthRegisterRequest(BaseModel):
    """Validation model for user registration"""
    username: Annotated[str, Field(min_length=3, max_length=50, description="Username")]
    email: EmailStr = Field(description="Email address")
    password: Annotated[str, Field(min_length=8, max_length=128, description="Password")]
    
    @field_validator('username')
    @classmethod
    def validate_username(cls, v):
        if not re.match(r'^[a-zA-Z0-9_.-]+$', v):
            raise ValueError("Username contains invalid characters")
        
        sanitizer = InputSanitizer(SanitizationLevel.STRICT)
        return sanitizer.sanitize_string(v)
    
    @field_validator('password')
    @classmethod
    def validate_password(cls, v):
        if '\x00' in v:
            raise ValueError("Password contains invalid characters")
        
        # Password strength requirements
        if len(v) < 8:
            raise ValueError("Password must be at least 8 characters")
        
        # Check for at least one letter and one number
        if not re.search(r'[a-zA-Z]', v) or not re.search(r'[0-9]', v):
            raise ValueError("Password must contain at least one letter and one number")
        
        return v

class ApiKeyCreateRequest(BaseModel):
    """Validation model for API key creation"""
    name: Annotated[str, Field(min_length=1, max_length=100, description="API key name")]
    scopes: List[str] = Field(default=[], description="Allowed scopes")
    expires_days: Optional[int] = Field(default=30, ge=1, le=365, description="Days until expiration")
    
    @field_validator('name')
    @classmethod
    def validate_name(cls, v):
        sanitizer = InputSanitizer(SanitizationLevel.STRICT)
        return sanitizer.sanitize_string(v)
    
    @field_validator('scopes')
    @classmethod
    def validate_scopes(cls, v):
        allowed_scopes = [
            'execute', 'analyze', 'validate', 'health', 
            'auth', 'admin', 'stats'
        ]
        
        for scope in v:
            if scope not in allowed_scopes:
                raise ValueError(f"Invalid scope: {scope}")
        
        return v

# Validation Helper Functions

def validate_request_data(data: Dict[str, Any], model_class: BaseModel) -> BaseModel:
    """
    Validate request data against a Pydantic model
    
    Args:
        data: Raw request data
        model_class: Pydantic model class to validate against
    
    Returns:
        Validated model instance
    
    Raises:
        ValidationError: If validation fails
    """
    try:
        return model_class(**data)
    except ValidationError as e:
        logger.warning(f"Validation error: {e}")
        raise

def sanitize_response_data(data: Any, level: SanitizationLevel = SanitizationLevel.BASIC) -> Any:
    """
    Sanitize response data to prevent information leakage
    
    Args:
        data: Response data to sanitize
        level: Sanitization level
    
    Returns:
        Sanitized data
    """
    sanitizer = InputSanitizer(level)
    
    if isinstance(data, dict):
        return {k: sanitize_response_data(v, level) for k, v in data.items()}
    elif isinstance(data, list):
        return [sanitize_response_data(item, level) for item in data]
    elif isinstance(data, str):
        # For response data, we're more lenient but still escape HTML
        return html.escape(data)
    else:
        return data

def create_validation_error_response(error: ValidationError) -> Dict[str, Any]:
    """
    Create a standardized error response for validation failures
    
    Args:
        error: Pydantic ValidationError
    
    Returns:
        Formatted error response
    """
    errors = []
    for err in error.errors():
        field = '.'.join(str(loc) for loc in err['loc'])
        errors.append({
            'field': field,
            'message': err['msg'],
            'type': err['type']
        })
    
    return {
        'error': 'Validation failed',
        'message': 'Request data validation failed',
        'details': errors,
        'error_count': len(errors)
    }

# Security Headers Helper

def get_security_headers() -> Dict[str, str]:
    """Get recommended security headers for responses"""
    return {
        'X-Content-Type-Options': 'nosniff',
        'X-Frame-Options': 'DENY',
        'X-XSS-Protection': '1; mode=block',
        'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
        'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'",
        'Referrer-Policy': 'strict-origin-when-cross-origin',
        'Permissions-Policy': 'geolocation=(), microphone=(), camera=()'
    }

# Testing function
if __name__ == "__main__":
    # Test sanitization
    sanitizer = InputSanitizer(SanitizationLevel.MODERATE)
    
    test_inputs = [
        "print('Hello World')",
        "<script>alert('xss')</script>",
        "'; DROP TABLE users; --",
        "eval('malicious code')",
        "normal text with spaces",
        "unicode test: \u0041\u0042\u0043",
        "url encoded: %3Cscript%3E",
    ]
    
    print("Testing Input Sanitization:")
    for test_input in test_inputs:
        try:
            result = sanitizer.sanitize_string(test_input)
            print(f"Input: {test_input[:50]}")
            print(f"Output: {result[:50]}")
            print(f"Safe: {not sanitizer._contains_dangerous_patterns(result)}")
            print("-" * 50)
        except ValueError as e:
            print(f"Input: {test_input[:50]}")
            print(f"Error: {e}")
            print("-" * 50)
    
    # Test Pydantic validation
    print("\nTesting Pydantic Validation:")
    
    # Valid request
    try:
        valid_request = CodeExecutionRequest(
            code="print('Hello World')",
            language="python"
        )
        print(f"Valid request: {valid_request}")
    except ValidationError as e:
        print(f"Validation error: {e}")
    
    # Invalid request
    try:
        invalid_request = CodeExecutionRequest(
            code="<script>alert('xss')</script>",
            language="invalid_lang"
        )
        print(f"Invalid request: {invalid_request}")
    except ValidationError as e:
        print(f"Expected validation error: {e}")

