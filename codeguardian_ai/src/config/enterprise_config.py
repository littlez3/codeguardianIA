"""
CodeGuardian AI - Enterprise Configuration Management
Centralized configuration with validation, secrets management, and environment-specific settings
"""

import os
import json
import yaml
from typing import Dict, Any, Optional, List, Union
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging
from cryptography.fernet import Fernet
import base64

class Environment(Enum):
    """Deployment environments"""
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"

class LogLevel(Enum):
    """Logging levels"""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"
    CRITICAL = "CRITICAL"

@dataclass
class DatabaseConfig:
    """Database configuration"""
    url: str
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    pool_recycle: int = 3600
    echo: bool = False
    
    def __post_init__(self):
        if not self.url:
            raise ValueError("Database URL is required")

@dataclass
class RedisConfig:
    """Redis configuration"""
    url: str
    max_connections: int = 100
    retry_on_timeout: bool = True
    socket_timeout: int = 5
    socket_connect_timeout: int = 5
    
    def __post_init__(self):
        if not self.url:
            raise ValueError("Redis URL is required")

@dataclass
class JWTConfig:
    """JWT authentication configuration"""
    secret_key: str
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    api_key_expire_days: int = 365
    
    def __post_init__(self):
        if not self.secret_key or len(self.secret_key) < 32:
            raise ValueError("JWT secret key must be at least 32 characters")

@dataclass
class SecurityConfig:
    """Security configuration"""
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 15
    password_min_length: int = 8
    require_special_chars: bool = True
    session_timeout_minutes: int = 60
    csrf_protection: bool = True
    
@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""
    enabled: bool = True
    storage: str = "redis"  # redis or memory
    default_per_minute: int = 100
    default_per_hour: int = 1000
    default_per_day: int = 10000
    
@dataclass
class ExecutionConfig:
    """Code execution configuration"""
    timeout_seconds: int = 30
    max_memory_mb: int = 256
    max_disk_mb: int = 100
    max_output_size: int = 10000
    allowed_imports: List[str] = field(default_factory=lambda: [
        "os", "sys", "json", "re", "math", "datetime", "collections",
        "itertools", "functools", "operator", "typing"
    ])
    blocked_functions: List[str] = field(default_factory=lambda: [
        "exec", "eval", "compile", "__import__", "open", "input"
    ])

@dataclass
class LLMConfig:
    """LLM provider configuration"""
    openai_api_key: Optional[str] = None
    anthropic_api_key: Optional[str] = None
    google_api_key: Optional[str] = None
    default_provider: str = "openai"
    timeout_seconds: int = 30
    max_retries: int = 3
    cache_enabled: bool = True
    cache_ttl_seconds: int = 3600

@dataclass
class MonitoringConfig:
    """Monitoring and observability configuration"""
    prometheus_enabled: bool = True
    prometheus_port: int = 9090
    jaeger_enabled: bool = True
    jaeger_endpoint: Optional[str] = None
    log_level: LogLevel = LogLevel.INFO
    structured_logging: bool = True
    
@dataclass
class CORSConfig:
    """CORS configuration"""
    origins: List[str] = field(default_factory=lambda: ["*"])
    methods: List[str] = field(default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "OPTIONS"])
    headers: List[str] = field(default_factory=lambda: ["Content-Type", "Authorization"])
    credentials: bool = True

@dataclass
class AppConfig:
    """Main application configuration"""
    # Environment
    environment: Environment
    secret_key: str
    debug: bool = False
    testing: bool = False
    
    # Core settings
    app_name: str = "CodeGuardian AI"
    app_version: str = "1.0.0"
    
    # Component configurations
    database: Optional[DatabaseConfig] = None
    redis: Optional[RedisConfig] = None
    jwt: Optional[JWTConfig] = None
    security: Optional[SecurityConfig] = None
    rate_limit: Optional[RateLimitConfig] = None
    execution: Optional[ExecutionConfig] = None
    llm: Optional[LLMConfig] = None
    monitoring: Optional[MonitoringConfig] = None
    cors: Optional[CORSConfig] = None
    
    # Admin settings
    admin_username: str = "admin"
    admin_email: str = "admin@codeguardian.ai"
    admin_password: str = "admin123"
    
    def __post_init__(self):
        # Validate critical settings
        if not self.secret_key or len(self.secret_key) < 32:
            raise ValueError("App secret key must be at least 32 characters")
            
        # Environment-specific validations
        if self.environment == Environment.PRODUCTION:
            if self.debug:
                raise ValueError("Debug mode cannot be enabled in production")
            if self.admin_password == "admin123":
                raise ValueError("Default admin password cannot be used in production")

class ConfigManager:
    """Enterprise configuration manager with encryption and validation"""
    
    def __init__(self, config_path: Optional[str] = None):
        self.config_path = config_path or os.getenv('CONFIG_PATH', 'config')
        self.encryption_key = self._get_encryption_key()
        self._config: Optional[AppConfig] = None
        
    def _get_encryption_key(self) -> Optional[Fernet]:
        """Get encryption key for sensitive configuration values"""
        key = os.getenv('CONFIG_ENCRYPTION_KEY')
        if key:
            try:
                return Fernet(key.encode())
            except Exception:
                logging.warning("Invalid encryption key provided")
        return None
    
    def _decrypt_value(self, value: str) -> str:
        """Decrypt an encrypted configuration value"""
        if not self.encryption_key:
            return value
            
        try:
            if value.startswith('encrypted:'):
                encrypted_data = value[10:]  # Remove 'encrypted:' prefix
                decrypted = self.encryption_key.decrypt(encrypted_data.encode())
                return decrypted.decode()
        except Exception:
            logging.warning(f"Failed to decrypt configuration value")
            
        return value
    
    def _load_from_env(self) -> AppConfig:
        """Load configuration from environment variables"""
        
        # Determine environment
        env_name = os.getenv('FLASK_ENV', 'development').lower()
        try:
            environment = Environment(env_name)
        except ValueError:
            environment = Environment.DEVELOPMENT
            
        # Database configuration
        database = DatabaseConfig(
            url=os.getenv('DATABASE_URL', 'sqlite:///codeguardian.db'),
            pool_size=int(os.getenv('DB_POOL_SIZE', '10')),
            max_overflow=int(os.getenv('DB_MAX_OVERFLOW', '20')),
            pool_timeout=int(os.getenv('DB_POOL_TIMEOUT', '30')),
            pool_recycle=int(os.getenv('DB_POOL_RECYCLE', '3600')),
            echo=os.getenv('DB_ECHO', 'false').lower() == 'true'
        )
        
        # Redis configuration
        redis = RedisConfig(
            url=os.getenv('REDIS_URL', 'redis://localhost:6379/0'),
            max_connections=int(os.getenv('REDIS_MAX_CONNECTIONS', '100')),
            retry_on_timeout=os.getenv('REDIS_RETRY_ON_TIMEOUT', 'true').lower() == 'true',
            socket_timeout=int(os.getenv('REDIS_SOCKET_TIMEOUT', '5')),
            socket_connect_timeout=int(os.getenv('REDIS_CONNECT_TIMEOUT', '5'))
        )
        
        # JWT configuration
        jwt = JWTConfig(
            secret_key=self._decrypt_value(os.getenv('JWT_SECRET_KEY', 'jwt-secret-key-change-in-production-12345678901234567890')),
            algorithm=os.getenv('JWT_ALGORITHM', 'HS256'),
            access_token_expire_minutes=int(os.getenv('JWT_ACCESS_TOKEN_EXPIRE_MINUTES', '30')),
            refresh_token_expire_days=int(os.getenv('JWT_REFRESH_TOKEN_EXPIRE_DAYS', '7')),
            api_key_expire_days=int(os.getenv('API_KEY_EXPIRE_DAYS', '365'))
        )
        
        # Security configuration
        security = SecurityConfig(
            max_login_attempts=int(os.getenv('MAX_LOGIN_ATTEMPTS', '5')),
            lockout_duration_minutes=int(os.getenv('LOCKOUT_DURATION_MINUTES', '15')),
            password_min_length=int(os.getenv('PASSWORD_MIN_LENGTH', '8')),
            require_special_chars=os.getenv('REQUIRE_SPECIAL_CHARS', 'true').lower() == 'true',
            session_timeout_minutes=int(os.getenv('SESSION_TIMEOUT_MINUTES', '60')),
            csrf_protection=os.getenv('CSRF_PROTECTION', 'true').lower() == 'true'
        )
        
        # Rate limiting configuration
        rate_limit = RateLimitConfig(
            enabled=os.getenv('RATE_LIMITING_ENABLED', 'true').lower() == 'true',
            storage=os.getenv('RATE_LIMITING_STORAGE', 'redis'),
            default_per_minute=int(os.getenv('RATE_LIMIT_PER_MINUTE', '100')),
            default_per_hour=int(os.getenv('RATE_LIMIT_PER_HOUR', '1000')),
            default_per_day=int(os.getenv('RATE_LIMIT_PER_DAY', '10000'))
        )
        
        # Execution configuration
        execution = ExecutionConfig(
            timeout_seconds=int(os.getenv('EXECUTION_TIMEOUT_SECONDS', '30')),
            max_memory_mb=int(os.getenv('EXECUTION_MAX_MEMORY_MB', '256')),
            max_disk_mb=int(os.getenv('EXECUTION_MAX_DISK_MB', '100')),
            max_output_size=int(os.getenv('EXECUTION_MAX_OUTPUT_SIZE', '10000'))
        )
        
        # LLM configuration
        llm = LLMConfig(
            openai_api_key=self._decrypt_value(os.getenv('OPENAI_API_KEY', '')),
            anthropic_api_key=self._decrypt_value(os.getenv('ANTHROPIC_API_KEY', '')),
            google_api_key=self._decrypt_value(os.getenv('GOOGLE_API_KEY', '')),
            default_provider=os.getenv('DEFAULT_LLM_PROVIDER', 'openai'),
            timeout_seconds=int(os.getenv('LLM_TIMEOUT_SECONDS', '30')),
            max_retries=int(os.getenv('LLM_MAX_RETRIES', '3')),
            cache_enabled=os.getenv('LLM_CACHE_ENABLED', 'true').lower() == 'true',
            cache_ttl_seconds=int(os.getenv('LLM_CACHE_TTL_SECONDS', '3600'))
        )
        
        # Monitoring configuration
        try:
            log_level = LogLevel(os.getenv('LOG_LEVEL', 'INFO').upper())
        except ValueError:
            log_level = LogLevel.INFO
            
        monitoring = MonitoringConfig(
            prometheus_enabled=os.getenv('PROMETHEUS_ENABLED', 'true').lower() == 'true',
            prometheus_port=int(os.getenv('PROMETHEUS_PORT', '9090')),
            jaeger_enabled=os.getenv('JAEGER_ENABLED', 'true').lower() == 'true',
            jaeger_endpoint=os.getenv('JAEGER_ENDPOINT'),
            log_level=log_level,
            structured_logging=os.getenv('STRUCTURED_LOGGING', 'true').lower() == 'true'
        )
        
        # CORS configuration
        cors_origins = os.getenv('CORS_ORIGINS', '*')
        if cors_origins == '*':
            origins = ['*']
        else:
            origins = [origin.strip() for origin in cors_origins.split(',')]
            
        cors = CORSConfig(origins=origins)
        
        return AppConfig(
            environment=environment,
            secret_key=self._decrypt_value(os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production-12345678901234567890')),
            debug=os.getenv('FLASK_DEBUG', 'false').lower() == 'true',
            testing=os.getenv('TESTING', 'false').lower() == 'true',
            app_name=os.getenv('APP_NAME', 'CodeGuardian AI'),
            app_version=os.getenv('APP_VERSION', '1.0.0'),
            database=database,
            redis=redis,
            jwt=jwt,
            security=security,
            rate_limit=rate_limit,
            execution=execution,
            llm=llm,
            monitoring=monitoring,
            cors=cors,
            admin_username=os.getenv('ADMIN_USERNAME', 'admin'),
            admin_email=os.getenv('ADMIN_EMAIL', 'admin@codeguardian.ai'),
            admin_password=self._decrypt_value(os.getenv('ADMIN_PASSWORD', 'admin123'))
        )
    
    def load_config(self, config_file: Optional[str] = None) -> AppConfig:
        """Load configuration from file or environment"""
        self._config = self._load_from_env()
        return self._config
    
    def get_config(self) -> AppConfig:
        """Get current configuration"""
        if self._config is None:
            self._config = self.load_config()
        return self._config
    
    def validate_config(self, config: AppConfig) -> List[str]:
        """Validate configuration and return list of errors"""
        errors = []
        
        # Environment-specific validations
        if config.environment == Environment.PRODUCTION:
            if config.debug:
                errors.append("Debug mode cannot be enabled in production")
            if config.admin_password == "admin123":
                errors.append("Default admin password cannot be used in production")
                
        # Security validations
        if len(config.secret_key) < 32:
            errors.append("Secret key must be at least 32 characters")
        if config.jwt and len(config.jwt.secret_key) < 32:
            errors.append("JWT secret key must be at least 32 characters")
            
        # Database validations
        if config.database and not config.database.url:
            errors.append("Database URL is required")
            
        return errors

# Global configuration manager
config_manager = ConfigManager()

def get_config() -> AppConfig:
    """Get application configuration"""
    return config_manager.get_config()

def load_config(config_file: Optional[str] = None) -> AppConfig:
    """Load and return application configuration"""
    return config_manager.load_config(config_file)

