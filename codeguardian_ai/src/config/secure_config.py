"""
CodeGuardian AI - Enterprise Configuration Management System
Secure configuration management with environment variables, secrets, and encryption
"""

import os
import json
import base64
import secrets
from typing import Dict, Any, Optional, Union, List
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
import logging
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import keyring

# Configure logging
logger = logging.getLogger(__name__)

class Environment(Enum):
    """Application environments"""
    DEVELOPMENT = "development"
    TESTING = "testing"
    STAGING = "staging"
    PRODUCTION = "production"

class SecretType(Enum):
    """Types of secrets for different handling"""
    DATABASE_URL = "database_url"
    JWT_SECRET = "jwt_secret"
    API_KEY = "api_key"
    ENCRYPTION_KEY = "encryption_key"
    OAUTH_SECRET = "oauth_secret"
    WEBHOOK_SECRET = "webhook_secret"

@dataclass
class SecretConfig:
    """Configuration for a secret"""
    name: str
    secret_type: SecretType
    required: bool = True
    default: Optional[str] = None
    description: str = ""
    rotation_days: Optional[int] = None  # Auto-rotation period
    min_length: int = 8
    max_length: int = 512

class SecretManager:
    """Enterprise-grade secret management with encryption and rotation"""
    
    def __init__(self, master_key: Optional[str] = None, keyring_service: str = "codeguardian_ai"):
        self.keyring_service = keyring_service
        self.master_key = master_key or self._get_or_create_master_key()
        self.cipher = self._create_cipher()
        
        # Secret configurations
        self.secret_configs = {
            'JWT_SECRET_KEY': SecretConfig(
                name='JWT_SECRET_KEY',
                secret_type=SecretType.JWT_SECRET,
                description='Secret key for JWT token signing',
                rotation_days=90,
                min_length=32
            ),
            'DATABASE_URL': SecretConfig(
                name='DATABASE_URL',
                secret_type=SecretType.DATABASE_URL,
                description='Database connection URL',
                required=False,
                default='sqlite:///codeguardian.db'
            ),
            'ENCRYPTION_KEY': SecretConfig(
                name='ENCRYPTION_KEY',
                secret_type=SecretType.ENCRYPTION_KEY,
                description='Key for encrypting sensitive data',
                rotation_days=180,
                min_length=32
            ),
            'API_RATE_LIMIT_SECRET': SecretConfig(
                name='API_RATE_LIMIT_SECRET',
                secret_type=SecretType.API_KEY,
                description='Secret for rate limiting calculations',
                rotation_days=30,
                min_length=16
            ),
            'AUDIT_ENCRYPTION_KEY': SecretConfig(
                name='AUDIT_ENCRYPTION_KEY',
                secret_type=SecretType.ENCRYPTION_KEY,
                description='Key for encrypting audit logs',
                rotation_days=365,
                min_length=32
            )
        }
    
    def _get_or_create_master_key(self) -> str:
        """Get or create master encryption key"""
        try:
            # Try to get existing master key from keyring
            master_key = keyring.get_password(self.keyring_service, "master_key")
            if master_key:
                return master_key
        except Exception as e:
            logger.warning(f"Could not access keyring: {e}")
        
        # Generate new master key
        master_key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
        
        try:
            # Store in keyring if available
            keyring.set_password(self.keyring_service, "master_key", master_key)
            logger.info("Master key stored in system keyring")
        except Exception as e:
            logger.warning(f"Could not store master key in keyring: {e}")
            # Fallback: store in environment variable
            os.environ['CODEGUARDIAN_MASTER_KEY'] = master_key
            logger.info("Master key stored in environment variable")
        
        return master_key
    
    def _create_cipher(self) -> Fernet:
        """Create encryption cipher from master key"""
        # Derive key from master key
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'codeguardian_salt',  # In production, use random salt
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(self.master_key.encode()))
        return Fernet(key)
    
    def generate_secret(self, secret_name: str, length: Optional[int] = None) -> str:
        """Generate a new secret value"""
        config = self.secret_configs.get(secret_name)
        if not config:
            raise ValueError(f"Unknown secret: {secret_name}")
        
        # Determine length
        if length is None:
            if config.secret_type == SecretType.JWT_SECRET:
                length = 64
            elif config.secret_type == SecretType.ENCRYPTION_KEY:
                length = 32
            elif config.secret_type == SecretType.API_KEY:
                length = 32
            else:
                length = 32
        
        # Validate length
        if length < config.min_length or length > config.max_length:
            raise ValueError(f"Secret length must be between {config.min_length} and {config.max_length}")
        
        # Generate secret based on type
        if config.secret_type in [SecretType.JWT_SECRET, SecretType.ENCRYPTION_KEY, SecretType.API_KEY]:
            # Generate cryptographically secure random string
            return base64.urlsafe_b64encode(secrets.token_bytes(length)).decode()[:length]
        else:
            # Generate alphanumeric string
            return secrets.token_urlsafe(length)[:length]
    
    def encrypt_secret(self, value: str) -> str:
        """Encrypt a secret value"""
        return self.cipher.encrypt(value.encode()).decode()
    
    def decrypt_secret(self, encrypted_value: str) -> str:
        """Decrypt a secret value"""
        return self.cipher.decrypt(encrypted_value.encode()).decode()
    
    def store_secret(self, name: str, value: str, encrypt: bool = True) -> None:
        """Store a secret securely"""
        try:
            # Store in keyring if available
            stored_value = self.encrypt_secret(value) if encrypt else value
            keyring.set_password(self.keyring_service, name, stored_value)
            logger.info(f"Secret '{name}' stored in keyring")
        except Exception as e:
            logger.warning(f"Could not store secret in keyring: {e}")
            # Fallback: store in environment variable (not recommended for production)
            os.environ[name] = value
            logger.warning(f"Secret '{name}' stored in environment variable (fallback)")
    
    def get_secret(self, name: str, decrypt: bool = True) -> Optional[str]:
        """Retrieve a secret securely"""
        try:
            # Try keyring first
            value = keyring.get_password(self.keyring_service, name)
            if value and decrypt:
                try:
                    return self.decrypt_secret(value)
                except Exception:
                    # Value might not be encrypted
                    return value
            elif value:
                return value
        except Exception as e:
            logger.warning(f"Could not access keyring for secret '{name}': {e}")
        
        # Fallback: environment variable
        return os.getenv(name)
    
    def rotate_secret(self, name: str) -> str:
        """Rotate a secret (generate new value and store)"""
        config = self.secret_configs.get(name)
        if not config:
            raise ValueError(f"Unknown secret: {name}")
        
        # Generate new secret
        new_value = self.generate_secret(name)
        
        # Store new secret
        self.store_secret(name, new_value)
        
        logger.info(f"Secret '{name}' rotated successfully")
        return new_value
    
    def validate_secret(self, name: str, value: str) -> bool:
        """Validate a secret against its configuration"""
        config = self.secret_configs.get(name)
        if not config:
            return False
        
        # Check length
        if len(value) < config.min_length or len(value) > config.max_length:
            return False
        
        # Type-specific validation
        if config.secret_type == SecretType.DATABASE_URL:
            return value.startswith(('sqlite:///', 'postgresql://', 'mysql://'))
        elif config.secret_type in [SecretType.JWT_SECRET, SecretType.ENCRYPTION_KEY, SecretType.API_KEY]:
            # Check if it's a valid base64 string
            try:
                base64.urlsafe_b64decode(value + '==')  # Add padding
                return True
            except Exception:
                return False
        
        return True

@dataclass
class DatabaseConfig:
    """Database configuration"""
    url: str = "sqlite:///codeguardian.db"
    pool_size: int = 10
    max_overflow: int = 20
    pool_timeout: int = 30
    pool_recycle: int = 3600
    echo: bool = False

@dataclass
class SecurityConfig:
    """Security configuration"""
    jwt_secret_key: str = ""
    jwt_access_token_expires: int = 3600  # 1 hour
    jwt_refresh_token_expires: int = 2592000  # 30 days
    password_hash_rounds: int = 12
    max_login_attempts: int = 5
    lockout_duration: int = 900  # 15 minutes
    encryption_key: str = ""
    audit_encryption_key: str = ""

@dataclass
class RateLimitConfig:
    """Rate limiting configuration"""
    enabled: bool = True
    default_requests: int = 100
    default_window: int = 3600  # 1 hour
    redis_url: Optional[str] = None
    secret_key: str = ""

@dataclass
class AuditConfig:
    """Audit configuration"""
    enabled: bool = True
    log_file: str = "logs/audit.jsonl"
    performance_log_file: str = "logs/performance.jsonl"
    security_log_file: str = "logs/security.jsonl"
    max_file_size: int = 100 * 1024 * 1024  # 100MB
    backup_count: int = 10
    enable_console: bool = True
    enable_syslog: bool = False
    encryption_enabled: bool = True

@dataclass
class ExecutionConfig:
    """Code execution configuration"""
    default_timeout: int = 10
    max_timeout: int = 300
    default_memory_mb: int = 128
    max_memory_mb: int = 1024
    default_disk_mb: int = 10
    max_disk_mb: int = 100
    sandbox_enabled: bool = True
    allowed_languages: List[str] = field(default_factory=lambda: ['python', 'javascript', 'bash'])

@dataclass
class AppConfig:
    """Main application configuration"""
    # Basic app settings
    app_name: str = "CodeGuardian AI"
    version: str = "1.0.0"
    environment: Environment = Environment.DEVELOPMENT
    debug: bool = False
    host: str = "0.0.0.0"
    port: int = 5001
    
    # Component configurations
    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    audit: AuditConfig = field(default_factory=AuditConfig)
    execution: ExecutionConfig = field(default_factory=ExecutionConfig)
    
    # Feature flags
    enable_authentication: bool = True
    enable_rate_limiting: bool = True
    enable_audit_logging: bool = True
    enable_code_execution: bool = True
    enable_security_analysis: bool = True

class ConfigManager:
    """Enterprise configuration manager with environment-specific settings"""
    
    def __init__(self, environment: Optional[Environment] = None):
        self.environment = environment or self._detect_environment()
        self.secret_manager = SecretManager()
        self.config = self._load_config()
        self._validate_config()
        self._ensure_secrets()
    
    def _detect_environment(self) -> Environment:
        """Detect current environment"""
        env_name = os.getenv('CODEGUARDIAN_ENV', 'development').lower()
        try:
            return Environment(env_name)
        except ValueError:
            logger.warning(f"Unknown environment '{env_name}', defaulting to development")
            return Environment.DEVELOPMENT
    
    def _load_config(self) -> AppConfig:
        """Load configuration from environment variables and files"""
        config = AppConfig()
        
        # Set environment
        config.environment = self.environment
        
        # Basic app settings
        config.app_name = os.getenv('CODEGUARDIAN_APP_NAME', config.app_name)
        config.version = os.getenv('CODEGUARDIAN_VERSION', config.version)
        config.debug = os.getenv('CODEGUARDIAN_DEBUG', 'false').lower() == 'true'
        config.host = os.getenv('CODEGUARDIAN_HOST', config.host)
        config.port = int(os.getenv('CODEGUARDIAN_PORT', str(config.port)))
        
        # Database configuration
        config.database.url = os.getenv('DATABASE_URL', config.database.url)
        config.database.pool_size = int(os.getenv('DB_POOL_SIZE', str(config.database.pool_size)))
        config.database.echo = os.getenv('DB_ECHO', 'false').lower() == 'true'
        
        # Security configuration
        config.security.jwt_access_token_expires = int(os.getenv('JWT_ACCESS_TOKEN_EXPIRES', str(config.security.jwt_access_token_expires)))
        config.security.jwt_refresh_token_expires = int(os.getenv('JWT_REFRESH_TOKEN_EXPIRES', str(config.security.jwt_refresh_token_expires)))
        config.security.password_hash_rounds = int(os.getenv('PASSWORD_HASH_ROUNDS', str(config.security.password_hash_rounds)))
        config.security.max_login_attempts = int(os.getenv('MAX_LOGIN_ATTEMPTS', str(config.security.max_login_attempts)))
        
        # Rate limiting configuration
        config.rate_limit.enabled = os.getenv('RATE_LIMIT_ENABLED', 'true').lower() == 'true'
        config.rate_limit.default_requests = int(os.getenv('RATE_LIMIT_REQUESTS', str(config.rate_limit.default_requests)))
        config.rate_limit.default_window = int(os.getenv('RATE_LIMIT_WINDOW', str(config.rate_limit.default_window)))
        config.rate_limit.redis_url = os.getenv('REDIS_URL')
        
        # Audit configuration
        config.audit.enabled = os.getenv('AUDIT_ENABLED', 'true').lower() == 'true'
        config.audit.log_file = os.getenv('AUDIT_LOG_FILE', config.audit.log_file)
        config.audit.enable_console = os.getenv('AUDIT_CONSOLE', 'true').lower() == 'true'
        config.audit.encryption_enabled = os.getenv('AUDIT_ENCRYPTION', 'true').lower() == 'true'
        
        # Execution configuration
        config.execution.default_timeout = int(os.getenv('EXEC_DEFAULT_TIMEOUT', str(config.execution.default_timeout)))
        config.execution.max_timeout = int(os.getenv('EXEC_MAX_TIMEOUT', str(config.execution.max_timeout)))
        config.execution.default_memory_mb = int(os.getenv('EXEC_DEFAULT_MEMORY', str(config.execution.default_memory_mb)))
        config.execution.max_memory_mb = int(os.getenv('EXEC_MAX_MEMORY', str(config.execution.max_memory_mb)))
        
        # Feature flags
        config.enable_authentication = os.getenv('ENABLE_AUTH', 'true').lower() == 'true'
        config.enable_rate_limiting = os.getenv('ENABLE_RATE_LIMIT', 'true').lower() == 'true'
        config.enable_audit_logging = os.getenv('ENABLE_AUDIT', 'true').lower() == 'true'
        
        # Environment-specific overrides
        if self.environment == Environment.PRODUCTION:
            config.debug = False
            config.security.password_hash_rounds = max(config.security.password_hash_rounds, 14)
            config.audit.enable_console = False
            config.audit.encryption_enabled = True
        elif self.environment == Environment.DEVELOPMENT:
            config.debug = True
            config.security.password_hash_rounds = min(config.security.password_hash_rounds, 8)
        
        return config
    
    def _validate_config(self) -> None:
        """Validate configuration values"""
        errors = []
        
        # Validate port
        if not (1 <= self.config.port <= 65535):
            errors.append(f"Invalid port: {self.config.port}")
        
        # Validate timeouts
        if self.config.execution.default_timeout > self.config.execution.max_timeout:
            errors.append("Default timeout cannot be greater than max timeout")
        
        # Validate memory limits
        if self.config.execution.default_memory_mb > self.config.execution.max_memory_mb:
            errors.append("Default memory cannot be greater than max memory")
        
        # Validate hash rounds
        if not (4 <= self.config.security.password_hash_rounds <= 20):
            errors.append(f"Password hash rounds must be between 4 and 20, got {self.config.security.password_hash_rounds}")
        
        if errors:
            raise ValueError(f"Configuration validation failed: {'; '.join(errors)}")
    
    def _ensure_secrets(self) -> None:
        """Ensure all required secrets are available"""
        # JWT Secret
        jwt_secret = self.secret_manager.get_secret('JWT_SECRET_KEY')
        if not jwt_secret:
            jwt_secret = self.secret_manager.generate_secret('JWT_SECRET_KEY')
            self.secret_manager.store_secret('JWT_SECRET_KEY', jwt_secret)
            logger.info("Generated new JWT secret key")
        self.config.security.jwt_secret_key = jwt_secret
        
        # Encryption Key
        encryption_key = self.secret_manager.get_secret('ENCRYPTION_KEY')
        if not encryption_key:
            encryption_key = self.secret_manager.generate_secret('ENCRYPTION_KEY')
            self.secret_manager.store_secret('ENCRYPTION_KEY', encryption_key)
            logger.info("Generated new encryption key")
        self.config.security.encryption_key = encryption_key
        
        # Audit Encryption Key
        audit_key = self.secret_manager.get_secret('AUDIT_ENCRYPTION_KEY')
        if not audit_key:
            audit_key = self.secret_manager.generate_secret('AUDIT_ENCRYPTION_KEY')
            self.secret_manager.store_secret('AUDIT_ENCRYPTION_KEY', audit_key)
            logger.info("Generated new audit encryption key")
        self.config.audit.encryption_key = audit_key
        
        # Rate Limit Secret
        rate_limit_secret = self.secret_manager.get_secret('API_RATE_LIMIT_SECRET')
        if not rate_limit_secret:
            rate_limit_secret = self.secret_manager.generate_secret('API_RATE_LIMIT_SECRET')
            self.secret_manager.store_secret('API_RATE_LIMIT_SECRET', rate_limit_secret)
            logger.info("Generated new rate limit secret")
        self.config.rate_limit.secret_key = rate_limit_secret
    
    def get_config(self) -> AppConfig:
        """Get the current configuration"""
        return self.config
    
    def update_config(self, updates: Dict[str, Any]) -> None:
        """Update configuration values"""
        for key, value in updates.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)
                logger.info(f"Updated config: {key} = {value}")
            else:
                logger.warning(f"Unknown config key: {key}")
        
        # Re-validate after updates
        self._validate_config()
    
    def rotate_secrets(self) -> Dict[str, str]:
        """Rotate all secrets"""
        rotated = {}
        for secret_name in self.secret_manager.secret_configs.keys():
            try:
                new_value = self.secret_manager.rotate_secret(secret_name)
                rotated[secret_name] = "rotated"
                logger.info(f"Rotated secret: {secret_name}")
            except Exception as e:
                logger.error(f"Failed to rotate secret {secret_name}: {e}")
                rotated[secret_name] = f"error: {e}"
        
        # Update config with new secrets
        self._ensure_secrets()
        
        return rotated
    
    def export_config(self, include_secrets: bool = False) -> Dict[str, Any]:
        """Export configuration (optionally including secrets)"""
        config_dict = {
            'app_name': self.config.app_name,
            'version': self.config.version,
            'environment': self.config.environment.value,
            'debug': self.config.debug,
            'host': self.config.host,
            'port': self.config.port,
            'database': {
                'url': self.config.database.url if include_secrets else '[REDACTED]',
                'pool_size': self.config.database.pool_size,
                'echo': self.config.database.echo
            },
            'security': {
                'jwt_secret_key': self.config.security.jwt_secret_key if include_secrets else '[REDACTED]',
                'jwt_access_token_expires': self.config.security.jwt_access_token_expires,
                'password_hash_rounds': self.config.security.password_hash_rounds,
                'max_login_attempts': self.config.security.max_login_attempts
            },
            'rate_limit': {
                'enabled': self.config.rate_limit.enabled,
                'default_requests': self.config.rate_limit.default_requests,
                'default_window': self.config.rate_limit.default_window,
                'secret_key': self.config.rate_limit.secret_key if include_secrets else '[REDACTED]'
            },
            'audit': {
                'enabled': self.config.audit.enabled,
                'log_file': self.config.audit.log_file,
                'encryption_enabled': self.config.audit.encryption_enabled
            },
            'execution': {
                'default_timeout': self.config.execution.default_timeout,
                'max_timeout': self.config.execution.max_timeout,
                'default_memory_mb': self.config.execution.default_memory_mb,
                'max_memory_mb': self.config.execution.max_memory_mb
            },
            'features': {
                'authentication': self.config.enable_authentication,
                'rate_limiting': self.config.enable_rate_limiting,
                'audit_logging': self.config.enable_audit_logging,
                'code_execution': self.config.enable_code_execution,
                'security_analysis': self.config.enable_security_analysis
            }
        }
        
        return config_dict

# Global configuration instance
_config_manager: Optional[ConfigManager] = None

def get_config_manager() -> ConfigManager:
    """Get the global configuration manager instance"""
    global _config_manager
    if _config_manager is None:
        _config_manager = ConfigManager()
    return _config_manager

def get_config() -> AppConfig:
    """Get the current application configuration"""
    return get_config_manager().get_config()

def initialize_config(environment: Optional[Environment] = None) -> ConfigManager:
    """Initialize the configuration system"""
    global _config_manager
    _config_manager = ConfigManager(environment)
    logger.info(f"Configuration initialized for environment: {_config_manager.environment.value}")
    return _config_manager

# Testing function
if __name__ == "__main__":
    # Test configuration system
    print("Testing Configuration System:")
    
    # Initialize config
    config_manager = initialize_config(Environment.DEVELOPMENT)
    config = get_config()
    
    print(f"Environment: {config.environment.value}")
    print(f"App Name: {config.app_name}")
    print(f"Version: {config.version}")
    print(f"Debug: {config.debug}")
    print(f"Host: {config.host}")
    print(f"Port: {config.port}")
    
    # Test secret management
    print("\nTesting Secret Management:")
    secret_manager = config_manager.secret_manager
    
    # Test secret generation
    test_secret = secret_manager.generate_secret('JWT_SECRET_KEY')
    print(f"Generated JWT secret: {test_secret[:10]}...")
    
    # Test encryption
    encrypted = secret_manager.encrypt_secret("test_value")
    decrypted = secret_manager.decrypt_secret(encrypted)
    print(f"Encryption test: {'test_value' == decrypted}")
    
    # Export config (without secrets)
    print("\nConfiguration Export (sanitized):")
    exported = config_manager.export_config(include_secrets=False)
    print(json.dumps(exported, indent=2))

