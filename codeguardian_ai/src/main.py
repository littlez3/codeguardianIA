import os
import sys
# DON'T CHANGE THIS PATH SETUP
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv
import asyncio
import logging
from datetime import datetime

# Load environment variables first
load_dotenv()

# Import enterprise configuration
from src.config.enterprise_config import get_config, load_config
from src.models.user import db
from src.routes.user import user_bp
from src.routes.api_enhanced import api_bp
from src.routes.auth import auth_bp
from src.routes.health import health_bp

# Initialize audit system
from src.audit.audit_system import initialize_audit_system, get_audit_manager, EventType, LogLevel
from src.auth.authentication import AuthService, AuthConfig, auth_service
from src.auth.rate_limiting import init_rate_limiting

def create_app(config_file: str = None) -> Flask:
    """Application factory with enterprise configuration"""
    
    # Load configuration
    config = load_config(config_file)
    
    # Validate configuration
    from src.config.enterprise_config import config_manager
    errors = config_manager.validate_config(config)
    if errors:
        raise ValueError(f"Configuration validation failed: {', '.join(errors)}")
    
    # Create Flask app
    app = Flask(__name__, static_folder=os.path.join(os.path.dirname(__file__), 'static'))
    
    # Configure Flask from enterprise config
    app.config['SECRET_KEY'] = config.secret_key
    app.config['JWT_SECRET_KEY'] = config.jwt.secret_key
    app.config['DEBUG'] = config.debug
    app.config['TESTING'] = config.testing
    app.config['ENV'] = config.environment.value
    
    # Database configuration
    app.config['SQLALCHEMY_DATABASE_URI'] = config.database.url
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'pool_size': config.database.pool_size,
        'max_overflow': config.database.max_overflow,
        'pool_timeout': config.database.pool_timeout,
        'pool_recycle': config.database.pool_recycle,
        'echo': config.database.echo
    }
    
    # Redis configuration
    app.config['REDIS_URL'] = config.redis.url
    
    # Store enterprise config in app
    app.config['ENTERPRISE_CONFIG'] = config
    
    # Configure CORS
    if config.cors.origins == ['*']:
        CORS(app, 
             methods=config.cors.methods,
             allow_headers=config.cors.headers,
             supports_credentials=config.cors.credentials)
    else:
        CORS(app, 
             origins=config.cors.origins,
             methods=config.cors.methods,
             allow_headers=config.cors.headers,
             supports_credentials=config.cors.credentials)
    
    # Initialize database
    db.init_app(app)
    
    # Initialize audit system
    audit_config = {
        'audit_log_file': 'logs/audit.jsonl',
        'performance_log_file': 'logs/performance.jsonl',
        'security_log_file': 'logs/security.jsonl',
        'enable_console': True,
        'enable_syslog': False,
        'log_level': config.monitoring.log_level.value,
        'structured_logging': config.monitoring.structured_logging
    }
    audit_manager = initialize_audit_system(audit_config)
    
    # Initialize authentication service
    auth_config = AuthConfig(
        jwt_secret_key=config.jwt.secret_key,
        jwt_algorithm=config.jwt.algorithm,
        access_token_expire_minutes=config.jwt.access_token_expire_minutes,
        refresh_token_expire_days=config.jwt.refresh_token_expire_days,
        api_key_expire_days=config.jwt.api_key_expire_days,
        max_login_attempts=config.security.max_login_attempts,
        lockout_duration_minutes=config.security.lockout_duration_minutes
    )
    
    # Initialize rate limiting
    if config.rate_limit.enabled:
        use_redis = config.rate_limit.storage.lower() == 'redis'
        redis_url = config.redis.url
        init_rate_limiting(app, use_redis, redis_url)
    
    # Register blueprints
    app.register_blueprint(user_bp, url_prefix='/api')
    app.register_blueprint(api_bp, url_prefix='/api')
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(health_bp, url_prefix='/api')
    
    # Create tables and initialize services
    with app.app_context():
        # Create database tables
        db.create_all()
        
        # Initialize global auth service
        import src.auth.authentication as auth_module
        auth_module.auth_service = AuthService(auth_config)
        
        # Create admin user if it doesn't exist
        from src.auth.authentication import AuthUser, UserRole
        admin_user = AuthUser.query.filter_by(username=config.admin_username).first()
        if not admin_user:
            try:
                admin_user = auth_module.auth_service.create_user(
                    config.admin_username, 
                    config.admin_email, 
                    config.admin_password, 
                    UserRole.ADMIN
                )
                app.logger.info(f"Created admin user: {config.admin_username}")
            except Exception as e:
                app.logger.error(f"Failed to create admin user: {e}")
        
        # Log application startup
        audit_logger = audit_manager.get_audit_logger()
        audit_logger.log_event(
            EventType.SYSTEM_STARTUP,
            LogLevel.INFO,
            "CodeGuardian AI application started",
            {
                "environment": config.environment.value,
                "version": config.app_version,
                "debug": config.debug,
                "timestamp": datetime.utcnow().isoformat()
            }
        )
    
    # Configure logging
    if not app.debug and not app.testing:
        # Production logging configuration
        if config.monitoring.structured_logging:
            try:
                import structlog
                structlog.configure(
                    processors=[
                        structlog.stdlib.filter_by_level,
                        structlog.stdlib.add_logger_name,
                        structlog.stdlib.add_log_level,
                        structlog.stdlib.PositionalArgumentsFormatter(),
                        structlog.processors.TimeStamper(fmt="iso"),
                        structlog.processors.StackInfoRenderer(),
                        structlog.processors.format_exc_info,
                        structlog.processors.UnicodeDecoder(),
                        structlog.processors.JSONRenderer()
                    ],
                    context_class=dict,
                    logger_factory=structlog.stdlib.LoggerFactory(),
                    wrapper_class=structlog.stdlib.BoundLogger,
                    cache_logger_on_first_use=True,
                )
            except ImportError:
                app.logger.warning("structlog not available, using standard logging")
        
        # Set log level
        app.logger.setLevel(getattr(logging, config.monitoring.log_level.value))
        
        # Add file handler
        if not os.path.exists('logs'):
            os.mkdir('logs')
        file_handler = logging.FileHandler('logs/codeguardian.log')
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(getattr(logging, config.monitoring.log_level.value))
        app.logger.addHandler(file_handler)
    
    return app

# Static file serving
def serve_static(app: Flask):
    """Configure static file serving"""
    @app.route('/', defaults={'path': ''})
    @app.route('/<path:path>')
    def serve(path):
        static_folder_path = app.static_folder
        if static_folder_path is None:
            return "Static folder not configured", 404

        if path != "" and os.path.exists(os.path.join(static_folder_path, path)):
            return send_from_directory(static_folder_path, path)
        else:
            index_path = os.path.join(static_folder_path, 'index.html')
            if os.path.exists(index_path):
                return send_from_directory(static_folder_path, 'index.html')
            else:
                return "index.html not found", 404

# Create application instance
app = create_app()
serve_static(app)

if __name__ == '__main__':
    config = get_config()
    
    # Development server configuration
    port = int(os.getenv('PORT', 5001))
    host = '0.0.0.0'  # Allow external connections
    
    app.logger.info(f"Starting CodeGuardian AI on {host}:{port}")
    app.logger.info(f"Environment: {config.environment.value}")
    app.logger.info(f"Debug mode: {config.debug}")
    
    app.run(host=host, port=port, debug=config.debug)

