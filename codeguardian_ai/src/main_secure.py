import os
import sys
# DON'T CHANGE THIS PATH SETUP
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables
load_dotenv('.env.secure')

# Initialize secure configuration FIRST
from src.config.secure_config import initialize_config, get_config, Environment
from src.models.user import db
from src.routes.user import user_bp
from src.routes.api_validated import api_bp
from src.routes.auth import auth_bp

# Initialize configuration system
config_manager = initialize_config()
config = get_config()

# Initialize audit system with secure config
from src.audit.audit_system import initialize_audit_system, get_audit_manager, EventType, LogLevel

# Initialize audit with config
audit_config = {
    'audit_log_file': config.audit.log_file,
    'performance_log_file': config.audit.performance_log_file,
    'security_log_file': config.audit.security_log_file,
    'enable_console': config.audit.enable_console,
    'enable_syslog': config.audit.enable_syslog
}
initialize_audit_system(audit_config)
audit_manager = get_audit_manager()

# Create Flask app with secure configuration
app = Flask(__name__, static_folder=os.path.join(os.path.dirname(__file__), 'static'))

# Configure Flask with secure settings
app.config['SECRET_KEY'] = config.security.jwt_secret_key
app.config['SQLALCHEMY_DATABASE_URI'] = config.database.url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_size': config.database.pool_size,
    'max_overflow': config.database.max_overflow,
    'pool_timeout': config.database.pool_timeout,
    'pool_recycle': config.database.pool_recycle,
    'echo': config.database.echo
}

# Enable CORS for all domains
CORS(app, origins="*", allow_headers=["Content-Type", "Authorization"])

# Initialize database
db.init_app(app)

# Register blueprints
app.register_blueprint(user_bp, url_prefix='/api')
app.register_blueprint(api_bp, url_prefix='/api')
app.register_blueprint(auth_bp, url_prefix='/api/auth')

# Create tables
with app.app_context():
    db.create_all()

@app.route('/')
def index():
    """Serve the main application page"""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/config')
def get_app_config():
    """Get application configuration (sanitized)"""
    return config_manager.export_config(include_secrets=False)

@app.route('/health')
def health_check():
    """Health check endpoint"""
    return {
        'status': 'healthy',
        'version': config.version,
        'environment': config.environment.value,
        'features': {
            'authentication': config.enable_authentication,
            'rate_limiting': config.enable_rate_limiting,
            'audit_logging': config.enable_audit_logging,
            'code_execution': config.enable_code_execution,
            'security_analysis': config.enable_security_analysis
        }
    }

if __name__ == '__main__':
    # Log startup with secure config
    audit_manager.audit_logger.log_event(
        event_type=EventType.SYSTEM_STARTUP,
        message="CodeGuardian AI MVP Core starting with secure configuration",
        level=LogLevel.INFO,
        details={
            'version': config.version,
            'environment': config.environment.value,
            'features_enabled': {
                'authentication': config.enable_authentication,
                'rate_limiting': config.enable_rate_limiting,
                'audit_logging': config.enable_audit_logging
            }
        },
        tags=['system', 'startup', 'secure']
    )
    
    print("🚀 CodeGuardian AI MVP Core starting with secure configuration...")
    print(f"📊 Environment: {config.environment.value}")
    print(f"🔐 Authentication: {'enabled' if config.enable_authentication else 'disabled'}")
    print(f"⚡ Rate limiting: {'enabled' if config.enable_rate_limiting else 'disabled'}")
    print(f"🛡️ Audit logging: {'enabled' if config.enable_audit_logging else 'disabled'}")
    print(f"🔒 Secrets: securely managed")
    
    app.run(
        host=config.host,
        port=config.port,
        debug=config.debug
    )

