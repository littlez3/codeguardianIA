import os
import sys
# DON'T CHANGE THIS PATH SETUP
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask import Flask, send_from_directory
from flask_cors import CORS
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

from src.routes.user import user_bp
from src.routes.api_validated import api_bp

# Initialize audit system
from src.audit.audit_system import initialize_audit_system, get_audit_manager, EventType, LogLevel
audit_config = {
    'audit_log_file': 'logs/audit.jsonl',
    'performance_log_file': 'logs/performance.jsonl',
    'security_log_file': 'logs/security.jsonl',
    'enable_console': True,
    'enable_syslog': False
}
audit_manager = initialize_audit_system(audit_config)

# Initialize simple auth and rate limiting
from src.auth.simple_auth import auth_service
from src.auth.rate_limiting import init_rate_limiting

app = Flask(__name__, static_folder=os.path.join(os.path.dirname(__file__), 'static'))
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')

# Enable CORS
CORS(app)

# Initialize rate limiting
init_rate_limiting(app)

# Register blueprints
app.register_blueprint(user_bp, url_prefix='/api')
app.register_blueprint(api_bp, url_prefix='/api')

@app.route('/')
def index():
    """Serve the main application"""
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/health')
def health():
    """Health check endpoint"""
    return {
        'status': 'healthy',
        'service': 'CodeGuardian AI',
        'version': '1.0.0'
    }

if __name__ == '__main__':
    # Log system startup
    audit_logger = audit_manager.get_audit_logger()
    audit_logger.log_event(
        event_type=EventType.SYSTEM_STARTUP,
        message="CodeGuardian AI MVP Core starting",
        level=LogLevel.INFO,
        details={'version': '1.0.0'}
    )
    
    print("🚀 CodeGuardian AI MVP Core starting...")
    print("📊 Audit system initialized")
    print("🔐 Authentication system ready")
    print("⚡ Rate limiting active")
    print("🛡️ Security engines loaded")
    
    app.run(host='0.0.0.0', port=5001, debug=True)

