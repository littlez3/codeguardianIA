# CodeGuardian AI - Enterprise Security Platform

## 🚀 Overview

CodeGuardian AI is an enterprise-grade autonomous DevSecOps orchestration platform that revolutionizes software security through advanced AI-powered code analysis, real-time threat detection, and automated vulnerability remediation.

## 🏗️ Architecture

### Enterprise Infrastructure
- **Kubernetes-native** deployment with HA configuration
- **Multi-layer security** with zero-trust architecture
- **Distributed rate limiting** with Redis coordination
- **Comprehensive audit logging** for compliance
- **Auto-scaling** based on load and threat levels

### Core Components

#### 1. Security Middleware (`src/middleware/security.py`)
- **15+ security checks** per request
- **Real-time threat detection** with 50+ malicious patterns
- **IP blocking** with automatic threat response
- **CSRF protection** for state-changing operations
- **Security headers** (HSTS, CSP, X-Frame-Options, etc.)

#### 2. Advanced Rate Limiting (`src/middleware/rate_limiting.py`)
- **4 algorithms**: Token Bucket, Sliding Window, Fixed Window, Adaptive
- **Distributed coordination** via Redis with Lua scripts
- **Threat-aware limiting** that adapts to suspicious activity
- **Multi-scope protection** (Global, IP, User, API Key, Endpoint)

#### 3. Input Validation System (`src/middleware/validation.py`)
- **Zero-trust input validation** with comprehensive sanitization
- **Threat detection** for XSS, SQL injection, command injection, etc.
- **4 sanitization modes**: Escape, Strip, Reject, Encode
- **Unicode attack protection** and encoding attack detection

#### 4. Enterprise Configuration (`src/config/enterprise_config.py`)
- **Environment-specific** configuration management
- **Secrets encryption** with Fernet encryption
- **Validation and compliance** checks
- **Hot-reload** configuration updates

#### 5. Audit System (`src/audit/audit_system.py`)
- **Comprehensive event logging** with structured JSON
- **Performance metrics** tracking
- **Security event correlation** 
- **Compliance reporting** capabilities

#### 6. API Core (`src/api/core.py`)
- **High-performance endpoints** with sub-200ms latency
- **Standardized response format** for consistency
- **Comprehensive error handling** with specific error codes
- **Real-time monitoring** and metrics collection

## 🔧 Installation & Setup

### Prerequisites
- Python 3.11+
- Redis 6.0+
- PostgreSQL 13+
- Docker & Kubernetes (for production)

### Local Development Setup

```bash
# Clone repository
git clone <repository-url>
cd codeguardian_ai

# Create virtual environment
python -m venv venv
source venv/bin/activate  # Linux/Mac
# or
venv\Scripts\activate     # Windows

# Install dependencies
pip install -r requirements.txt

# Setup environment variables
cp .env.example .env
# Edit .env with your configuration

# Initialize database
python -c "from src.main import create_app; app = create_app(); app.app_context().push(); from src.models.user import db; db.create_all()"

# Run application
python src/main.py
```

### Production Deployment

```bash
# Build Docker image
docker build -t codeguardian-ai:latest .

# Deploy to Kubernetes
kubectl apply -f infrastructure/kubernetes/namespace.yaml
kubectl apply -f infrastructure/kubernetes/postgres.yaml
kubectl apply -f infrastructure/kubernetes/redis.yaml

# Deploy application (customize deployment.yaml)
kubectl apply -f infrastructure/kubernetes/deployment.yaml
```

## 🔐 Security Features

### Multi-Layer Security Architecture
1. **Network Security**: TLS 1.3, security headers, IP filtering
2. **Application Security**: Input validation, CSRF protection, XSS prevention
3. **Authentication**: JWT with refresh tokens, role-based access control
4. **Authorization**: Granular permissions, API key management
5. **Audit & Monitoring**: Comprehensive logging, real-time alerting

### Threat Detection Capabilities
- **XSS Protection**: Script injection, event handler detection
- **SQL Injection**: Union queries, command execution, data extraction
- **Command Injection**: Shell command execution, system calls
- **Path Traversal**: Directory traversal, file access attempts
- **LDAP/NoSQL Injection**: Database-specific attack patterns
- **Encoding Attacks**: Multiple encoding, Unicode attacks

## 📊 Performance Specifications

### Benchmarks
- **API Response Time**: P95 < 200ms
- **Throughput**: 10,000+ RPS sustained
- **Memory Usage**: < 512MB base footprint
- **CPU Efficiency**: < 5% idle load
- **Database Connections**: Optimized pooling (10 base, 20 overflow)

### Scalability
- **Horizontal scaling**: Auto-scaling based on CPU/memory/response time
- **Database scaling**: Read replicas, connection pooling
- **Cache optimization**: Redis clustering, intelligent cache invalidation
- **Load balancing**: Kubernetes ingress with health checks

## 🛡️ API Endpoints

### Core API (`/api/v1/`)

#### Code Analysis
```http
POST /api/v1/analyze
Content-Type: application/json
Authorization: Bearer <token>

{
  "code": "def vulnerable_function(user_input): exec(user_input)",
  "language": "python",
  "analysis_type": "security"
}
```

#### Code Execution
```http
POST /api/v1/execute
Content-Type: application/json
Authorization: Bearer <token>

{
  "code": "print('Hello, World!')",
  "language": "python",
  "timeout": 10
}
```

#### Input Validation
```http
POST /api/v1/validate
Content-Type: application/json

{
  "data": {
    "username": "test_user",
    "email": "test@example.com"
  },
  "validation_level": "strict"
}
```

### Admin API (`/api/v1/admin/`)

#### User Management
```http
GET /api/v1/admin/users
Authorization: Bearer <admin-token>
```

#### Audit Logs
```http
GET /api/v1/admin/audit-logs?limit=100&event_type=security
Authorization: Bearer <admin-token>
```

## 🔧 Configuration

### Environment Variables

```bash
# Application
SECRET_KEY=your-secret-key-32-chars-minimum
FLASK_ENV=production
FLASK_DEBUG=false

# Database
DATABASE_URL=postgresql://user:pass@localhost/codeguardian
DB_POOL_SIZE=10
DB_MAX_OVERFLOW=20

# Redis
REDIS_URL=redis://localhost:6379/0
REDIS_MAX_CONNECTIONS=100

# JWT
JWT_SECRET_KEY=your-jwt-secret-key-32-chars-minimum
JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# Security
MAX_LOGIN_ATTEMPTS=5
LOCKOUT_DURATION_MINUTES=15
RATE_LIMITING_ENABLED=true

# Monitoring
LOG_LEVEL=INFO
PROMETHEUS_ENABLED=true
JAEGER_ENABLED=true
```

### Rate Limiting Configuration

The system includes sophisticated rate limiting with multiple algorithms:

- **Token Bucket**: Burst handling with sustained rate control
- **Sliding Window**: Precise time-based limiting
- **Fixed Window**: Simple time-window based limiting  
- **Adaptive**: Dynamic adjustment based on system load and threats

## 📈 Monitoring & Observability

### Health Checks
- **Liveness**: `/api/health/live` - Application is running
- **Readiness**: `/api/health/ready` - Application is ready to serve traffic
- **Startup**: `/api/health/startup` - Application has started successfully

### Metrics
- **Prometheus metrics** at `/metrics`
- **Custom business metrics** via audit system
- **Performance tracking** with request timing
- **Error rate monitoring** with alerting

### Logging
- **Structured JSON logging** for machine parsing
- **Audit trail** for compliance and security
- **Performance metrics** for optimization
- **Security events** for threat analysis

## 🧪 Testing

### Running Tests
```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=src --cov-report=html

# Run security tests
pytest tests/test_security.py

# Run performance tests
pytest tests/test_performance.py -v
```

### Test Categories
- **Unit Tests**: Individual component testing
- **Integration Tests**: Component interaction testing
- **Security Tests**: Vulnerability and threat testing
- **Performance Tests**: Load and stress testing
- **End-to-End Tests**: Complete workflow testing

## 🚀 Deployment

### Docker Deployment
```bash
# Build image
docker build -t codeguardian-ai:latest .

# Run container
docker run -d \
  --name codeguardian-ai \
  -p 5001:5001 \
  -e DATABASE_URL=postgresql://... \
  -e REDIS_URL=redis://... \
  codeguardian-ai:latest
```

### Kubernetes Deployment
```bash
# Apply configurations
kubectl apply -f infrastructure/kubernetes/

# Check deployment status
kubectl get pods -n codeguardian-ai

# View logs
kubectl logs -f deployment/codeguardian-ai -n codeguardian-ai
```

## 📋 Development Guidelines

### Code Standards
- **PEP 8** compliance for Python code
- **Type hints** for all function signatures
- **Docstrings** for all classes and functions
- **Error handling** with specific exception types
- **Security-first** development approach

### Security Guidelines
- **Input validation** for all user inputs
- **Output encoding** for all responses
- **Authentication** for all protected endpoints
- **Authorization** checks for all operations
- **Audit logging** for all security events

## 🔄 CI/CD Pipeline

### GitHub Actions Workflow
1. **Code Quality**: Linting, formatting, type checking
2. **Security Scanning**: Bandit, Safety, Semgrep
3. **Testing**: Unit, integration, security tests
4. **Build**: Docker image creation
5. **Deploy**: Staging and production deployment
6. **Monitoring**: Post-deployment health checks

## 📞 Support & Maintenance

### Monitoring Alerts
- **High error rate** (>5% over 5 minutes)
- **High response time** (P95 >500ms over 5 minutes)
- **Security events** (threat score >0.7)
- **System resources** (CPU >80%, Memory >90%)

### Maintenance Tasks
- **Log rotation** (daily)
- **Database maintenance** (weekly)
- **Security updates** (as needed)
- **Performance optimization** (monthly)

## 📜 License

Enterprise License - All Rights Reserved

## 🤝 Contributing

This is an enterprise product. For contribution guidelines, please contact the development team.

---

**CodeGuardian AI** - Autonomous DevSecOps Orchestration Platform
*Securing the future of software development*

