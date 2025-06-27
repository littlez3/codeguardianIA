"""
CodeGuardian AI - Authentication & Authorization System
Enterprise-grade JWT authentication with role-based access control
"""

import jwt
import bcrypt
import uuid
from datetime import datetime, timedelta, timezone
from functools import wraps
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum

from flask import request, jsonify, current_app
from flask_sqlalchemy import SQLAlchemy

# Import existing db instance
from src.models.user import db

class UserRole(Enum):
    """User roles for authorization"""
    ADMIN = "admin"
    DEVELOPER = "developer"
    ANALYST = "analyst"
    VIEWER = "viewer"

class TokenType(Enum):
    """Token types"""
    ACCESS = "access"
    REFRESH = "refresh"
    API_KEY = "api_key"

@dataclass
class AuthConfig:
    """Authentication configuration"""
    jwt_secret_key: str
    jwt_algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7
    api_key_expire_days: int = 365
    max_login_attempts: int = 5
    lockout_duration_minutes: int = 15

class AuthUser(db.Model):
    """Enhanced user model with authentication features"""
    __tablename__ = 'auth_users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.Enum(UserRole), nullable=False, default=UserRole.VIEWER)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    is_verified = db.Column(db.Boolean, default=False, nullable=False)
    
    # Security fields
    failed_login_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(45), nullable=True)  # IPv6 support
    
    # Audit fields
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('auth_users.id'), nullable=True)
    
    # Relationships
    api_keys = db.relationship('ApiKey', foreign_keys='ApiKey.user_id', back_populates='user', lazy='dynamic', cascade='all, delete-orphan')
    created_api_keys = db.relationship('ApiKey', foreign_keys='ApiKey.created_by', back_populates='creator', lazy='dynamic')
    refresh_tokens = db.relationship('RefreshToken', backref='user', lazy=True, cascade='all, delete-orphan')
    
    def __repr__(self):
        return f'<AuthUser {self.username}>'
    
    def set_password(self, password: str):
        """Hash and set password"""
        salt = bcrypt.gensalt()
        self.password_hash = bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')
    
    def check_password(self, password: str) -> bool:
        """Verify password"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def is_locked(self) -> bool:
        """Check if account is locked"""
        if self.locked_until is None:
            return False
        return datetime.utcnow() < self.locked_until
    
    def lock_account(self, duration_minutes: int = 15):
        """Lock account for specified duration"""
        self.locked_until = datetime.utcnow() + timedelta(minutes=duration_minutes)
        db.session.commit()
    
    def unlock_account(self):
        """Unlock account and reset failed attempts"""
        self.locked_until = None
        self.failed_login_attempts = 0
        db.session.commit()
    
    def increment_failed_login(self):
        """Increment failed login attempts"""
        self.failed_login_attempts += 1
        db.session.commit()
    
    def reset_failed_login(self):
        """Reset failed login attempts"""
        self.failed_login_attempts = 0
        db.session.commit()
    
    def update_last_login(self, ip_address: str):
        """Update last login timestamp and IP"""
        self.last_login = datetime.utcnow()
        self.last_login_ip = ip_address
        db.session.commit()
    
    def has_permission(self, required_role: UserRole) -> bool:
        """Check if user has required role or higher"""
        role_hierarchy = {
            UserRole.VIEWER: 1,
            UserRole.ANALYST: 2,
            UserRole.DEVELOPER: 3,
            UserRole.ADMIN: 4
        }
        return role_hierarchy.get(self.role, 0) >= role_hierarchy.get(required_role, 0)
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'role': self.role.value,
            'is_active': self.is_active,
            'is_verified': self.is_verified,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'created_at': self.created_at.isoformat(),
            'updated_at': self.updated_at.isoformat()
        }
        
        if include_sensitive:
            data.update({
                'failed_login_attempts': self.failed_login_attempts,
                'locked_until': self.locked_until.isoformat() if self.locked_until else None,
                'last_login_ip': self.last_login_ip
            })
        
        return data

class ApiKey(db.Model):
    """API Keys for programmatic access"""
    __tablename__ = 'api_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    key_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    key_hash = db.Column(db.String(128), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('auth_users.id'), nullable=False)
    
    # Permissions and limits
    scopes = db.Column(db.JSON, nullable=False, default=list)  # List of allowed endpoints
    rate_limit_per_minute = db.Column(db.Integer, default=60, nullable=False)
    
    # Status and expiry
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=True)
    last_used = db.Column(db.DateTime, nullable=True)
    last_used_ip = db.Column(db.String(45), nullable=True)
    
    # Audit
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('auth_users.id'), nullable=False)
    
    # Relationships
    user = db.relationship('AuthUser', foreign_keys=[user_id], back_populates='api_keys')
    creator = db.relationship('AuthUser', foreign_keys=[created_by], back_populates='created_api_keys')
    
    def __repr__(self):
        return f'<ApiKey {self.name}>'
    
    @staticmethod
    def generate_key() -> str:
        """Generate a new API key"""
        return f"cg_{uuid.uuid4().hex}"
    
    def set_key(self, key: str):
        """Hash and set API key"""
        salt = bcrypt.gensalt()
        self.key_hash = bcrypt.hashpw(key.encode('utf-8'), salt).decode('utf-8')
    
    def check_key(self, key: str) -> bool:
        """Verify API key"""
        return bcrypt.checkpw(key.encode('utf-8'), self.key_hash.encode('utf-8'))
    
    def is_expired(self) -> bool:
        """Check if API key is expired"""
        if self.expires_at is None:
            return False
        return datetime.utcnow() > self.expires_at
    
    def update_last_used(self, ip_address: str):
        """Update last used timestamp and IP"""
        self.last_used = datetime.utcnow()
        self.last_used_ip = ip_address
        db.session.commit()
    
    def has_scope(self, endpoint: str) -> bool:
        """Check if API key has access to endpoint"""
        if not self.scopes:
            return False
        return endpoint in self.scopes or '*' in self.scopes
    
    def to_dict(self, include_sensitive: bool = False) -> Dict[str, Any]:
        """Convert to dictionary"""
        data = {
            'id': self.id,
            'key_id': self.key_id,
            'name': self.name,
            'scopes': self.scopes,
            'rate_limit_per_minute': self.rate_limit_per_minute,
            'is_active': self.is_active,
            'expires_at': self.expires_at.isoformat() if self.expires_at else None,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'created_at': self.created_at.isoformat()
        }
        
        if include_sensitive:
            data.update({
                'last_used_ip': self.last_used_ip
            })
        
        return data

class RefreshToken(db.Model):
    """Refresh tokens for JWT authentication"""
    __tablename__ = 'refresh_tokens'
    
    id = db.Column(db.Integer, primary_key=True)
    token_id = db.Column(db.String(36), unique=True, nullable=False, default=lambda: str(uuid.uuid4()))
    user_id = db.Column(db.Integer, db.ForeignKey('auth_users.id'), nullable=False)
    
    # Token details
    expires_at = db.Column(db.DateTime, nullable=False)
    is_revoked = db.Column(db.Boolean, default=False, nullable=False)
    
    # Audit
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_used = db.Column(db.DateTime, nullable=True)
    created_ip = db.Column(db.String(45), nullable=True)
    last_used_ip = db.Column(db.String(45), nullable=True)
    
    def __repr__(self):
        return f'<RefreshToken {self.token_id}>'
    
    def is_expired(self) -> bool:
        """Check if refresh token is expired"""
        return datetime.utcnow() > self.expires_at
    
    def is_valid(self) -> bool:
        """Check if refresh token is valid"""
        return not self.is_revoked and not self.is_expired()
    
    def revoke(self):
        """Revoke refresh token"""
        self.is_revoked = True
        db.session.commit()
    
    def update_last_used(self, ip_address: str):
        """Update last used timestamp and IP"""
        self.last_used = datetime.utcnow()
        self.last_used_ip = ip_address
        db.session.commit()

class AuthService:
    """Authentication service"""
    
    def __init__(self, config: AuthConfig):
        self.config = config
    
    def create_user(self, username: str, email: str, password: str, 
                   role: UserRole = UserRole.VIEWER, created_by: int = None) -> AuthUser:
        """Create a new user"""
        # Check if user already exists
        if AuthUser.query.filter_by(username=username).first():
            raise ValueError("Username already exists")
        
        if AuthUser.query.filter_by(email=email).first():
            raise ValueError("Email already exists")
        
        user = AuthUser(
            username=username,
            email=email,
            role=role,
            created_by=created_by
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        return user
    
    def authenticate_user(self, username: str, password: str, ip_address: str) -> Optional[AuthUser]:
        """Authenticate user with username/password"""
        user = AuthUser.query.filter_by(username=username).first()
        
        if not user:
            return None
        
        # Check if account is locked
        if user.is_locked():
            raise ValueError("Account is temporarily locked due to too many failed login attempts")
        
        # Check if account is active
        if not user.is_active:
            raise ValueError("Account is disabled")
        
        # Verify password
        if not user.check_password(password):
            user.increment_failed_login()
            
            # Lock account if too many failed attempts
            if user.failed_login_attempts >= self.config.max_login_attempts:
                user.lock_account(self.config.lockout_duration_minutes)
                raise ValueError("Account locked due to too many failed login attempts")
            
            return None
        
        # Successful login
        user.reset_failed_login()
        user.update_last_login(ip_address)
        
        return user
    
    def authenticate_api_key(self, api_key: str, ip_address: str) -> Optional[AuthUser]:
        """Authenticate using API key"""
        # Extract key_id from API key format: cg_{key_id}_{secret}
        if not api_key.startswith('cg_'):
            return None
        
        try:
            parts = api_key.split('_', 2)
            if len(parts) != 3:
                return None
            
            key_id = parts[1]
            
            api_key_obj = ApiKey.query.filter_by(key_id=key_id).first()
            if not api_key_obj:
                return None
            
            # Check if API key is valid
            if not api_key_obj.is_active or api_key_obj.is_expired():
                return None
            
            # Verify API key
            if not api_key_obj.check_key(api_key):
                return None
            
            # Update last used
            api_key_obj.update_last_used(ip_address)
            
            return api_key_obj.user
            
        except Exception:
            return None
    
    def generate_tokens(self, user: AuthUser, ip_address: str) -> Dict[str, str]:
        """Generate access and refresh tokens"""
        now = datetime.now(timezone.utc)
        
        # Create refresh token
        refresh_token_obj = RefreshToken(
            user_id=user.id,
            expires_at=now + timedelta(days=self.config.refresh_token_expire_days),
            created_ip=ip_address
        )
        db.session.add(refresh_token_obj)
        db.session.commit()
        
        # Generate access token
        access_payload = {
            'user_id': user.id,
            'username': user.username,
            'role': user.role.value,
            'token_type': TokenType.ACCESS.value,
            'iat': now,
            'exp': now + timedelta(minutes=self.config.access_token_expire_minutes)
        }
        
        access_token = jwt.encode(
            access_payload,
            self.config.jwt_secret_key,
            algorithm=self.config.jwt_algorithm
        )
        
        # Generate refresh token JWT
        refresh_payload = {
            'token_id': refresh_token_obj.token_id,
            'user_id': user.id,
            'token_type': TokenType.REFRESH.value,
            'iat': now,
            'exp': refresh_token_obj.expires_at
        }
        
        refresh_token = jwt.encode(
            refresh_payload,
            self.config.jwt_secret_key,
            algorithm=self.config.jwt_algorithm
        )
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': self.config.access_token_expire_minutes * 60
        }
    
    def refresh_access_token(self, refresh_token: str, ip_address: str) -> Dict[str, str]:
        """Refresh access token using refresh token"""
        try:
            # Decode refresh token
            payload = jwt.decode(
                refresh_token,
                self.config.jwt_secret_key,
                algorithms=[self.config.jwt_algorithm]
            )
            
            if payload.get('token_type') != TokenType.REFRESH.value:
                raise ValueError("Invalid token type")
            
            # Find refresh token in database
            token_id = payload.get('token_id')
            refresh_token_obj = RefreshToken.query.filter_by(token_id=token_id).first()
            
            if not refresh_token_obj or not refresh_token_obj.is_valid():
                raise ValueError("Invalid or expired refresh token")
            
            # Update last used
            refresh_token_obj.update_last_used(ip_address)
            
            # Generate new access token
            user = refresh_token_obj.user
            now = datetime.now(timezone.utc)
            
            access_payload = {
                'user_id': user.id,
                'username': user.username,
                'role': user.role.value,
                'token_type': TokenType.ACCESS.value,
                'iat': now,
                'exp': now + timedelta(minutes=self.config.access_token_expire_minutes)
            }
            
            access_token = jwt.encode(
                access_payload,
                self.config.jwt_secret_key,
                algorithm=self.config.jwt_algorithm
            )
            
            return {
                'access_token': access_token,
                'token_type': 'Bearer',
                'expires_in': self.config.access_token_expire_minutes * 60
            }
            
        except jwt.InvalidTokenError:
            raise ValueError("Invalid refresh token")
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(
                token,
                self.config.jwt_secret_key,
                algorithms=[self.config.jwt_algorithm]
            )
            
            if payload.get('token_type') != TokenType.ACCESS.value:
                return None
            
            return payload
            
        except jwt.InvalidTokenError:
            return None
    
    def revoke_refresh_token(self, refresh_token: str):
        """Revoke a refresh token"""
        try:
            payload = jwt.decode(
                refresh_token,
                self.config.jwt_secret_key,
                algorithms=[self.config.jwt_algorithm]
            )
            
            token_id = payload.get('token_id')
            refresh_token_obj = RefreshToken.query.filter_by(token_id=token_id).first()
            
            if refresh_token_obj:
                refresh_token_obj.revoke()
                
        except jwt.InvalidTokenError:
            pass  # Token already invalid
    
    def revoke_all_user_tokens(self, user_id: int):
        """Revoke all refresh tokens for a user"""
        RefreshToken.query.filter_by(user_id=user_id).update({'is_revoked': True})
        db.session.commit()
    
    def create_api_key(self, user_id: int, name: str, scopes: List[str], 
                      created_by: int, expires_days: int = None) -> tuple[ApiKey, str]:
        """Create a new API key"""
        # Generate API key
        key = ApiKey.generate_key()
        
        # Set expiry
        expires_at = None
        if expires_days:
            expires_at = datetime.utcnow() + timedelta(days=expires_days)
        
        api_key_obj = ApiKey(
            name=name,
            user_id=user_id,
            scopes=scopes,
            expires_at=expires_at,
            created_by=created_by
        )
        api_key_obj.set_key(key)
        
        db.session.add(api_key_obj)
        db.session.commit()
        
        return api_key_obj, key

# Global auth service instance (will be initialized in main.py)
auth_service: Optional[AuthService] = None

def get_client_ip() -> str:
    """Get client IP address from request"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr or 'unknown'

def require_auth(required_role: UserRole = UserRole.VIEWER):
    """Decorator to require authentication and authorization"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            global auth_service
            
            if not auth_service:
                return jsonify({'error': 'Authentication service not initialized'}), 500
            
            # Get token from Authorization header or API key
            auth_header = request.headers.get('Authorization')
            api_key = request.headers.get('X-API-Key')
            
            user = None
            ip_address = get_client_ip()
            
            if auth_header and auth_header.startswith('Bearer '):
                # JWT token authentication
                token = auth_header.split(' ')[1]
                payload = auth_service.verify_token(token)
                
                if not payload:
                    return jsonify({'error': 'Invalid or expired token'}), 401
                
                user = AuthUser.query.get(payload['user_id'])
                
            elif api_key:
                # API key authentication
                user = auth_service.authenticate_api_key(api_key, ip_address)
                
                if not user:
                    return jsonify({'error': 'Invalid API key'}), 401
                
                # Check API key scope for this endpoint
                api_key_obj = ApiKey.query.filter_by(user_id=user.id).first()
                if api_key_obj and not api_key_obj.has_scope(request.endpoint):
                    return jsonify({'error': 'Insufficient API key permissions'}), 403
            
            else:
                return jsonify({'error': 'Authentication required'}), 401
            
            if not user or not user.is_active:
                return jsonify({'error': 'User not found or inactive'}), 401
            
            # Check role authorization
            if not user.has_permission(required_role):
                return jsonify({'error': 'Insufficient permissions'}), 403
            
            # Add user to request context
            request.current_user = user
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

def optional_auth():
    """Decorator for optional authentication (adds user to context if authenticated)"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            global auth_service
            
            request.current_user = None
            
            if not auth_service:
                return f(*args, **kwargs)
            
            # Get token from Authorization header or API key
            auth_header = request.headers.get('Authorization')
            api_key = request.headers.get('X-API-Key')
            
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                payload = auth_service.verify_token(token)
                
                if payload:
                    user = AuthUser.query.get(payload['user_id'])
                    if user and user.is_active:
                        request.current_user = user
            
            elif api_key:
                ip_address = get_client_ip()
                user = auth_service.authenticate_api_key(api_key, ip_address)
                if user and user.is_active:
                    request.current_user = user
            
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

