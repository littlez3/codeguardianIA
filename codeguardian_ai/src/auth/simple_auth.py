"""
CodeGuardian AI - Simplified Authentication System
Simplified version without ambiguous relationships for MVP
"""

import os
import jwt
import bcrypt
import uuid
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from enum import Enum
from flask import request, jsonify, g
from functools import wraps
from dataclasses import dataclass

# Simple in-memory storage for MVP (replace with proper DB later)
users_db = {}
api_keys_db = {}
refresh_tokens_db = {}

class UserRole(Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    DEVELOPER = "developer"
    ADMIN = "admin"

@dataclass
class SimpleUser:
    id: str
    username: str
    email: str
    password_hash: str
    role: UserRole
    is_active: bool = True
    failed_login_attempts: int = 0
    last_login: Optional[datetime] = None
    created_at: datetime = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()
    
    def check_password(self, password: str) -> bool:
        """Check if password is correct"""
        return bcrypt.checkpw(password.encode('utf-8'), self.password_hash.encode('utf-8'))
    
    def has_permission(self, required_role: UserRole) -> bool:
        """Check if user has required role or higher"""
        role_hierarchy = {
            UserRole.VIEWER: 1,
            UserRole.ANALYST: 2,
            UserRole.DEVELOPER: 3,
            UserRole.ADMIN: 4
        }
        return role_hierarchy.get(self.role, 0) >= role_hierarchy.get(required_role, 0)

class SimpleAuthService:
    def __init__(self):
        self.jwt_secret = os.getenv('JWT_SECRET_KEY', 'dev-secret-key-change-in-production')
        self.jwt_algorithm = 'HS256'
        self.access_token_expires = timedelta(hours=1)
        self.refresh_token_expires = timedelta(days=30)
        
        # Create default admin user
        self._create_default_admin()
    
    def _create_default_admin(self):
        """Create default admin user if not exists"""
        admin_id = "admin-001"
        if admin_id not in users_db:
            password_hash = bcrypt.hashpw("admin123-change-this".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
            admin_user = SimpleUser(
                id=admin_id,
                username="admin",
                email="admin@codeguardian.ai",
                password_hash=password_hash,
                role=UserRole.ADMIN
            )
            users_db[admin_id] = admin_user
    
    def authenticate_user(self, username: str, password: str, ip_address: str) -> Optional[SimpleUser]:
        """Authenticate user with username and password"""
        # Find user by username
        user = None
        for u in users_db.values():
            if u.username == username:
                user = u
                break
        
        if not user or not user.is_active:
            return None
        
        # Check password
        if not user.check_password(password):
            user.failed_login_attempts += 1
            return None
        
        # Reset failed attempts and update last login
        user.failed_login_attempts = 0
        user.last_login = datetime.utcnow()
        
        return user
    
    def generate_tokens(self, user: SimpleUser, ip_address: str) -> Dict[str, Any]:
        """Generate access and refresh tokens"""
        now = datetime.utcnow()
        
        # Access token payload
        access_payload = {
            'user_id': user.id,
            'username': user.username,
            'role': user.role.value,
            'iat': now,
            'exp': now + self.access_token_expires,
            'type': 'access'
        }
        
        # Refresh token payload
        refresh_payload = {
            'user_id': user.id,
            'iat': now,
            'exp': now + self.refresh_token_expires,
            'type': 'refresh',
            'jti': str(uuid.uuid4())
        }
        
        # Generate tokens
        access_token = jwt.encode(access_payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        refresh_token = jwt.encode(refresh_payload, self.jwt_secret, algorithm=self.jwt_algorithm)
        
        # Store refresh token
        refresh_tokens_db[refresh_payload['jti']] = {
            'user_id': user.id,
            'ip_address': ip_address,
            'created_at': now,
            'expires_at': now + self.refresh_token_expires,
            'is_active': True
        }
        
        return {
            'access_token': access_token,
            'refresh_token': refresh_token,
            'token_type': 'Bearer',
            'expires_in': int(self.access_token_expires.total_seconds()),
            'user': {
                'id': user.id,
                'username': user.username,
                'role': user.role.value
            }
        }
    
    def verify_token(self, token: str) -> Optional[Dict[str, Any]]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=[self.jwt_algorithm])
            return payload
        except jwt.ExpiredSignatureError:
            return None
        except jwt.InvalidTokenError:
            return None
    
    def get_user_by_id(self, user_id: str) -> Optional[SimpleUser]:
        """Get user by ID"""
        return users_db.get(user_id)

# Global auth service instance
auth_service = SimpleAuthService()

def get_client_ip():
    """Get client IP address"""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        return request.headers.get('X-Real-IP')
    else:
        return request.remote_addr

def require_auth():
    """Decorator to require authentication"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            if not auth_header or not auth_header.startswith('Bearer '):
                return jsonify({'error': 'Authentication required'}), 401
            
            token = auth_header.split(' ')[1]
            payload = auth_service.verify_token(token)
            
            if not payload or payload.get('type') != 'access':
                return jsonify({'error': 'Invalid or expired token'}), 401
            
            user = auth_service.get_user_by_id(payload['user_id'])
            if not user or not user.is_active:
                return jsonify({'error': 'User not found or inactive'}), 401
            
            # Add user to request context
            request.current_user = user
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def optional_auth():
    """Decorator for optional authentication"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            auth_header = request.headers.get('Authorization')
            request.current_user = None
            
            if auth_header and auth_header.startswith('Bearer '):
                token = auth_header.split(' ')[1]
                payload = auth_service.verify_token(token)
                
                if payload and payload.get('type') == 'access':
                    user = auth_service.get_user_by_id(payload['user_id'])
                    if user and user.is_active:
                        request.current_user = user
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator

