"""
CodeGuardian AI - Authentication Routes
API endpoints for authentication, user management, and API key management
"""

from flask import Blueprint, request, jsonify
from flask_cors import cross_origin
from datetime import datetime, timedelta
import os

from src.auth.authentication import (
    AuthService, AuthUser, ApiKey, UserRole, AuthConfig,
    require_auth, optional_auth, get_client_ip
)
from src.auth.rate_limiting import rate_limit, RateLimit, RateLimitStrategy

# Create blueprint for authentication routes
auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/register', methods=['POST'])
@cross_origin()
@rate_limit('auth', RateLimit(3, 300, RateLimitStrategy.SLIDING_WINDOW))  # 3 registrations per 5 minutes
def register():
    """Register a new user"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        username = data.get('username')
        email = data.get('email')
        password = data.get('password')
        
        if not all([username, email, password]):
            return jsonify({'error': 'Username, email, and password are required'}), 400
        
        # Validate password strength
        if len(password) < 8:
            return jsonify({'error': 'Password must be at least 8 characters long'}), 400
        
        # Create user
        try:
            import src.auth.authentication as auth_module
            user = auth_module.auth_service.create_user(username, email, password, UserRole.VIEWER)
            
            return jsonify({
                'message': 'User registered successfully',
                'user': user.to_dict()
            }), 201
            
        except ValueError as e:
            return jsonify({'error': str(e)}), 409
        
    except Exception as e:
        return jsonify({
            'error': 'Registration failed',
            'message': str(e)
        }), 500

@auth_bp.route('/login', methods=['POST'])
@cross_origin()
@rate_limit('auth', RateLimit(5, 300, RateLimitStrategy.SLIDING_WINDOW))  # 5 login attempts per 5 minutes
def login():
    """Authenticate user and return tokens"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        username = data.get('username')
        password = data.get('password')
        
        if not all([username, password]):
            return jsonify({'error': 'Username and password are required'}), 400
        
        ip_address = get_client_ip()
        
        try:
            import src.auth.authentication as auth_module
            user = auth_module.auth_service.authenticate_user(username, password, ip_address)
            
            if not user:
                return jsonify({'error': 'Invalid username or password'}), 401
            
            # Generate tokens
            tokens = auth_module.auth_service.generate_tokens(user, ip_address)
            
            return jsonify({
                'message': 'Login successful',
                'user': user.to_dict(),
                'tokens': tokens
            })
            
        except ValueError as e:
            return jsonify({'error': str(e)}), 401
        
    except Exception as e:
        return jsonify({
            'error': 'Login failed',
            'message': str(e)
        }), 500

@auth_bp.route('/refresh', methods=['POST'])
@cross_origin()
@rate_limit('auth', RateLimit(10, 300, RateLimitStrategy.SLIDING_WINDOW))  # 10 refresh attempts per 5 minutes
def refresh_token():
    """Refresh access token using refresh token"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        refresh_token = data.get('refresh_token')
        
        if not refresh_token:
            return jsonify({'error': 'Refresh token is required'}), 400
        
        ip_address = get_client_ip()
        
        try:
            import src.auth.authentication as auth_module
            tokens = auth_module.auth_service.refresh_access_token(refresh_token, ip_address)
            
            return jsonify({
                'message': 'Token refreshed successfully',
                'tokens': tokens
            })
            
        except ValueError as e:
            return jsonify({'error': str(e)}), 401
        
    except Exception as e:
        return jsonify({
            'error': 'Token refresh failed',
            'message': str(e)
        }), 500

@auth_bp.route('/logout', methods=['POST'])
@cross_origin()
@require_auth()
def logout():
    """Logout user and revoke refresh token"""
    try:
        data = request.get_json() or {}
        refresh_token = data.get('refresh_token')
        
        if refresh_token:
            import src.auth.authentication as auth_module
            auth_module.auth_service.revoke_refresh_token(refresh_token)
        
        return jsonify({'message': 'Logout successful'})
        
    except Exception as e:
        return jsonify({
            'error': 'Logout failed',
            'message': str(e)
        }), 500

@auth_bp.route('/logout-all', methods=['POST'])
@cross_origin()
@require_auth()
def logout_all():
    """Logout from all devices (revoke all refresh tokens)"""
    try:
        user = request.current_user
        import src.auth.authentication as auth_module
        auth_module.auth_service.revoke_all_user_tokens(user.id)
        
        return jsonify({'message': 'Logged out from all devices'})
        
    except Exception as e:
        return jsonify({
            'error': 'Logout all failed',
            'message': str(e)
        }), 500

@auth_bp.route('/profile', methods=['GET'])
@cross_origin()
@require_auth()
def get_profile():
    """Get current user profile"""
    try:
        user = request.current_user
        return jsonify({
            'user': user.to_dict(include_sensitive=True)
        })
        
    except Exception as e:
        return jsonify({
            'error': 'Failed to get profile',
            'message': str(e)
        }), 500

@auth_bp.route('/profile', methods=['PUT'])
@cross_origin()
@require_auth()
def update_profile():
    """Update current user profile"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        user = request.current_user
        
        # Update allowed fields
        if 'email' in data:
            # Check if email is already taken
            existing_user = AuthUser.query.filter_by(email=data['email']).first()
            if existing_user and existing_user.id != user.id:
                return jsonify({'error': 'Email already in use'}), 409
            user.email = data['email']
        
        # Only admins can change roles
        if 'role' in data and user.role == UserRole.ADMIN:
            try:
                new_role = UserRole(data['role'])
                user.role = new_role
            except ValueError:
                return jsonify({'error': 'Invalid role'}), 400
        
        user.updated_at = datetime.utcnow()
        
        from src.models.user import db
        db.session.commit()
        
        return jsonify({
            'message': 'Profile updated successfully',
            'user': user.to_dict()
        })
        
    except Exception as e:
        from src.models.user import db
        db.session.rollback()
        return jsonify({
            'error': 'Profile update failed',
            'message': str(e)
        }), 500

@auth_bp.route('/change-password', methods=['POST'])
@cross_origin()
@require_auth()
@rate_limit('auth', RateLimit(3, 300, RateLimitStrategy.SLIDING_WINDOW))  # 3 password changes per 5 minutes
def change_password():
    """Change user password"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        current_password = data.get('current_password')
        new_password = data.get('new_password')
        
        if not all([current_password, new_password]):
            return jsonify({'error': 'Current password and new password are required'}), 400
        
        user = request.current_user
        
        # Verify current password
        if not user.check_password(current_password):
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        # Validate new password
        if len(new_password) < 8:
            return jsonify({'error': 'New password must be at least 8 characters long'}), 400
        
        # Set new password
        user.set_password(new_password)
        user.updated_at = datetime.utcnow()
        
        from src.models.user import db
        db.session.commit()
        
        # Revoke all refresh tokens to force re-login
        import src.auth.authentication as auth_module
        auth_module.auth_service.revoke_all_user_tokens(user.id)
        
        return jsonify({'message': 'Password changed successfully'})
        
    except Exception as e:
        from src.models.user import db
        db.session.rollback()
        return jsonify({
            'error': 'Password change failed',
            'message': str(e)
        }), 500

# API Key Management Routes

@auth_bp.route('/api-keys', methods=['GET'])
@cross_origin()
@require_auth(UserRole.DEVELOPER)
def list_api_keys():
    """List user's API keys"""
    try:
        user = request.current_user
        api_keys = ApiKey.query.filter_by(user_id=user.id).all()
        
        return jsonify({
            'api_keys': [key.to_dict() for key in api_keys]
        })
        
    except Exception as e:
        return jsonify({
            'error': 'Failed to list API keys',
            'message': str(e)
        }), 500

@auth_bp.route('/api-keys', methods=['POST'])
@cross_origin()
@require_auth(UserRole.DEVELOPER)
@rate_limit('auth', RateLimit(5, 3600, RateLimitStrategy.SLIDING_WINDOW))  # 5 API key creations per hour
def create_api_key():
    """Create a new API key"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        name = data.get('name')
        scopes = data.get('scopes', ['*'])  # Default to all scopes
        expires_days = data.get('expires_days', 365)
        
        if not name:
            return jsonify({'error': 'API key name is required'}), 400
        
        user = request.current_user
        
        # Create API key
        import src.auth.authentication as auth_module
        api_key_obj, api_key = auth_module.auth_service.create_api_key(
            user.id, name, scopes, user.id, expires_days
        )
        
        return jsonify({
            'message': 'API key created successfully',
            'api_key': {
                'id': api_key_obj.id,
                'key': api_key,  # Only returned once
                'name': api_key_obj.name,
                'scopes': api_key_obj.scopes,
                'expires_at': api_key_obj.expires_at.isoformat() if api_key_obj.expires_at else None
            }
        }), 201
        
    except Exception as e:
        return jsonify({
            'error': 'API key creation failed',
            'message': str(e)
        }), 500

@auth_bp.route('/api-keys/<int:key_id>', methods=['DELETE'])
@cross_origin()
@require_auth(UserRole.DEVELOPER)
def delete_api_key(key_id):
    """Delete an API key"""
    try:
        user = request.current_user
        
        api_key = ApiKey.query.filter_by(id=key_id, user_id=user.id).first()
        
        if not api_key:
            return jsonify({'error': 'API key not found'}), 404
        
        from src.models.user import db
        db.session.delete(api_key)
        db.session.commit()
        
        return jsonify({'message': 'API key deleted successfully'})
        
    except Exception as e:
        from src.models.user import db
        db.session.rollback()
        return jsonify({
            'error': 'API key deletion failed',
            'message': str(e)
        }), 500

@auth_bp.route('/api-keys/<int:key_id>', methods=['PUT'])
@cross_origin()
@require_auth(UserRole.DEVELOPER)
def update_api_key(key_id):
    """Update an API key"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        user = request.current_user
        
        api_key = ApiKey.query.filter_by(id=key_id, user_id=user.id).first()
        
        if not api_key:
            return jsonify({'error': 'API key not found'}), 404
        
        # Update allowed fields
        if 'name' in data:
            api_key.name = data['name']
        
        if 'scopes' in data:
            api_key.scopes = data['scopes']
        
        if 'is_active' in data:
            api_key.is_active = data['is_active']
        
        if 'rate_limit_per_minute' in data:
            api_key.rate_limit_per_minute = data['rate_limit_per_minute']
        
        from src.models.user import db
        db.session.commit()
        
        return jsonify({
            'message': 'API key updated successfully',
            'api_key': api_key.to_dict()
        })
        
    except Exception as e:
        from src.models.user import db
        db.session.rollback()
        return jsonify({
            'error': 'API key update failed',
            'message': str(e)
        }), 500

# Admin Routes

@auth_bp.route('/admin/users', methods=['GET'])
@cross_origin()
@require_auth(UserRole.ADMIN)
def admin_list_users():
    """List all users (admin only)"""
    try:
        page = request.args.get('page', 1, type=int)
        per_page = request.args.get('per_page', 20, type=int)
        
        users = AuthUser.query.paginate(
            page=page, per_page=per_page, error_out=False
        )
        
        return jsonify({
            'users': [user.to_dict(include_sensitive=True) for user in users.items],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': users.total,
                'pages': users.pages,
                'has_next': users.has_next,
                'has_prev': users.has_prev
            }
        })
        
    except Exception as e:
        return jsonify({
            'error': 'Failed to list users',
            'message': str(e)
        }), 500

@auth_bp.route('/admin/users/<int:user_id>', methods=['PUT'])
@cross_origin()
@require_auth(UserRole.ADMIN)
def admin_update_user(user_id):
    """Update user (admin only)"""
    try:
        data = request.get_json()
        
        if not data:
            return jsonify({'error': 'No JSON data provided'}), 400
        
        user = AuthUser.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        # Update allowed fields
        if 'role' in data:
            try:
                new_role = UserRole(data['role'])
                user.role = new_role
            except ValueError:
                return jsonify({'error': 'Invalid role'}), 400
        
        if 'is_active' in data:
            user.is_active = data['is_active']
        
        if 'is_verified' in data:
            user.is_verified = data['is_verified']
        
        user.updated_at = datetime.utcnow()
        
        from src.models.user import db
        db.session.commit()
        
        return jsonify({
            'message': 'User updated successfully',
            'user': user.to_dict(include_sensitive=True)
        })
        
    except Exception as e:
        from src.models.user import db
        db.session.rollback()
        return jsonify({
            'error': 'User update failed',
            'message': str(e)
        }), 500

@auth_bp.route('/admin/users/<int:user_id>/unlock', methods=['POST'])
@cross_origin()
@require_auth(UserRole.ADMIN)
def admin_unlock_user(user_id):
    """Unlock user account (admin only)"""
    try:
        user = AuthUser.query.get(user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        user.unlock_account()
        
        return jsonify({'message': 'User account unlocked successfully'})
        
    except Exception as e:
        return jsonify({
            'error': 'Failed to unlock user account',
            'message': str(e)
        }), 500

# Health check for authentication system
@auth_bp.route('/health', methods=['GET'])
@cross_origin()
def auth_health():
    """Authentication system health check"""
    try:
        # Check database connectivity
        user_count = AuthUser.query.count()
        
        return jsonify({
            'status': 'healthy',
            'timestamp': datetime.utcnow().isoformat(),
            'stats': {
                'total_users': user_count,
                'auth_service_initialized': True  # Always true since we're using it
            }
        })
        
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'error': str(e),
            'timestamp': datetime.utcnow().isoformat()
        }), 500

