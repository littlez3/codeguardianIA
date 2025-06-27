"""
CodeGuardian AI - Rate Limiting System
Advanced rate limiting with multiple strategies and Redis support
"""

import time
import json
import hashlib
from typing import Dict, Any, Optional, Callable
from dataclasses import dataclass
from enum import Enum
from collections import defaultdict, deque
from threading import Lock

from flask import request, jsonify, current_app
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

class RateLimitStrategy(Enum):
    """Rate limiting strategies"""
    FIXED_WINDOW = "fixed_window"
    SLIDING_WINDOW = "sliding_window"
    TOKEN_BUCKET = "token_bucket"
    LEAKY_BUCKET = "leaky_bucket"

@dataclass
class RateLimit:
    """Rate limit configuration"""
    requests: int
    window_seconds: int
    strategy: RateLimitStrategy = RateLimitStrategy.SLIDING_WINDOW
    burst_requests: Optional[int] = None  # For token bucket
    key_func: Optional[Callable] = None

class InMemoryRateLimiter:
    """In-memory rate limiter with multiple strategies"""
    
    def __init__(self):
        self.windows = defaultdict(dict)  # {key: {window_start: count}}
        self.sliding_windows = defaultdict(deque)  # {key: deque of timestamps}
        self.token_buckets = defaultdict(dict)  # {key: {tokens: int, last_refill: float}}
        self.leaky_buckets = defaultdict(dict)  # {key: {queue: deque, last_leak: float}}
        self.lock = Lock()
    
    def is_allowed(self, key: str, rate_limit: RateLimit) -> tuple[bool, Dict[str, Any]]:
        """Check if request is allowed under rate limit"""
        with self.lock:
            if rate_limit.strategy == RateLimitStrategy.FIXED_WINDOW:
                return self._fixed_window_check(key, rate_limit)
            elif rate_limit.strategy == RateLimitStrategy.SLIDING_WINDOW:
                return self._sliding_window_check(key, rate_limit)
            elif rate_limit.strategy == RateLimitStrategy.TOKEN_BUCKET:
                return self._token_bucket_check(key, rate_limit)
            elif rate_limit.strategy == RateLimitStrategy.LEAKY_BUCKET:
                return self._leaky_bucket_check(key, rate_limit)
            else:
                return True, {}
    
    def _fixed_window_check(self, key: str, rate_limit: RateLimit) -> tuple[bool, Dict[str, Any]]:
        """Fixed window rate limiting"""
        now = time.time()
        window_start = int(now // rate_limit.window_seconds) * rate_limit.window_seconds
        
        if key not in self.windows:
            self.windows[key] = {}
        
        # Clean old windows
        old_windows = [w for w in self.windows[key].keys() if w < window_start]
        for w in old_windows:
            del self.windows[key][w]
        
        current_count = self.windows[key].get(window_start, 0)
        
        if current_count >= rate_limit.requests:
            return False, {
                'limit': rate_limit.requests,
                'remaining': 0,
                'reset_time': window_start + rate_limit.window_seconds,
                'retry_after': (window_start + rate_limit.window_seconds) - now
            }
        
        self.windows[key][window_start] = current_count + 1
        
        return True, {
            'limit': rate_limit.requests,
            'remaining': rate_limit.requests - (current_count + 1),
            'reset_time': window_start + rate_limit.window_seconds,
            'retry_after': 0
        }
    
    def _sliding_window_check(self, key: str, rate_limit: RateLimit) -> tuple[bool, Dict[str, Any]]:
        """Sliding window rate limiting"""
        now = time.time()
        window_start = now - rate_limit.window_seconds
        
        if key not in self.sliding_windows:
            self.sliding_windows[key] = deque()
        
        # Remove old requests
        while self.sliding_windows[key] and self.sliding_windows[key][0] <= window_start:
            self.sliding_windows[key].popleft()
        
        current_count = len(self.sliding_windows[key])
        
        if current_count >= rate_limit.requests:
            oldest_request = self.sliding_windows[key][0]
            retry_after = oldest_request + rate_limit.window_seconds - now
            
            return False, {
                'limit': rate_limit.requests,
                'remaining': 0,
                'reset_time': oldest_request + rate_limit.window_seconds,
                'retry_after': max(0, retry_after)
            }
        
        self.sliding_windows[key].append(now)
        
        return True, {
            'limit': rate_limit.requests,
            'remaining': rate_limit.requests - (current_count + 1),
            'reset_time': now + rate_limit.window_seconds,
            'retry_after': 0
        }
    
    def _token_bucket_check(self, key: str, rate_limit: RateLimit) -> tuple[bool, Dict[str, Any]]:
        """Token bucket rate limiting"""
        now = time.time()
        
        if key not in self.token_buckets:
            self.token_buckets[key] = {
                'tokens': rate_limit.burst_requests or rate_limit.requests,
                'last_refill': now
            }
        
        bucket = self.token_buckets[key]
        
        # Refill tokens
        time_passed = now - bucket['last_refill']
        tokens_to_add = time_passed * (rate_limit.requests / rate_limit.window_seconds)
        bucket['tokens'] = min(
            rate_limit.burst_requests or rate_limit.requests,
            bucket['tokens'] + tokens_to_add
        )
        bucket['last_refill'] = now
        
        if bucket['tokens'] < 1:
            retry_after = (1 - bucket['tokens']) / (rate_limit.requests / rate_limit.window_seconds)
            return False, {
                'limit': rate_limit.requests,
                'remaining': 0,
                'retry_after': retry_after
            }
        
        bucket['tokens'] -= 1
        
        return True, {
            'limit': rate_limit.requests,
            'remaining': int(bucket['tokens']),
            'retry_after': 0
        }
    
    def _leaky_bucket_check(self, key: str, rate_limit: RateLimit) -> tuple[bool, Dict[str, Any]]:
        """Leaky bucket rate limiting"""
        now = time.time()
        
        if key not in self.leaky_buckets:
            self.leaky_buckets[key] = {
                'queue': deque(),
                'last_leak': now
            }
        
        bucket = self.leaky_buckets[key]
        
        # Leak requests
        time_passed = now - bucket['last_leak']
        requests_to_leak = time_passed * (rate_limit.requests / rate_limit.window_seconds)
        
        for _ in range(int(requests_to_leak)):
            if bucket['queue']:
                bucket['queue'].popleft()
        
        bucket['last_leak'] = now
        
        if len(bucket['queue']) >= rate_limit.requests:
            return False, {
                'limit': rate_limit.requests,
                'remaining': 0,
                'retry_after': rate_limit.window_seconds / rate_limit.requests
            }
        
        bucket['queue'].append(now)
        
        return True, {
            'limit': rate_limit.requests,
            'remaining': rate_limit.requests - len(bucket['queue']),
            'retry_after': 0
        }

class RateLimitManager:
    """Rate limit manager with multiple limiters"""
    
    def __init__(self, use_redis: bool = False, redis_url: str = None):
        self.use_redis = use_redis
        self.in_memory_limiter = InMemoryRateLimiter()
        
        # Flask-Limiter for Redis-backed rate limiting
        if use_redis:
            self.flask_limiter = Limiter(
                key_func=get_remote_address,
                storage_uri=redis_url or "redis://localhost:6379"
            )
        else:
            self.flask_limiter = None
        
        # Rate limit configurations
        self.rate_limits = {
            'default': RateLimit(100, 3600),  # 100 requests per hour
            'auth': RateLimit(5, 300),        # 5 auth attempts per 5 minutes
            'execute': RateLimit(10, 60),     # 10 code executions per minute
            'analyze': RateLimit(20, 60),     # 20 security analyses per minute
            'api_key': RateLimit(1000, 3600), # 1000 requests per hour for API keys
        }
    
    def get_rate_limit_key(self, identifier: str, endpoint: str, user_id: Optional[int] = None) -> str:
        """Generate rate limit key"""
        if user_id:
            return f"user:{user_id}:{endpoint}"
        else:
            return f"ip:{identifier}:{endpoint}"
    
    def check_rate_limit(self, identifier: str, endpoint: str, 
                        user_id: Optional[int] = None, 
                        custom_limit: Optional[RateLimit] = None) -> tuple[bool, Dict[str, Any]]:
        """Check rate limit for request"""
        rate_limit = custom_limit or self.rate_limits.get(endpoint, self.rate_limits['default'])
        key = self.get_rate_limit_key(identifier, endpoint, user_id)
        
        return self.in_memory_limiter.is_allowed(key, rate_limit)
    
    def add_rate_limit(self, name: str, rate_limit: RateLimit):
        """Add custom rate limit configuration"""
        self.rate_limits[name] = rate_limit

# Global rate limit manager
rate_limit_manager: Optional[RateLimitManager] = None

def get_rate_limit_identifier() -> str:
    """Get identifier for rate limiting (IP address or user ID)"""
    # Try to get user ID from request context
    if hasattr(request, 'current_user') and request.current_user:
        return f"user:{request.current_user.id}"
    
    # Fall back to IP address
    if request.headers.get('X-Forwarded-For'):
        ip = request.headers.get('X-Forwarded-For').split(',')[0].strip()
    elif request.headers.get('X-Real-IP'):
        ip = request.headers.get('X-Real-IP')
    else:
        ip = request.remote_addr or 'unknown'
    
    return f"ip:{ip}"

def rate_limit(endpoint: str = None, custom_limit: RateLimit = None):
    """Decorator for rate limiting endpoints"""
    def decorator(f):
        from functools import wraps
        
        @wraps(f)
        def decorated_function(*args, **kwargs):
            global rate_limit_manager
            
            if not rate_limit_manager:
                # Rate limiting not configured, allow request
                return f(*args, **kwargs)
            
            endpoint_name = endpoint or request.endpoint or f.__name__
            identifier = get_rate_limit_identifier()
            user_id = getattr(request, 'current_user', None)
            user_id = user_id.id if user_id else None
            
            allowed, info = rate_limit_manager.check_rate_limit(
                identifier, endpoint_name, user_id, custom_limit
            )
            
            if not allowed:
                response = jsonify({
                    'error': 'Rate limit exceeded',
                    'message': f'Too many requests. Try again in {info.get("retry_after", 0):.1f} seconds.',
                    'rate_limit': {
                        'limit': info.get('limit'),
                        'remaining': info.get('remaining', 0),
                        'reset_time': info.get('reset_time'),
                        'retry_after': info.get('retry_after', 0)
                    }
                })
                response.status_code = 429
                
                # Add rate limit headers
                response.headers['X-RateLimit-Limit'] = str(info.get('limit', 0))
                response.headers['X-RateLimit-Remaining'] = str(info.get('remaining', 0))
                response.headers['X-RateLimit-Reset'] = str(int(info.get('reset_time', 0)))
                response.headers['Retry-After'] = str(int(info.get('retry_after', 0)))
                
                return response
            
            # Add rate limit headers to successful responses
            response = f(*args, **kwargs)
            
            if hasattr(response, 'headers'):
                response.headers['X-RateLimit-Limit'] = str(info.get('limit', 0))
                response.headers['X-RateLimit-Remaining'] = str(info.get('remaining', 0))
                if 'reset_time' in info:
                    response.headers['X-RateLimit-Reset'] = str(int(info['reset_time']))
            
            return response
        
        return decorated_function
    return decorator

def init_rate_limiting(app, use_redis: bool = False, redis_url: str = None):
    """Initialize rate limiting for Flask app"""
    global rate_limit_manager
    
    rate_limit_manager = RateLimitManager(use_redis, redis_url)
    
    if rate_limit_manager.flask_limiter:
        rate_limit_manager.flask_limiter.init_app(app)
    
    return rate_limit_manager

