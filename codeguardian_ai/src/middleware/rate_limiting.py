"""
CodeGuardian AI - Enterprise Rate Limiting System
Advanced rate limiting with adaptive algorithms, distributed coordination, and intelligent threat detection
"""

import time
import math
import json
import hashlib
from typing import Dict, Any, Optional, List, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime, timezone, timedelta
from collections import defaultdict, deque
import threading
import redis
from flask import request, current_app, g
import logging

from src.audit.audit_system import get_audit_manager, EventType, LogLevel, SecurityLevel

class RateLimitAlgorithm(Enum):
    """Rate limiting algorithms"""
    TOKEN_BUCKET = "token_bucket"
    SLIDING_WINDOW = "sliding_window"
    FIXED_WINDOW = "fixed_window"
    ADAPTIVE = "adaptive"

class RateLimitScope(Enum):
    """Rate limit scope levels"""
    GLOBAL = "global"
    IP = "ip"
    USER = "user"
    API_KEY = "api_key"
    ENDPOINT = "endpoint"

@dataclass
class RateLimitRule:
    """Rate limiting rule configuration"""
    name: str
    algorithm: RateLimitAlgorithm
    scope: RateLimitScope
    limit: int
    window_seconds: int
    burst_limit: Optional[int] = None
    priority: int = 1
    enabled: bool = True
    endpoints: List[str] = field(default_factory=list)
    methods: List[str] = field(default_factory=lambda: ["GET", "POST", "PUT", "DELETE"])
    
    def __post_init__(self):
        if self.burst_limit is None:
            self.burst_limit = self.limit * 2

@dataclass
class RateLimitResult:
    """Rate limit check result"""
    allowed: bool
    remaining: int
    reset_time: datetime
    retry_after: Optional[int] = None
    rule_name: Optional[str] = None
    current_usage: int = 0

class TokenBucket:
    """Token bucket algorithm implementation"""
    
    def __init__(self, capacity: int, refill_rate: float, initial_tokens: Optional[int] = None):
        self.capacity = capacity
        self.refill_rate = refill_rate  # tokens per second
        self.tokens = initial_tokens if initial_tokens is not None else capacity
        self.last_refill = time.time()
        self._lock = threading.Lock()
    
    def consume(self, tokens: int = 1) -> bool:
        """Attempt to consume tokens from bucket"""
        with self._lock:
            now = time.time()
            
            # Refill tokens based on elapsed time
            elapsed = now - self.last_refill
            self.tokens = min(self.capacity, self.tokens + elapsed * self.refill_rate)
            self.last_refill = now
            
            if self.tokens >= tokens:
                self.tokens -= tokens
                return True
            
            return False
    
    def get_state(self) -> Dict[str, Any]:
        """Get current bucket state"""
        with self._lock:
            return {
                "tokens": self.tokens,
                "capacity": self.capacity,
                "refill_rate": self.refill_rate,
                "last_refill": self.last_refill
            }

class SlidingWindowCounter:
    """Sliding window counter implementation"""
    
    def __init__(self, window_seconds: int, precision_seconds: int = 1):
        self.window_seconds = window_seconds
        self.precision_seconds = precision_seconds
        self.buckets = deque()
        self._lock = threading.Lock()
    
    def add_request(self, timestamp: Optional[float] = None) -> int:
        """Add a request and return current count"""
        if timestamp is None:
            timestamp = time.time()
        
        with self._lock:
            # Remove old buckets
            cutoff = timestamp - self.window_seconds
            while self.buckets and self.buckets[0][0] < cutoff:
                self.buckets.popleft()
            
            # Add current request
            bucket_time = timestamp // self.precision_seconds * self.precision_seconds
            
            if self.buckets and self.buckets[-1][0] == bucket_time:
                self.buckets[-1] = (bucket_time, self.buckets[-1][1] + 1)
            else:
                self.buckets.append((bucket_time, 1))
            
            # Return total count
            return sum(count for _, count in self.buckets)

class AdaptiveRateLimiter:
    """Adaptive rate limiter that adjusts based on system load and threat detection"""
    
    def __init__(self, base_limit: int, window_seconds: int):
        self.base_limit = base_limit
        self.window_seconds = window_seconds
        self.current_multiplier = 1.0
        self.threat_score = 0.0
        self.system_load = 0.0
        self.request_history = deque(maxlen=1000)
        self._lock = threading.Lock()
    
    def update_system_metrics(self, cpu_usage: float, memory_usage: float, response_time: float):
        """Update system metrics for adaptive adjustment"""
        with self._lock:
            # Calculate system load score (0.0 to 1.0)
            self.system_load = (cpu_usage + memory_usage + min(response_time / 1000, 1.0)) / 3.0
            
            # Adjust multiplier based on system load
            if self.system_load > 0.8:
                self.current_multiplier = max(0.1, self.current_multiplier * 0.9)
            elif self.system_load < 0.3:
                self.current_multiplier = min(2.0, self.current_multiplier * 1.1)
    
    def update_threat_score(self, suspicious_activity: bool, malicious_patterns: int):
        """Update threat score based on security events"""
        with self._lock:
            if suspicious_activity:
                self.threat_score = min(1.0, self.threat_score + 0.1)
            else:
                self.threat_score = max(0.0, self.threat_score - 0.01)
            
            # Add malicious pattern penalty
            self.threat_score = min(1.0, self.threat_score + malicious_patterns * 0.05)
            
            # Adjust multiplier based on threat score
            if self.threat_score > 0.7:
                self.current_multiplier = max(0.05, self.current_multiplier * 0.8)
    
    def get_current_limit(self) -> int:
        """Get current adaptive limit"""
        with self._lock:
            adaptive_limit = int(self.base_limit * self.current_multiplier)
            return max(1, adaptive_limit)

class EnterpriseRateLimiter:
    """Enterprise-grade rate limiter with multiple algorithms and distributed coordination"""
    
    def __init__(self, redis_client: Optional[redis.Redis] = None):
        self.redis_client = redis_client
        self.local_buckets: Dict[str, TokenBucket] = {}
        self.local_counters: Dict[str, SlidingWindowCounter] = {}
        self.adaptive_limiters: Dict[str, AdaptiveRateLimiter] = {}
        self.rules: List[RateLimitRule] = []
        self.audit_manager = get_audit_manager()
        self._lock = threading.Lock()
        
        # Default rules
        self._setup_default_rules()
    
    def _setup_default_rules(self):
        """Setup default rate limiting rules"""
        default_rules = [
            # Global rate limits
            RateLimitRule(
                name="global_requests",
                algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
                scope=RateLimitScope.GLOBAL,
                limit=10000,
                window_seconds=60,
                priority=1
            ),
            
            # IP-based limits
            RateLimitRule(
                name="ip_requests_per_minute",
                algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
                scope=RateLimitScope.IP,
                limit=100,
                window_seconds=60,
                burst_limit=150,
                priority=2
            ),
            
            RateLimitRule(
                name="ip_requests_per_hour",
                algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
                scope=RateLimitScope.IP,
                limit=1000,
                window_seconds=3600,
                priority=2
            ),
            
            # Authentication endpoints (stricter)
            RateLimitRule(
                name="auth_attempts",
                algorithm=RateLimitAlgorithm.FIXED_WINDOW,
                scope=RateLimitScope.IP,
                limit=5,
                window_seconds=300,  # 5 minutes
                endpoints=["/api/auth/login", "/api/auth/register"],
                priority=3
            ),
            
            # API endpoints
            RateLimitRule(
                name="api_requests",
                algorithm=RateLimitAlgorithm.ADAPTIVE,
                scope=RateLimitScope.USER,
                limit=500,
                window_seconds=60,
                endpoints=["/api/analyze", "/api/execute"],
                priority=2
            ),
            
            # Admin endpoints (very strict)
            RateLimitRule(
                name="admin_requests",
                algorithm=RateLimitAlgorithm.TOKEN_BUCKET,
                scope=RateLimitScope.USER,
                limit=10,
                window_seconds=60,
                endpoints=["/api/admin/*"],
                priority=4
            )
        ]
        
        self.rules.extend(default_rules)
    
    def add_rule(self, rule: RateLimitRule):
        """Add a new rate limiting rule"""
        with self._lock:
            self.rules.append(rule)
            # Sort by priority (higher priority first)
            self.rules.sort(key=lambda r: r.priority, reverse=True)
    
    def check_rate_limit(self, identifier: str, endpoint: str, method: str) -> RateLimitResult:
        """Check if request is within rate limits"""
        
        # Find applicable rules
        applicable_rules = self._get_applicable_rules(endpoint, method)
        
        for rule in applicable_rules:
            if not rule.enabled:
                continue
            
            # Generate key for this rule and identifier
            key = self._generate_key(rule, identifier, endpoint)
            
            # Check rate limit based on algorithm
            result = self._check_rule(rule, key, identifier)
            
            if not result.allowed:
                # Log rate limit violation
                self._log_rate_limit_violation(rule, identifier, endpoint, result)
                return result
        
        # All rules passed
        return RateLimitResult(
            allowed=True,
            remaining=float('inf'),
            reset_time=datetime.now(timezone.utc) + timedelta(seconds=60)
        )
    
    def _get_applicable_rules(self, endpoint: str, method: str) -> List[RateLimitRule]:
        """Get rules applicable to the endpoint and method"""
        applicable = []
        
        for rule in self.rules:
            # Check method
            if rule.methods and method not in rule.methods:
                continue
            
            # Check endpoint
            if rule.endpoints:
                endpoint_matches = False
                for pattern in rule.endpoints:
                    if pattern.endswith('*'):
                        if endpoint.startswith(pattern[:-1]):
                            endpoint_matches = True
                            break
                    elif pattern == endpoint:
                        endpoint_matches = True
                        break
                
                if not endpoint_matches:
                    continue
            
            applicable.append(rule)
        
        return applicable
    
    def _generate_key(self, rule: RateLimitRule, identifier: str, endpoint: str) -> str:
        """Generate cache key for rate limit rule"""
        scope_value = identifier
        
        if rule.scope == RateLimitScope.GLOBAL:
            scope_value = "global"
        elif rule.scope == RateLimitScope.ENDPOINT:
            scope_value = f"{identifier}:{endpoint}"
        
        return f"rate_limit:{rule.name}:{scope_value}"
    
    def _check_rule(self, rule: RateLimitRule, key: str, identifier: str) -> RateLimitResult:
        """Check rate limit for a specific rule"""
        
        if rule.algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
            return self._check_token_bucket(rule, key)
        
        elif rule.algorithm == RateLimitAlgorithm.SLIDING_WINDOW:
            return self._check_sliding_window(rule, key)
        
        elif rule.algorithm == RateLimitAlgorithm.FIXED_WINDOW:
            return self._check_fixed_window(rule, key)
        
        elif rule.algorithm == RateLimitAlgorithm.ADAPTIVE:
            return self._check_adaptive(rule, key, identifier)
        
        else:
            # Default to sliding window
            return self._check_sliding_window(rule, key)
    
    def _check_token_bucket(self, rule: RateLimitRule, key: str) -> RateLimitResult:
        """Check token bucket rate limit"""
        
        if self.redis_client:
            return self._check_token_bucket_redis(rule, key)
        else:
            return self._check_token_bucket_local(rule, key)
    
    def _check_token_bucket_local(self, rule: RateLimitRule, key: str) -> RateLimitResult:
        """Check token bucket using local storage"""
        
        if key not in self.local_buckets:
            refill_rate = rule.limit / rule.window_seconds
            self.local_buckets[key] = TokenBucket(rule.burst_limit, refill_rate)
        
        bucket = self.local_buckets[key]
        allowed = bucket.consume(1)
        
        state = bucket.get_state()
        remaining = int(state["tokens"])
        
        reset_time = datetime.now(timezone.utc) + timedelta(
            seconds=max(0, (1 - state["tokens"]) / state["refill_rate"])
        )
        
        return RateLimitResult(
            allowed=allowed,
            remaining=remaining,
            reset_time=reset_time,
            rule_name=rule.name,
            current_usage=rule.burst_limit - remaining
        )
    
    def _check_token_bucket_redis(self, rule: RateLimitRule, key: str) -> RateLimitResult:
        """Check token bucket using Redis for distributed coordination"""
        
        lua_script = """
        local key = KEYS[1]
        local capacity = tonumber(ARGV[1])
        local refill_rate = tonumber(ARGV[2])
        local tokens_requested = tonumber(ARGV[3])
        local now = tonumber(ARGV[4])
        
        local bucket = redis.call('HMGET', key, 'tokens', 'last_refill')
        local tokens = tonumber(bucket[1]) or capacity
        local last_refill = tonumber(bucket[2]) or now
        
        -- Refill tokens
        local elapsed = now - last_refill
        tokens = math.min(capacity, tokens + elapsed * refill_rate)
        
        local allowed = 0
        if tokens >= tokens_requested then
            tokens = tokens - tokens_requested
            allowed = 1
        end
        
        -- Update bucket
        redis.call('HMSET', key, 'tokens', tokens, 'last_refill', now)
        redis.call('EXPIRE', key, 3600)  -- 1 hour TTL
        
        return {allowed, tokens}
        """
        
        try:
            now = time.time()
            refill_rate = rule.limit / rule.window_seconds
            
            result = self.redis_client.eval(
                lua_script,
                1,
                key,
                rule.burst_limit,
                refill_rate,
                1,
                now
            )
            
            allowed = bool(result[0])
            remaining = int(result[1])
            
            reset_time = datetime.now(timezone.utc) + timedelta(
                seconds=max(0, (1 - remaining) / refill_rate)
            )
            
            return RateLimitResult(
                allowed=allowed,
                remaining=remaining,
                reset_time=reset_time,
                rule_name=rule.name,
                current_usage=rule.burst_limit - remaining
            )
            
        except Exception as e:
            # Fallback to local check
            logging.warning(f"Redis rate limit check failed: {e}")
            return self._check_token_bucket_local(rule, key)
    
    def _check_sliding_window(self, rule: RateLimitRule, key: str) -> RateLimitResult:
        """Check sliding window rate limit"""
        
        if self.redis_client:
            return self._check_sliding_window_redis(rule, key)
        else:
            return self._check_sliding_window_local(rule, key)
    
    def _check_sliding_window_local(self, rule: RateLimitRule, key: str) -> RateLimitResult:
        """Check sliding window using local storage"""
        
        if key not in self.local_counters:
            self.local_counters[key] = SlidingWindowCounter(rule.window_seconds)
        
        counter = self.local_counters[key]
        current_count = counter.add_request()
        
        allowed = current_count <= rule.limit
        remaining = max(0, rule.limit - current_count)
        
        reset_time = datetime.now(timezone.utc) + timedelta(seconds=rule.window_seconds)
        
        return RateLimitResult(
            allowed=allowed,
            remaining=remaining,
            reset_time=reset_time,
            rule_name=rule.name,
            current_usage=current_count
        )
    
    def _check_sliding_window_redis(self, rule: RateLimitRule, key: str) -> RateLimitResult:
        """Check sliding window using Redis"""
        
        lua_script = """
        local key = KEYS[1]
        local window = tonumber(ARGV[1])
        local limit = tonumber(ARGV[2])
        local now = tonumber(ARGV[3])
        
        -- Remove old entries
        redis.call('ZREMRANGEBYSCORE', key, 0, now - window)
        
        -- Count current entries
        local current = redis.call('ZCARD', key)
        
        local allowed = 0
        if current < limit then
            -- Add current request
            redis.call('ZADD', key, now, now)
            allowed = 1
            current = current + 1
        end
        
        -- Set expiration
        redis.call('EXPIRE', key, window)
        
        return {allowed, current}
        """
        
        try:
            now = time.time()
            
            result = self.redis_client.eval(
                lua_script,
                1,
                key,
                rule.window_seconds,
                rule.limit,
                now
            )
            
            allowed = bool(result[0])
            current_count = int(result[1])
            remaining = max(0, rule.limit - current_count)
            
            reset_time = datetime.now(timezone.utc) + timedelta(seconds=rule.window_seconds)
            
            return RateLimitResult(
                allowed=allowed,
                remaining=remaining,
                reset_time=reset_time,
                rule_name=rule.name,
                current_usage=current_count
            )
            
        except Exception as e:
            logging.warning(f"Redis sliding window check failed: {e}")
            return self._check_sliding_window_local(rule, key)
    
    def _check_fixed_window(self, rule: RateLimitRule, key: str) -> RateLimitResult:
        """Check fixed window rate limit"""
        
        now = time.time()
        window_start = int(now // rule.window_seconds) * rule.window_seconds
        window_key = f"{key}:{window_start}"
        
        if self.redis_client:
            try:
                current = self.redis_client.incr(window_key)
                if current == 1:
                    self.redis_client.expire(window_key, rule.window_seconds)
                
                allowed = current <= rule.limit
                remaining = max(0, rule.limit - current)
                
            except Exception as e:
                logging.warning(f"Redis fixed window check failed: {e}")
                # Fallback to allowing request
                allowed = True
                remaining = rule.limit
                current = 0
        else:
            # Simple local implementation
            if not hasattr(self, '_fixed_windows'):
                self._fixed_windows = {}
            
            if window_key not in self._fixed_windows:
                self._fixed_windows[window_key] = 0
            
            self._fixed_windows[window_key] += 1
            current = self._fixed_windows[window_key]
            
            allowed = current <= rule.limit
            remaining = max(0, rule.limit - current)
            
            # Clean old windows
            cutoff = now - rule.window_seconds * 2
            self._fixed_windows = {
                k: v for k, v in self._fixed_windows.items()
                if float(k.split(':')[-1]) > cutoff
            }
        
        reset_time = datetime.fromtimestamp(
            window_start + rule.window_seconds,
            timezone.utc
        )
        
        return RateLimitResult(
            allowed=allowed,
            remaining=remaining,
            reset_time=reset_time,
            rule_name=rule.name,
            current_usage=current if 'current' in locals() else 0
        )
    
    def _check_adaptive(self, rule: RateLimitRule, key: str, identifier: str) -> RateLimitResult:
        """Check adaptive rate limit"""
        
        if key not in self.adaptive_limiters:
            self.adaptive_limiters[key] = AdaptiveRateLimiter(rule.limit, rule.window_seconds)
        
        limiter = self.adaptive_limiters[key]
        current_limit = limiter.get_current_limit()
        
        # Use sliding window with adaptive limit
        adaptive_rule = RateLimitRule(
            name=f"{rule.name}_adaptive",
            algorithm=RateLimitAlgorithm.SLIDING_WINDOW,
            scope=rule.scope,
            limit=current_limit,
            window_seconds=rule.window_seconds
        )
        
        result = self._check_sliding_window(adaptive_rule, key)
        result.rule_name = rule.name
        
        return result
    
    def _log_rate_limit_violation(self, rule: RateLimitRule, identifier: str, endpoint: str, result: RateLimitResult):
        """Log rate limit violation"""
        
        audit_logger = self.audit_manager.get_audit_logger()
        audit_logger.log_event(
            EventType.SECURITY_RATE_LIMIT_EXCEEDED,
            LogLevel.WARNING,
            f"Rate limit exceeded for {rule.name}",
            {
                "rule_name": rule.name,
                "identifier": identifier,
                "endpoint": endpoint,
                "current_usage": result.current_usage,
                "limit": rule.limit,
                "window_seconds": rule.window_seconds,
                "retry_after": result.retry_after
            },
            security_level=SecurityLevel.MEDIUM
        )
    
    def get_rate_limit_status(self, identifier: str, endpoint: str) -> Dict[str, Any]:
        """Get current rate limit status for identifier"""
        
        status = {}
        applicable_rules = self._get_applicable_rules(endpoint, "GET")
        
        for rule in applicable_rules:
            key = self._generate_key(rule, identifier, endpoint)
            
            # Get current status without consuming
            if rule.algorithm == RateLimitAlgorithm.TOKEN_BUCKET:
                if key in self.local_buckets:
                    bucket = self.local_buckets[key]
                    state = bucket.get_state()
                    status[rule.name] = {
                        "remaining": int(state["tokens"]),
                        "limit": rule.burst_limit,
                        "reset_time": datetime.now(timezone.utc) + timedelta(seconds=rule.window_seconds)
                    }
            
            elif rule.algorithm == RateLimitAlgorithm.SLIDING_WINDOW:
                if key in self.local_counters:
                    counter = self.local_counters[key]
                    # This is approximate since we can't check without adding
                    status[rule.name] = {
                        "limit": rule.limit,
                        "window_seconds": rule.window_seconds,
                        "reset_time": datetime.now(timezone.utc) + timedelta(seconds=rule.window_seconds)
                    }
        
        return status

# Global rate limiter instance
enterprise_rate_limiter = None

def init_enterprise_rate_limiter(redis_client: Optional[redis.Redis] = None):
    """Initialize global rate limiter"""
    global enterprise_rate_limiter
    enterprise_rate_limiter = EnterpriseRateLimiter(redis_client)
    return enterprise_rate_limiter

def get_rate_limiter() -> EnterpriseRateLimiter:
    """Get global rate limiter instance"""
    global enterprise_rate_limiter
    if enterprise_rate_limiter is None:
        enterprise_rate_limiter = EnterpriseRateLimiter()
    return enterprise_rate_limiter

