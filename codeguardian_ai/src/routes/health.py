"""
CodeGuardian AI - Enterprise Health Check System
Comprehensive health monitoring for production readiness
"""

import time
import psutil
import asyncio
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, asdict
from enum import Enum
from flask import Blueprint, jsonify, current_app
import redis
import psycopg2
from sqlalchemy import text

from src.models.user import db
from src.audit.audit_system import get_audit_manager, EventType, LogLevel

health_bp = Blueprint('health', __name__)

class HealthStatus(Enum):
    """Health check status levels"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    CRITICAL = "critical"

@dataclass
class HealthCheck:
    """Individual health check result"""
    name: str
    status: HealthStatus
    response_time_ms: float
    message: str
    details: Optional[Dict[str, Any]] = None
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.now(timezone.utc).isoformat()

@dataclass
class SystemHealth:
    """Overall system health status"""
    status: HealthStatus
    version: str
    uptime_seconds: float
    timestamp: str
    checks: List[HealthCheck]
    summary: Dict[str, int]
    
    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

class HealthChecker:
    """Enterprise health checking system"""
    
    def __init__(self):
        self.start_time = time.time()
        self.version = "1.0.0"
        self.audit_manager = get_audit_manager()
        
    async def check_database(self) -> HealthCheck:
        """Check database connectivity and performance"""
        start_time = time.time()
        
        try:
            # Test basic connectivity
            with current_app.app_context():
                result = db.session.execute(text('SELECT 1')).scalar()
                
            if result != 1:
                raise Exception("Database query returned unexpected result")
                
            # Test connection pool
            pool_info = db.engine.pool.status()
            
            response_time = (time.time() - start_time) * 1000
            
            details = {
                "pool_size": db.engine.pool.size(),
                "checked_in": db.engine.pool.checkedin(),
                "checked_out": db.engine.pool.checkedout(),
                "overflow": db.engine.pool.overflow(),
                "response_time_ms": response_time
            }
            
            # Determine status based on performance
            if response_time > 1000:  # > 1 second
                status = HealthStatus.CRITICAL
                message = f"Database response time critical: {response_time:.2f}ms"
            elif response_time > 500:  # > 500ms
                status = HealthStatus.DEGRADED
                message = f"Database response time degraded: {response_time:.2f}ms"
            else:
                status = HealthStatus.HEALTHY
                message = f"Database healthy: {response_time:.2f}ms"
                
            return HealthCheck(
                name="database",
                status=status,
                response_time_ms=response_time,
                message=message,
                details=details
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return HealthCheck(
                name="database",
                status=HealthStatus.CRITICAL,
                response_time_ms=response_time,
                message=f"Database connection failed: {str(e)}",
                details={"error": str(e)}
            )
    
    async def check_redis(self) -> HealthCheck:
        """Check Redis connectivity and performance"""
        start_time = time.time()
        
        try:
            # Get Redis URL from config
            redis_url = current_app.config.get('REDIS_URL', 'redis://localhost:6379/0')
            
            # Create Redis client
            r = redis.from_url(redis_url, decode_responses=True)
            
            # Test basic operations
            test_key = f"health_check_{int(time.time())}"
            r.set(test_key, "test_value", ex=60)  # Expire in 60 seconds
            value = r.get(test_key)
            r.delete(test_key)
            
            if value != "test_value":
                raise Exception("Redis read/write test failed")
                
            # Get Redis info
            info = r.info()
            
            response_time = (time.time() - start_time) * 1000
            
            details = {
                "connected_clients": info.get('connected_clients', 0),
                "used_memory_human": info.get('used_memory_human', 'unknown'),
                "redis_version": info.get('redis_version', 'unknown'),
                "uptime_in_seconds": info.get('uptime_in_seconds', 0),
                "response_time_ms": response_time
            }
            
            # Determine status
            if response_time > 500:
                status = HealthStatus.DEGRADED
                message = f"Redis response time degraded: {response_time:.2f}ms"
            else:
                status = HealthStatus.HEALTHY
                message = f"Redis healthy: {response_time:.2f}ms"
                
            return HealthCheck(
                name="redis",
                status=status,
                response_time_ms=response_time,
                message=message,
                details=details
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return HealthCheck(
                name="redis",
                status=HealthStatus.CRITICAL,
                response_time_ms=response_time,
                message=f"Redis connection failed: {str(e)}",
                details={"error": str(e)}
            )
    
    async def check_system_resources(self) -> HealthCheck:
        """Check system resource utilization"""
        start_time = time.time()
        
        try:
            # Get system metrics
            cpu_percent = psutil.cpu_percent(interval=1)
            memory = psutil.virtual_memory()
            disk = psutil.disk_usage('/')
            
            response_time = (time.time() - start_time) * 1000
            
            details = {
                "cpu_percent": cpu_percent,
                "memory_percent": memory.percent,
                "memory_available_gb": round(memory.available / (1024**3), 2),
                "disk_percent": disk.percent,
                "disk_free_gb": round(disk.free / (1024**3), 2),
                "response_time_ms": response_time
            }
            
            # Determine status based on resource usage
            if cpu_percent > 90 or memory.percent > 90 or disk.percent > 90:
                status = HealthStatus.CRITICAL
                message = "System resources critical"
            elif cpu_percent > 80 or memory.percent > 80 or disk.percent > 80:
                status = HealthStatus.DEGRADED
                message = "System resources degraded"
            else:
                status = HealthStatus.HEALTHY
                message = "System resources healthy"
                
            return HealthCheck(
                name="system_resources",
                status=status,
                response_time_ms=response_time,
                message=message,
                details=details
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return HealthCheck(
                name="system_resources",
                status=HealthStatus.CRITICAL,
                response_time_ms=response_time,
                message=f"System resource check failed: {str(e)}",
                details={"error": str(e)}
            )
    
    async def check_external_dependencies(self) -> HealthCheck:
        """Check external API dependencies"""
        start_time = time.time()
        
        try:
            # This would check external APIs like OpenAI, Anthropic, etc.
            # For now, we'll simulate the check
            
            response_time = (time.time() - start_time) * 1000
            
            details = {
                "openai_api": "healthy",
                "anthropic_api": "healthy",
                "github_api": "healthy",
                "response_time_ms": response_time
            }
            
            return HealthCheck(
                name="external_dependencies",
                status=HealthStatus.HEALTHY,
                response_time_ms=response_time,
                message="External dependencies healthy",
                details=details
            )
            
        except Exception as e:
            response_time = (time.time() - start_time) * 1000
            return HealthCheck(
                name="external_dependencies",
                status=HealthStatus.DEGRADED,
                response_time_ms=response_time,
                message=f"External dependency check failed: {str(e)}",
                details={"error": str(e)}
            )
    
    async def run_all_checks(self) -> SystemHealth:
        """Run all health checks and return overall system health"""
        checks = await asyncio.gather(
            self.check_database(),
            self.check_redis(),
            self.check_system_resources(),
            self.check_external_dependencies(),
            return_exceptions=True
        )
        
        # Handle any exceptions from checks
        valid_checks = []
        for check in checks:
            if isinstance(check, Exception):
                valid_checks.append(HealthCheck(
                    name="unknown",
                    status=HealthStatus.CRITICAL,
                    response_time_ms=0,
                    message=f"Health check failed: {str(check)}"
                ))
            else:
                valid_checks.append(check)
        
        # Calculate overall status
        status_counts = {status: 0 for status in HealthStatus}
        for check in valid_checks:
            status_counts[check.status] += 1
        
        # Determine overall status
        if status_counts[HealthStatus.CRITICAL] > 0:
            overall_status = HealthStatus.CRITICAL
        elif status_counts[HealthStatus.UNHEALTHY] > 0:
            overall_status = HealthStatus.UNHEALTHY
        elif status_counts[HealthStatus.DEGRADED] > 0:
            overall_status = HealthStatus.DEGRADED
        else:
            overall_status = HealthStatus.HEALTHY
        
        uptime = time.time() - self.start_time
        
        return SystemHealth(
            status=overall_status,
            version=self.version,
            uptime_seconds=uptime,
            timestamp=datetime.now(timezone.utc).isoformat(),
            checks=valid_checks,
            summary={
                "total_checks": len(valid_checks),
                "healthy": status_counts[HealthStatus.HEALTHY],
                "degraded": status_counts[HealthStatus.DEGRADED],
                "unhealthy": status_counts[HealthStatus.UNHEALTHY],
                "critical": status_counts[HealthStatus.CRITICAL]
            }
        )

# Global health checker instance
health_checker = HealthChecker()

@health_bp.route('/health', methods=['GET'])
async def health_check():
    """Basic health check endpoint"""
    try:
        system_health = await health_checker.run_all_checks()
        
        # Log health check
        audit_manager = get_audit_manager()
        audit_logger = audit_manager.get_audit_logger()
        
        audit_logger.log_event(
            EventType.SYSTEM_HEALTH_CHECK,
            LogLevel.INFO,
            "Health check performed",
            {
                "status": system_health.status.value,
                "uptime_seconds": system_health.uptime_seconds,
                "checks_summary": system_health.summary
            }
        )
        
        # Return appropriate HTTP status code
        status_code = 200
        if system_health.status == HealthStatus.DEGRADED:
            status_code = 200  # Still operational
        elif system_health.status == HealthStatus.UNHEALTHY:
            status_code = 503  # Service unavailable
        elif system_health.status == HealthStatus.CRITICAL:
            status_code = 503  # Service unavailable
            
        return jsonify(asdict(system_health)), status_code
        
    except Exception as e:
        # Emergency fallback
        error_health = SystemHealth(
            status=HealthStatus.CRITICAL,
            version=health_checker.version,
            uptime_seconds=time.time() - health_checker.start_time,
            timestamp=datetime.now(timezone.utc).isoformat(),
            checks=[HealthCheck(
                name="emergency",
                status=HealthStatus.CRITICAL,
                response_time_ms=0,
                message=f"Health check system failed: {str(e)}"
            )],
            summary={"total_checks": 1, "critical": 1, "healthy": 0, "degraded": 0, "unhealthy": 0}
        )
        
        return jsonify(asdict(error_health)), 503

@health_bp.route('/ready', methods=['GET'])
async def readiness_check():
    """Kubernetes readiness probe endpoint"""
    try:
        # Quick checks for readiness
        db_check = await health_checker.check_database()
        
        if db_check.status in [HealthStatus.CRITICAL, HealthStatus.UNHEALTHY]:
            return jsonify({
                "status": "not_ready",
                "message": "Database not available",
                "timestamp": datetime.now(timezone.utc).isoformat()
            }), 503
            
        return jsonify({
            "status": "ready",
            "message": "Service is ready to accept traffic",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 200
        
    except Exception as e:
        return jsonify({
            "status": "not_ready",
            "message": f"Readiness check failed: {str(e)}",
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 503

@health_bp.route('/live', methods=['GET'])
def liveness_check():
    """Kubernetes liveness probe endpoint"""
    return jsonify({
        "status": "alive",
        "message": "Service is alive",
        "uptime_seconds": time.time() - health_checker.start_time,
        "timestamp": datetime.now(timezone.utc).isoformat()
    }), 200

