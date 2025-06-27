"""
CodeGuardian AI - Base Agent Class
Enterprise-grade foundation for all specialized agents in the Multi-Agent Framework.

This module provides the abstract base class and common functionality for all agents
in the CodeGuardian AI system, ensuring consistent behavior, communication protocols,
and integration with the orchestration system.
"""

import abc
import asyncio
import json
import logging
import time
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass, field
from concurrent.futures import ThreadPoolExecutor, as_completed

import redis
from sqlalchemy import create_engine, Column, String, DateTime, Text, Float, Integer, Boolean
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session

from ..config.enterprise_config import EnterpriseConfig
from ..audit.audit_system import AuditSystem


class AgentStatus(Enum):
    """Agent operational status enumeration."""
    INITIALIZING = "initializing"
    READY = "ready"
    BUSY = "busy"
    ERROR = "error"
    MAINTENANCE = "maintenance"
    SHUTDOWN = "shutdown"


class TaskPriority(Enum):
    """Task priority levels for agent work queue."""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    BACKGROUND = 5


class TaskStatus(Enum):
    """Task execution status tracking."""
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"
    TIMEOUT = "timeout"


@dataclass
class AgentCapability:
    """Represents a specific capability of an agent."""
    name: str
    description: str
    confidence_level: float  # 0.0 to 1.0
    performance_metrics: Dict[str, float] = field(default_factory=dict)
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))


@dataclass
class AnalysisTask:
    """Represents a task assigned to an agent."""
    task_id: str
    task_type: str
    priority: TaskPriority
    payload: Dict[str, Any]
    context: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: TaskStatus = TaskStatus.PENDING
    result: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    timeout_seconds: int = 300
    retry_count: int = 0
    max_retries: int = 3


@dataclass
class AgentMetrics:
    """Performance and operational metrics for an agent."""
    tasks_completed: int = 0
    tasks_failed: int = 0
    average_execution_time: float = 0.0
    success_rate: float = 0.0
    last_activity: Optional[datetime] = None
    uptime_seconds: float = 0.0
    memory_usage_mb: float = 0.0
    cpu_usage_percent: float = 0.0
    error_rate: float = 0.0
    throughput_per_minute: float = 0.0


class BaseAgent(abc.ABC):
    """
    Abstract base class for all CodeGuardian AI agents.
    
    This class provides the foundational functionality that all specialized agents
    inherit, including task management, communication protocols, performance monitoring,
    and integration with the orchestration system.
    """
    
    def __init__(
        self,
        agent_id: str,
        agent_type: str,
        config: EnterpriseConfig,
        redis_client: Optional[redis.Redis] = None,
        db_session: Optional[Session] = None
    ):
        """
        Initialize the base agent with core functionality.
        
        Args:
            agent_id: Unique identifier for this agent instance
            agent_type: Type/category of the agent (e.g., 'security', 'architecture')
            config: Enterprise configuration object
            redis_client: Redis client for inter-agent communication
            db_session: Database session for persistent storage
        """
        self.agent_id = agent_id
        self.agent_type = agent_type
        self.config = config
        self.status = AgentStatus.INITIALIZING
        self.created_at = datetime.now(timezone.utc)
        self.last_heartbeat = datetime.now(timezone.utc)
        
        # Initialize logging
        self.logger = logging.getLogger(f"codeguardian.agents.{agent_type}.{agent_id}")
        self.logger.setLevel(getattr(logging, config.log_level.upper()))
        
        # Initialize audit system
        self.audit_system = AuditSystem(config)
        
        # Initialize Redis for inter-agent communication
        self.redis_client = redis_client or redis.Redis(
            host=config.redis_host,
            port=config.redis_port,
            db=config.redis_db,
            decode_responses=True,
            socket_timeout=5,
            socket_connect_timeout=5,
            retry_on_timeout=True
        )
        
        # Initialize database session
        self.db_session = db_session
        
        # Initialize metrics and capabilities
        self.metrics = AgentMetrics()
        self.capabilities: Dict[str, AgentCapability] = {}
        self.task_queue: List[AnalysisTask] = []
        self.active_tasks: Dict[str, AnalysisTask] = {}
        
        # Thread pool for concurrent task execution
        self.executor = ThreadPoolExecutor(
            max_workers=config.agent_max_workers,
            thread_name_prefix=f"agent-{agent_type}-{agent_id}"
        )
        
        # Performance tracking
        self.start_time = time.time()
        self.task_execution_times: List[float] = []
        
        # Initialize agent-specific capabilities
        self._initialize_capabilities()
        
        # Register agent with orchestration system
        self._register_agent()
        
        self.logger.info(f"Agent {self.agent_id} ({self.agent_type}) initialized successfully")
    
    @abc.abstractmethod
    def _initialize_capabilities(self) -> None:
        """Initialize agent-specific capabilities. Must be implemented by subclasses."""
        pass
    
    @abc.abstractmethod
    async def analyze(self, task: AnalysisTask) -> Dict[str, Any]:
        """
        Perform agent-specific analysis on the given task.
        
        Args:
            task: The analysis task to process
            
        Returns:
            Dictionary containing analysis results
            
        Raises:
            NotImplementedError: Must be implemented by subclasses
        """
        raise NotImplementedError("Subclasses must implement the analyze method")
    
    def _register_agent(self) -> None:
        """Register this agent with the orchestration system."""
        try:
            agent_info = {
                "agent_id": self.agent_id,
                "agent_type": self.agent_type,
                "status": self.status.value,
                "capabilities": {name: cap.name for name, cap in self.capabilities.items()},
                "created_at": self.created_at.isoformat(),
                "last_heartbeat": self.last_heartbeat.isoformat()
            }
            
            # Register in Redis
            self.redis_client.hset(
                f"agent:{self.agent_id}",
                mapping=agent_info
            )
            
            # Add to active agents set
            self.redis_client.sadd("active_agents", self.agent_id)
            
            # Set expiration for heartbeat monitoring
            self.redis_client.expire(f"agent:{self.agent_id}", 300)  # 5 minutes
            
            self.logger.info(f"Agent {self.agent_id} registered with orchestration system")
            
        except Exception as e:
            self.logger.error(f"Failed to register agent: {str(e)}")
            raise
    
    def add_capability(self, capability: AgentCapability) -> None:
        """Add a new capability to this agent."""
        self.capabilities[capability.name] = capability
        self.logger.info(f"Added capability: {capability.name}")
        
        # Update registration
        self._update_agent_registration()
    
    def update_capability_confidence(self, capability_name: str, confidence: float) -> None:
        """Update the confidence level for a specific capability."""
        if capability_name in self.capabilities:
            self.capabilities[capability_name].confidence_level = confidence
            self.capabilities[capability_name].last_updated = datetime.now(timezone.utc)
            self.logger.debug(f"Updated confidence for {capability_name}: {confidence}")
    
    def get_capability_confidence(self, capability_name: str) -> float:
        """Get the confidence level for a specific capability."""
        if capability_name in self.capabilities:
            return self.capabilities[capability_name].confidence_level
        return 0.0
    
    def can_handle_task(self, task_type: str) -> bool:
        """Check if this agent can handle a specific task type."""
        return task_type in self.capabilities
    
    def get_task_priority_score(self, task: AnalysisTask) -> float:
        """
        Calculate priority score for a task based on agent capabilities and current load.
        
        Returns:
            Float score where higher values indicate higher priority
        """
        base_priority = {
            TaskPriority.CRITICAL: 100,
            TaskPriority.HIGH: 75,
            TaskPriority.MEDIUM: 50,
            TaskPriority.LOW: 25,
            TaskPriority.BACKGROUND: 10
        }.get(task.priority, 50)
        
        # Adjust based on capability confidence
        capability_bonus = 0
        if task.task_type in self.capabilities:
            capability_bonus = self.capabilities[task.task_type].confidence_level * 20
        
        # Adjust based on current load
        load_penalty = len(self.active_tasks) * 5
        
        return base_priority + capability_bonus - load_penalty
    
    async def submit_task(self, task: AnalysisTask) -> str:
        """
        Submit a task for processing by this agent.
        
        Args:
            task: The task to process
            
        Returns:
            Task ID for tracking
        """
        if not task.task_id:
            task.task_id = str(uuid.uuid4())
        
        # Validate task
        if not self.can_handle_task(task.task_type):
            raise ValueError(f"Agent {self.agent_id} cannot handle task type: {task.task_type}")
        
        # Add to queue
        self.task_queue.append(task)
        self.task_queue.sort(key=lambda t: self.get_task_priority_score(t), reverse=True)
        
        self.logger.info(f"Task {task.task_id} submitted to agent {self.agent_id}")
        
        # Audit log
        await self.audit_system.log_event(
            event_type="TASK_SUBMITTED",
            details={
                "agent_id": self.agent_id,
                "task_id": task.task_id,
                "task_type": task.task_type,
                "priority": task.priority.value
            }
        )
        
        return task.task_id
    
    async def process_next_task(self) -> Optional[Dict[str, Any]]:
        """
        Process the next task in the queue.
        
        Returns:
            Task result or None if no tasks available
        """
        if not self.task_queue or self.status != AgentStatus.READY:
            return None
        
        task = self.task_queue.pop(0)
        task.started_at = datetime.now(timezone.utc)
        task.status = TaskStatus.IN_PROGRESS
        self.active_tasks[task.task_id] = task
        
        self.logger.info(f"Processing task {task.task_id} of type {task.task_type}")
        
        try:
            # Set agent status to busy
            self.status = AgentStatus.BUSY
            self._update_agent_registration()
            
            # Execute the task with timeout
            start_time = time.time()
            result = await asyncio.wait_for(
                self.analyze(task),
                timeout=task.timeout_seconds
            )
            
            execution_time = time.time() - start_time
            self.task_execution_times.append(execution_time)
            
            # Update task status
            task.completed_at = datetime.now(timezone.utc)
            task.status = TaskStatus.COMPLETED
            task.result = result
            
            # Update metrics
            self.metrics.tasks_completed += 1
            self._update_metrics()
            
            self.logger.info(f"Task {task.task_id} completed in {execution_time:.2f}s")
            
            # Audit log
            await self.audit_system.log_event(
                event_type="TASK_COMPLETED",
                details={
                    "agent_id": self.agent_id,
                    "task_id": task.task_id,
                    "execution_time": execution_time,
                    "result_summary": self._summarize_result(result)
                }
            )
            
            return result
            
        except asyncio.TimeoutError:
            task.status = TaskStatus.TIMEOUT
            task.error = f"Task timed out after {task.timeout_seconds} seconds"
            self.metrics.tasks_failed += 1
            self.logger.error(f"Task {task.task_id} timed out")
            
        except Exception as e:
            task.status = TaskStatus.FAILED
            task.error = str(e)
            self.metrics.tasks_failed += 1
            self.logger.error(f"Task {task.task_id} failed: {str(e)}")
            
            # Audit log
            await self.audit_system.log_event(
                event_type="TASK_FAILED",
                details={
                    "agent_id": self.agent_id,
                    "task_id": task.task_id,
                    "error": str(e)
                }
            )
            
        finally:
            # Clean up
            self.active_tasks.pop(task.task_id, None)
            self.status = AgentStatus.READY
            self._update_agent_registration()
            self._update_metrics()
        
        return None
    
    def get_task_status(self, task_id: str) -> Optional[TaskStatus]:
        """Get the status of a specific task."""
        if task_id in self.active_tasks:
            return self.active_tasks[task_id].status
        
        # Check completed tasks (could be stored in database)
        return None
    
    def cancel_task(self, task_id: str) -> bool:
        """Cancel a pending or active task."""
        # Remove from queue if pending
        for i, task in enumerate(self.task_queue):
            if task.task_id == task_id:
                task.status = TaskStatus.CANCELLED
                self.task_queue.pop(i)
                self.logger.info(f"Cancelled pending task {task_id}")
                return True
        
        # Mark active task for cancellation
        if task_id in self.active_tasks:
            self.active_tasks[task_id].status = TaskStatus.CANCELLED
            self.logger.info(f"Marked active task {task_id} for cancellation")
            return True
        
        return False
    
    def get_queue_status(self) -> Dict[str, Any]:
        """Get current queue status and metrics."""
        return {
            "agent_id": self.agent_id,
            "agent_type": self.agent_type,
            "status": self.status.value,
            "queue_length": len(self.task_queue),
            "active_tasks": len(self.active_tasks),
            "metrics": {
                "tasks_completed": self.metrics.tasks_completed,
                "tasks_failed": self.metrics.tasks_failed,
                "success_rate": self.metrics.success_rate,
                "average_execution_time": self.metrics.average_execution_time,
                "throughput_per_minute": self.metrics.throughput_per_minute
            },
            "capabilities": list(self.capabilities.keys()),
            "last_heartbeat": self.last_heartbeat.isoformat()
        }
    
    async def send_heartbeat(self) -> None:
        """Send heartbeat to orchestration system."""
        self.last_heartbeat = datetime.now(timezone.utc)
        
        try:
            # Update Redis with current status
            self.redis_client.hset(
                f"agent:{self.agent_id}",
                mapping={
                    "status": self.status.value,
                    "last_heartbeat": self.last_heartbeat.isoformat(),
                    "queue_length": len(self.task_queue),
                    "active_tasks": len(self.active_tasks),
                    "tasks_completed": self.metrics.tasks_completed,
                    "success_rate": self.metrics.success_rate
                }
            )
            
            # Reset expiration
            self.redis_client.expire(f"agent:{self.agent_id}", 300)
            
        except Exception as e:
            self.logger.error(f"Failed to send heartbeat: {str(e)}")
    
    async def communicate_with_agent(
        self,
        target_agent_id: str,
        message_type: str,
        payload: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """
        Send a message to another agent.
        
        Args:
            target_agent_id: ID of the target agent
            message_type: Type of message being sent
            payload: Message payload
            
        Returns:
            Response from target agent or None if no response
        """
        message = {
            "from_agent": self.agent_id,
            "to_agent": target_agent_id,
            "message_type": message_type,
            "payload": payload,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "message_id": str(uuid.uuid4())
        }
        
        try:
            # Send message via Redis pub/sub
            channel = f"agent_messages:{target_agent_id}"
            self.redis_client.publish(channel, json.dumps(message))
            
            self.logger.debug(f"Sent message to {target_agent_id}: {message_type}")
            
            # For request-response pattern, wait for response
            if message_type.endswith("_request"):
                response_channel = f"agent_responses:{self.agent_id}:{message['message_id']}"
                pubsub = self.redis_client.pubsub()
                pubsub.subscribe(response_channel)
                
                # Wait for response with timeout
                for message_data in pubsub.listen():
                    if message_data['type'] == 'message':
                        response = json.loads(message_data['data'])
                        pubsub.unsubscribe(response_channel)
                        return response
                        
        except Exception as e:
            self.logger.error(f"Failed to communicate with agent {target_agent_id}: {str(e)}")
        
        return None
    
    def _update_agent_registration(self) -> None:
        """Update agent registration in orchestration system."""
        try:
            self.redis_client.hset(
                f"agent:{self.agent_id}",
                mapping={
                    "status": self.status.value,
                    "last_heartbeat": self.last_heartbeat.isoformat(),
                    "queue_length": len(self.task_queue),
                    "active_tasks": len(self.active_tasks)
                }
            )
        except Exception as e:
            self.logger.error(f"Failed to update agent registration: {str(e)}")
    
    def _update_metrics(self) -> None:
        """Update agent performance metrics."""
        total_tasks = self.metrics.tasks_completed + self.metrics.tasks_failed
        if total_tasks > 0:
            self.metrics.success_rate = self.metrics.tasks_completed / total_tasks
        
        if self.task_execution_times:
            self.metrics.average_execution_time = sum(self.task_execution_times) / len(self.task_execution_times)
        
        # Calculate throughput
        uptime_minutes = (time.time() - self.start_time) / 60
        if uptime_minutes > 0:
            self.metrics.throughput_per_minute = self.metrics.tasks_completed / uptime_minutes
        
        self.metrics.uptime_seconds = time.time() - self.start_time
        self.metrics.last_activity = datetime.now(timezone.utc)
        
        # Keep only recent execution times for rolling average
        if len(self.task_execution_times) > 100:
            self.task_execution_times = self.task_execution_times[-100:]
    
    def _summarize_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Create a summary of analysis result for audit logging."""
        summary = {
            "result_type": result.get("type", "unknown"),
            "success": result.get("success", False),
            "items_analyzed": result.get("items_analyzed", 0)
        }
        
        # Add agent-specific summary fields
        if "vulnerabilities" in result:
            summary["vulnerabilities_found"] = len(result["vulnerabilities"])
        
        if "recommendations" in result:
            summary["recommendations_count"] = len(result["recommendations"])
        
        if "score" in result:
            summary["analysis_score"] = result["score"]
        
        return summary
    
    async def shutdown(self) -> None:
        """Gracefully shutdown the agent."""
        self.logger.info(f"Shutting down agent {self.agent_id}")
        
        self.status = AgentStatus.SHUTDOWN
        
        # Cancel all pending tasks
        for task in self.task_queue:
            task.status = TaskStatus.CANCELLED
        
        # Wait for active tasks to complete (with timeout)
        timeout = 30  # seconds
        start_time = time.time()
        
        while self.active_tasks and (time.time() - start_time) < timeout:
            await asyncio.sleep(1)
        
        # Force cancel remaining active tasks
        for task in self.active_tasks.values():
            task.status = TaskStatus.CANCELLED
        
        # Shutdown thread pool
        self.executor.shutdown(wait=True, timeout=10)
        
        # Unregister from orchestration system
        try:
            self.redis_client.srem("active_agents", self.agent_id)
            self.redis_client.delete(f"agent:{self.agent_id}")
        except Exception as e:
            self.logger.error(f"Failed to unregister agent: {str(e)}")
        
        self.logger.info(f"Agent {self.agent_id} shutdown complete")
    
    def __str__(self) -> str:
        return f"Agent({self.agent_id}, {self.agent_type}, {self.status.value})"
    
    def __repr__(self) -> str:
        return (f"BaseAgent(agent_id='{self.agent_id}', agent_type='{self.agent_type}', "
                f"status={self.status}, tasks_completed={self.metrics.tasks_completed})")

