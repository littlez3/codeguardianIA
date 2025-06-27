"""
CodeGuardian AI - Agent Orchestration System
Enterprise-grade multi-agent coordination and workflow management

This module implements sophisticated orchestration capabilities:
- Intelligent task distribution among specialized agents
- Conflict resolution and consensus building
- Real-time coordination and synchronization
- Load balancing and performance optimization
- Workflow management and execution tracking
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Callable
from dataclasses import dataclass, asdict, field
from enum import Enum
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from queue import Queue, PriorityQueue
import heapq

from ..agents.base_agent import BaseAgent, AgentCapability, TaskPriority, TaskStatus
from ..knowledge_graph.engine import KnowledgeGraphEngine, KnowledgeEntity, EntityType
from ..config.enterprise_config import EnterpriseConfig


class OrchestrationStrategy(Enum):
    """Strategies for task orchestration"""
    PARALLEL = "parallel"          # Execute all agents in parallel
    SEQUENTIAL = "sequential"      # Execute agents one by one
    CONDITIONAL = "conditional"    # Execute based on conditions
    ADAPTIVE = "adaptive"         # Adapt strategy based on context
    CONSENSUS = "consensus"       # Require consensus from multiple agents


class ConflictResolutionMethod(Enum):
    """Methods for resolving conflicts between agents"""
    CONFIDENCE_BASED = "confidence"    # Use highest confidence result
    MAJORITY_VOTE = "majority"         # Use majority consensus
    WEIGHTED_AVERAGE = "weighted"      # Weight by agent expertise
    ESCALATION = "escalation"          # Escalate to human review
    EXPERT_OVERRIDE = "expert"         # Use most expert agent


@dataclass
class TaskRequest:
    """Represents a task request for the orchestration system"""
    id: str
    type: str
    payload: Dict[str, Any]
    priority: TaskPriority = TaskPriority.MEDIUM
    required_capabilities: Set[AgentCapability] = field(default_factory=set)
    strategy: OrchestrationStrategy = OrchestrationStrategy.ADAPTIVE
    timeout: int = 300  # seconds
    created_at: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentResult:
    """Result from an individual agent"""
    agent_id: str
    agent_type: str
    task_id: str
    result: Dict[str, Any]
    confidence: float
    execution_time: float
    status: TaskStatus
    error: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class OrchestrationResult:
    """Final result from orchestration"""
    task_id: str
    status: TaskStatus
    results: List[AgentResult]
    final_result: Dict[str, Any]
    confidence: float
    execution_time: float
    strategy_used: OrchestrationStrategy
    conflicts_resolved: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)


class ConflictResolver:
    """Handles conflicts between agent results"""
    
    def __init__(self, knowledge_graph: KnowledgeGraphEngine):
        self.knowledge_graph = knowledge_graph
        self.logger = logging.getLogger(__name__)
    
    async def resolve_conflicts(self, results: List[AgentResult], 
                              method: ConflictResolutionMethod = ConflictResolutionMethod.CONFIDENCE_BASED) -> Tuple[Dict[str, Any], float]:
        """
        Resolve conflicts between agent results
        
        Args:
            results: List of agent results to resolve
            method: Resolution method to use
            
        Returns:
            Tuple of (resolved_result, confidence)
        """
        if not results:
            return {}, 0.0
        
        if len(results) == 1:
            return results[0].result, results[0].confidence
        
        try:
            if method == ConflictResolutionMethod.CONFIDENCE_BASED:
                return self._resolve_by_confidence(results)
            elif method == ConflictResolutionMethod.MAJORITY_VOTE:
                return await self._resolve_by_majority(results)
            elif method == ConflictResolutionMethod.WEIGHTED_AVERAGE:
                return self._resolve_by_weighted_average(results)
            elif method == ConflictResolutionMethod.EXPERT_OVERRIDE:
                return self._resolve_by_expertise(results)
            else:
                # Default to confidence-based
                return self._resolve_by_confidence(results)
                
        except Exception as e:
            self.logger.error(f"Conflict resolution failed: {e}")
            # Fallback to highest confidence result
            return self._resolve_by_confidence(results)
    
    def _resolve_by_confidence(self, results: List[AgentResult]) -> Tuple[Dict[str, Any], float]:
        """Resolve by selecting highest confidence result"""
        best_result = max(results, key=lambda r: r.confidence)
        return best_result.result, best_result.confidence
    
    async def _resolve_by_majority(self, results: List[AgentResult]) -> Tuple[Dict[str, Any], float]:
        """Resolve by majority vote on similar results"""
        # Group similar results
        groups = []
        for result in results:
            placed = False
            for group in groups:
                if self._are_results_similar(result.result, group[0].result):
                    group.append(result)
                    placed = True
                    break
            if not placed:
                groups.append([result])
        
        # Find largest group
        largest_group = max(groups, key=len)
        
        # Calculate average confidence of the group
        avg_confidence = sum(r.confidence for r in largest_group) / len(largest_group)
        
        # Return the highest confidence result from the largest group
        best_in_group = max(largest_group, key=lambda r: r.confidence)
        return best_in_group.result, avg_confidence
    
    def _resolve_by_weighted_average(self, results: List[AgentResult]) -> Tuple[Dict[str, Any], float]:
        """Resolve by weighted average based on confidence"""
        total_weight = sum(r.confidence for r in results)
        if total_weight == 0:
            return results[0].result, 0.0
        
        # For numerical results, compute weighted average
        # For categorical results, use weighted voting
        merged_result = {}
        weighted_confidence = 0
        
        for result in results:
            weight = result.confidence / total_weight
            weighted_confidence += result.confidence * weight
            
            for key, value in result.result.items():
                if key not in merged_result:
                    merged_result[key] = []
                merged_result[key].append((value, weight))
        
        # Merge values
        final_result = {}
        for key, weighted_values in merged_result.items():
            if isinstance(weighted_values[0][0], (int, float)):
                # Numerical average
                final_result[key] = sum(v * w for v, w in weighted_values)
            else:
                # Categorical voting
                vote_counts = {}
                for value, weight in weighted_values:
                    vote_counts[value] = vote_counts.get(value, 0) + weight
                final_result[key] = max(vote_counts.items(), key=lambda x: x[1])[0]
        
        return final_result, weighted_confidence
    
    def _resolve_by_expertise(self, results: List[AgentResult]) -> Tuple[Dict[str, Any], float]:
        """Resolve by selecting result from most expert agent"""
        # Define expertise hierarchy
        expertise_order = {
            'security_agent': 5,
            'architecture_agent': 4,
            'performance_agent': 3,
            'testing_agent': 2,
            'devops_agent': 2,
            'compliance_agent': 1
        }
        
        best_result = max(results, key=lambda r: (
            expertise_order.get(r.agent_type, 0),
            r.confidence
        ))
        
        return best_result.result, best_result.confidence
    
    def _are_results_similar(self, result1: Dict[str, Any], result2: Dict[str, Any], 
                           threshold: float = 0.8) -> bool:
        """Check if two results are similar"""
        # Simple similarity check based on common keys and values
        common_keys = set(result1.keys()) & set(result2.keys())
        if not common_keys:
            return False
        
        matches = 0
        for key in common_keys:
            if result1[key] == result2[key]:
                matches += 1
        
        similarity = matches / len(common_keys)
        return similarity >= threshold


class WorkflowEngine:
    """Manages complex workflows and task dependencies"""
    
    def __init__(self):
        self.workflows: Dict[str, Dict[str, Any]] = {}
        self.active_workflows: Dict[str, Dict[str, Any]] = {}
        self.logger = logging.getLogger(__name__)
    
    def register_workflow(self, workflow_id: str, workflow_definition: Dict[str, Any]):
        """Register a workflow definition"""
        self.workflows[workflow_id] = workflow_definition
        self.logger.info(f"Registered workflow: {workflow_id}")
    
    async def execute_workflow(self, workflow_id: str, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a registered workflow"""
        if workflow_id not in self.workflows:
            raise ValueError(f"Workflow {workflow_id} not found")
        
        workflow = self.workflows[workflow_id]
        execution_id = str(uuid.uuid4())
        
        self.active_workflows[execution_id] = {
            'workflow_id': workflow_id,
            'status': 'running',
            'start_time': datetime.utcnow(),
            'steps_completed': 0,
            'total_steps': len(workflow.get('steps', [])),
            'current_data': input_data
        }
        
        try:
            result = await self._execute_workflow_steps(workflow, input_data, execution_id)
            self.active_workflows[execution_id]['status'] = 'completed'
            return result
        except Exception as e:
            self.active_workflows[execution_id]['status'] = 'failed'
            self.active_workflows[execution_id]['error'] = str(e)
            raise
        finally:
            # Clean up after some time
            asyncio.create_task(self._cleanup_workflow(execution_id, delay=3600))
    
    async def _execute_workflow_steps(self, workflow: Dict[str, Any], 
                                    data: Dict[str, Any], execution_id: str) -> Dict[str, Any]:
        """Execute workflow steps"""
        current_data = data.copy()
        
        for i, step in enumerate(workflow.get('steps', [])):
            step_type = step.get('type')
            step_config = step.get('config', {})
            
            if step_type == 'agent_task':
                # Execute agent task
                result = await self._execute_agent_step(step_config, current_data)
                current_data.update(result)
            elif step_type == 'condition':
                # Conditional execution
                if not self._evaluate_condition(step_config, current_data):
                    continue
            elif step_type == 'parallel':
                # Parallel execution
                results = await self._execute_parallel_steps(step_config, current_data)
                current_data.update(results)
            
            self.active_workflows[execution_id]['steps_completed'] = i + 1
        
        return current_data
    
    async def _execute_agent_step(self, config: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute a single agent step"""
        # This would integrate with the orchestrator
        # For now, return placeholder
        return {'step_result': 'completed'}
    
    def _evaluate_condition(self, condition: Dict[str, Any], data: Dict[str, Any]) -> bool:
        """Evaluate a workflow condition"""
        # Simple condition evaluation
        field = condition.get('field')
        operator = condition.get('operator')
        value = condition.get('value')
        
        if field not in data:
            return False
        
        data_value = data[field]
        
        if operator == 'equals':
            return data_value == value
        elif operator == 'greater_than':
            return data_value > value
        elif operator == 'less_than':
            return data_value < value
        elif operator == 'contains':
            return value in str(data_value)
        
        return False
    
    async def _execute_parallel_steps(self, config: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
        """Execute steps in parallel"""
        steps = config.get('steps', [])
        tasks = []
        
        for step in steps:
            task = asyncio.create_task(self._execute_agent_step(step, data))
            tasks.append(task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        merged_result = {}
        for result in results:
            if isinstance(result, dict):
                merged_result.update(result)
        
        return merged_result
    
    async def _cleanup_workflow(self, execution_id: str, delay: int):
        """Clean up workflow execution data after delay"""
        await asyncio.sleep(delay)
        if execution_id in self.active_workflows:
            del self.active_workflows[execution_id]


class AgentOrchestrator:
    """
    Enterprise Agent Orchestration System
    
    Coordinates multiple specialized agents to provide comprehensive
    code analysis and recommendations with intelligent conflict resolution
    and adaptive execution strategies.
    """
    
    def __init__(self, config: EnterpriseConfig, knowledge_graph: KnowledgeGraphEngine):
        self.config = config
        self.knowledge_graph = knowledge_graph
        self.logger = logging.getLogger(__name__)
        
        # Agent management
        self.agents: Dict[str, BaseAgent] = {}
        self.agent_capabilities: Dict[str, Set[AgentCapability]] = {}
        self.agent_load: Dict[str, int] = {}
        self.agent_performance: Dict[str, Dict[str, float]] = {}
        
        # Task management
        self.task_queue = PriorityQueue()
        self.active_tasks: Dict[str, TaskRequest] = {}
        self.task_results: Dict[str, OrchestrationResult] = {}
        
        # Orchestration components
        self.conflict_resolver = ConflictResolver(knowledge_graph)
        self.workflow_engine = WorkflowEngine()
        
        # Performance tracking
        self.execution_stats = {
            'total_tasks': 0,
            'successful_tasks': 0,
            'failed_tasks': 0,
            'avg_execution_time': 0.0,
            'conflicts_resolved': 0
        }
        
        # Threading
        self.executor = ThreadPoolExecutor(max_workers=10)
        self.running = False
        self.orchestration_thread = None
        
        # Initialize default workflows
        self._initialize_default_workflows()
    
    def register_agent(self, agent: BaseAgent):
        """Register an agent with the orchestrator"""
        agent_id = agent.agent_id
        self.agents[agent_id] = agent
        self.agent_capabilities[agent_id] = agent.capabilities
        self.agent_load[agent_id] = 0
        self.agent_performance[agent_id] = {
            'avg_execution_time': 0.0,
            'success_rate': 1.0,
            'avg_confidence': 0.8
        }
        
        self.logger.info(f"Registered agent: {agent_id} with capabilities: {agent.capabilities}")
    
    def unregister_agent(self, agent_id: str):
        """Unregister an agent"""
        if agent_id in self.agents:
            del self.agents[agent_id]
            del self.agent_capabilities[agent_id]
            del self.agent_load[agent_id]
            del self.agent_performance[agent_id]
            self.logger.info(f"Unregistered agent: {agent_id}")
    
    async def submit_task(self, task: TaskRequest) -> str:
        """Submit a task for orchestration"""
        task_id = task.id or str(uuid.uuid4())
        task.id = task_id
        
        # Add to active tasks
        self.active_tasks[task_id] = task
        
        # Add to priority queue
        priority = task.priority.value
        self.task_queue.put((priority, time.time(), task))
        
        self.logger.info(f"Submitted task {task_id} with priority {task.priority}")
        return task_id
    
    async def execute_task(self, task: TaskRequest) -> OrchestrationResult:
        """Execute a single task using appropriate orchestration strategy"""
        start_time = time.time()
        
        try:
            # Determine execution strategy
            strategy = self._determine_strategy(task)
            
            # Select appropriate agents
            selected_agents = self._select_agents(task)
            
            if not selected_agents:
                raise ValueError(f"No suitable agents found for task {task.id}")
            
            # Execute based on strategy
            if strategy == OrchestrationStrategy.PARALLEL:
                results = await self._execute_parallel(task, selected_agents)
            elif strategy == OrchestrationStrategy.SEQUENTIAL:
                results = await self._execute_sequential(task, selected_agents)
            elif strategy == OrchestrationStrategy.CONDITIONAL:
                results = await self._execute_conditional(task, selected_agents)
            elif strategy == OrchestrationStrategy.CONSENSUS:
                results = await self._execute_consensus(task, selected_agents)
            else:  # ADAPTIVE
                results = await self._execute_adaptive(task, selected_agents)
            
            # Resolve conflicts if multiple results
            final_result, confidence = await self.conflict_resolver.resolve_conflicts(results)
            
            # Create orchestration result
            execution_time = time.time() - start_time
            orchestration_result = OrchestrationResult(
                task_id=task.id,
                status=TaskStatus.COMPLETED,
                results=results,
                final_result=final_result,
                confidence=confidence,
                execution_time=execution_time,
                strategy_used=strategy,
                conflicts_resolved=len(results) - 1 if len(results) > 1 else 0
            )
            
            # Update statistics
            self._update_statistics(orchestration_result)
            
            # Store result
            self.task_results[task.id] = orchestration_result
            
            # Update knowledge graph
            await self._update_knowledge_graph(task, orchestration_result)
            
            return orchestration_result
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Task execution failed for {task.id}: {e}")
            
            error_result = OrchestrationResult(
                task_id=task.id,
                status=TaskStatus.FAILED,
                results=[],
                final_result={'error': str(e)},
                confidence=0.0,
                execution_time=execution_time,
                strategy_used=OrchestrationStrategy.ADAPTIVE,
                metadata={'error': str(e)}
            )
            
            self.task_results[task.id] = error_result
            return error_result
        
        finally:
            # Clean up
            if task.id in self.active_tasks:
                del self.active_tasks[task.id]
    
    def _determine_strategy(self, task: TaskRequest) -> OrchestrationStrategy:
        """Determine the best orchestration strategy for a task"""
        if task.strategy != OrchestrationStrategy.ADAPTIVE:
            return task.strategy
        
        # Adaptive strategy selection based on task characteristics
        required_caps = task.required_capabilities
        
        # If task requires multiple capabilities, use parallel
        if len(required_caps) > 2:
            return OrchestrationStrategy.PARALLEL
        
        # If task is high priority and time-sensitive, use parallel
        if task.priority == TaskPriority.HIGH and task.timeout < 60:
            return OrchestrationStrategy.PARALLEL
        
        # If task requires consensus (security-critical), use consensus
        if AgentCapability.SECURITY_ANALYSIS in required_caps:
            return OrchestrationStrategy.CONSENSUS
        
        # Default to parallel for better performance
        return OrchestrationStrategy.PARALLEL
    
    def _select_agents(self, task: TaskRequest) -> List[BaseAgent]:
        """Select appropriate agents for a task"""
        if not task.required_capabilities:
            # If no specific capabilities required, use all agents
            return list(self.agents.values())
        
        selected = []
        for agent_id, agent in self.agents.items():
            agent_caps = self.agent_capabilities[agent_id]
            
            # Check if agent has any required capability
            if task.required_capabilities & agent_caps:
                selected.append(agent)
        
        # Sort by performance and load
        selected.sort(key=lambda a: (
            -self.agent_performance[a.agent_id]['success_rate'],
            self.agent_load[a.agent_id],
            -self.agent_performance[a.agent_id]['avg_confidence']
        ))
        
        return selected
    
    async def _execute_parallel(self, task: TaskRequest, agents: List[BaseAgent]) -> List[AgentResult]:
        """Execute task on multiple agents in parallel"""
        tasks = []
        for agent in agents:
            agent_task = asyncio.create_task(self._execute_agent_task(agent, task))
            tasks.append(agent_task)
        
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        agent_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                agent_results.append(AgentResult(
                    agent_id=agents[i].agent_id,
                    agent_type=agents[i].agent_type,
                    task_id=task.id,
                    result={},
                    confidence=0.0,
                    execution_time=0.0,
                    status=TaskStatus.FAILED,
                    error=str(result)
                ))
            else:
                agent_results.append(result)
        
        return agent_results
    
    async def _execute_sequential(self, task: TaskRequest, agents: List[BaseAgent]) -> List[AgentResult]:
        """Execute task on agents sequentially"""
        results = []
        
        for agent in agents:
            try:
                result = await self._execute_agent_task(agent, task)
                results.append(result)
                
                # Early termination if high confidence result
                if result.confidence > 0.9:
                    break
                    
            except Exception as e:
                results.append(AgentResult(
                    agent_id=agent.agent_id,
                    agent_type=agent.agent_type,
                    task_id=task.id,
                    result={},
                    confidence=0.0,
                    execution_time=0.0,
                    status=TaskStatus.FAILED,
                    error=str(e)
                ))
        
        return results
    
    async def _execute_conditional(self, task: TaskRequest, agents: List[BaseAgent]) -> List[AgentResult]:
        """Execute task with conditional logic"""
        results = []
        
        # Start with primary agent (highest capability match)
        primary_agent = agents[0] if agents else None
        if primary_agent:
            primary_result = await self._execute_agent_task(primary_agent, task)
            results.append(primary_result)
            
            # If primary result has low confidence, try secondary agents
            if primary_result.confidence < 0.7 and len(agents) > 1:
                secondary_tasks = []
                for agent in agents[1:3]:  # Try up to 2 more agents
                    secondary_tasks.append(self._execute_agent_task(agent, task))
                
                secondary_results = await asyncio.gather(*secondary_tasks, return_exceptions=True)
                for result in secondary_results:
                    if not isinstance(result, Exception):
                        results.append(result)
        
        return results
    
    async def _execute_consensus(self, task: TaskRequest, agents: List[BaseAgent]) -> List[AgentResult]:
        """Execute task requiring consensus from multiple agents"""
        # Execute on at least 3 agents for meaningful consensus
        consensus_agents = agents[:max(3, len(agents))]
        
        results = await self._execute_parallel(task, consensus_agents)
        
        # Filter successful results
        successful_results = [r for r in results if r.status == TaskStatus.COMPLETED]
        
        if len(successful_results) < 2:
            # Not enough results for consensus, return what we have
            return results
        
        # Check for consensus (similar results)
        consensus_groups = []
        for result in successful_results:
            placed = False
            for group in consensus_groups:
                if self.conflict_resolver._are_results_similar(result.result, group[0].result):
                    group.append(result)
                    placed = True
                    break
            if not placed:
                consensus_groups.append([result])
        
        # Return the largest consensus group
        if consensus_groups:
            largest_group = max(consensus_groups, key=len)
            return largest_group
        
        return successful_results
    
    async def _execute_adaptive(self, task: TaskRequest, agents: List[BaseAgent]) -> List[AgentResult]:
        """Execute task with adaptive strategy"""
        # Start with parallel execution of top 2 agents
        top_agents = agents[:2]
        initial_results = await self._execute_parallel(task, top_agents)
        
        # Check if we have good enough results
        successful_results = [r for r in initial_results if r.status == TaskStatus.COMPLETED]
        
        if successful_results:
            max_confidence = max(r.confidence for r in successful_results)
            
            # If we have high confidence result, return early
            if max_confidence > 0.85:
                return initial_results
            
            # If moderate confidence and we have consensus, return
            if max_confidence > 0.7 and len(successful_results) > 1:
                return initial_results
        
        # Otherwise, try additional agents
        if len(agents) > 2:
            additional_agents = agents[2:4]  # Try up to 2 more
            additional_results = await self._execute_parallel(task, additional_agents)
            initial_results.extend(additional_results)
        
        return initial_results
    
    async def _execute_agent_task(self, agent: BaseAgent, task: TaskRequest) -> AgentResult:
        """Execute task on a single agent"""
        start_time = time.time()
        
        # Update agent load
        self.agent_load[agent.agent_id] += 1
        
        try:
            # Get context from knowledge graph
            context = await self.knowledge_graph.get_context_for_analysis(
                task.payload.get('code', ''),
                task.payload.get('file_path')
            )
            
            # Add context to task payload
            enhanced_payload = task.payload.copy()
            enhanced_payload['context'] = context
            
            # Execute agent task
            result = await agent.analyze(enhanced_payload)
            
            execution_time = time.time() - start_time
            
            # Update agent performance
            self._update_agent_performance(agent.agent_id, execution_time, True, result.get('confidence', 0.8))
            
            return AgentResult(
                agent_id=agent.agent_id,
                agent_type=agent.agent_type,
                task_id=task.id,
                result=result,
                confidence=result.get('confidence', 0.8),
                execution_time=execution_time,
                status=TaskStatus.COMPLETED
            )
            
        except Exception as e:
            execution_time = time.time() - start_time
            self.logger.error(f"Agent {agent.agent_id} failed on task {task.id}: {e}")
            
            # Update agent performance
            self._update_agent_performance(agent.agent_id, execution_time, False, 0.0)
            
            return AgentResult(
                agent_id=agent.agent_id,
                agent_type=agent.agent_type,
                task_id=task.id,
                result={},
                confidence=0.0,
                execution_time=execution_time,
                status=TaskStatus.FAILED,
                error=str(e)
            )
        
        finally:
            # Update agent load
            self.agent_load[agent.agent_id] -= 1
    
    def _update_agent_performance(self, agent_id: str, execution_time: float, 
                                success: bool, confidence: float):
        """Update agent performance metrics"""
        if agent_id not in self.agent_performance:
            return
        
        perf = self.agent_performance[agent_id]
        
        # Update execution time (exponential moving average)
        alpha = 0.1
        perf['avg_execution_time'] = (alpha * execution_time + 
                                    (1 - alpha) * perf['avg_execution_time'])
        
        # Update success rate
        perf['success_rate'] = (alpha * (1.0 if success else 0.0) + 
                              (1 - alpha) * perf['success_rate'])
        
        # Update confidence
        if success:
            perf['avg_confidence'] = (alpha * confidence + 
                                    (1 - alpha) * perf['avg_confidence'])
    
    def _update_statistics(self, result: OrchestrationResult):
        """Update orchestration statistics"""
        self.execution_stats['total_tasks'] += 1
        
        if result.status == TaskStatus.COMPLETED:
            self.execution_stats['successful_tasks'] += 1
        else:
            self.execution_stats['failed_tasks'] += 1
        
        # Update average execution time
        alpha = 0.1
        self.execution_stats['avg_execution_time'] = (
            alpha * result.execution_time + 
            (1 - alpha) * self.execution_stats['avg_execution_time']
        )
        
        self.execution_stats['conflicts_resolved'] += result.conflicts_resolved
    
    async def _update_knowledge_graph(self, task: TaskRequest, result: OrchestrationResult):
        """Update knowledge graph with task results"""
        try:
            # Create entities for findings
            for agent_result in result.results:
                if agent_result.status == TaskStatus.COMPLETED:
                    entity = KnowledgeEntity(
                        id=None,  # Will be auto-generated
                        type=EntityType.AGENT_FINDING,
                        name=f"{agent_result.agent_type}_finding_{task.id}",
                        properties={
                            'task_id': task.id,
                            'agent_type': agent_result.agent_type,
                            'result': agent_result.result,
                            'execution_time': agent_result.execution_time
                        },
                        confidence=agent_result.confidence,
                        source_agent=agent_result.agent_id
                    )
                    await self.knowledge_graph.add_entity(entity)
        
        except Exception as e:
            self.logger.error(f"Failed to update knowledge graph: {e}")
    
    def _initialize_default_workflows(self):
        """Initialize default workflows"""
        # Code analysis workflow
        code_analysis_workflow = {
            'name': 'comprehensive_code_analysis',
            'description': 'Complete code analysis using all agents',
            'steps': [
                {
                    'type': 'parallel',
                    'config': {
                        'steps': [
                            {'type': 'agent_task', 'agent_type': 'security_agent'},
                            {'type': 'agent_task', 'agent_type': 'architecture_agent'},
                            {'type': 'agent_task', 'agent_type': 'performance_agent'}
                        ]
                    }
                },
                {
                    'type': 'condition',
                    'config': {
                        'field': 'security_score',
                        'operator': 'less_than',
                        'value': 0.7
                    }
                },
                {
                    'type': 'agent_task',
                    'config': {
                        'agent_type': 'compliance_agent'
                    }
                }
            ]
        }
        
        self.workflow_engine.register_workflow('code_analysis', code_analysis_workflow)
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get orchestration statistics"""
        return {
            'execution_stats': self.execution_stats.copy(),
            'agent_performance': self.agent_performance.copy(),
            'agent_load': self.agent_load.copy(),
            'active_tasks': len(self.active_tasks),
            'completed_tasks': len(self.task_results)
        }
    
    def get_task_result(self, task_id: str) -> Optional[OrchestrationResult]:
        """Get result for a specific task"""
        return self.task_results.get(task_id)
    
    async def shutdown(self):
        """Shutdown the orchestrator"""
        self.running = False
        if self.orchestration_thread:
            self.orchestration_thread.join(timeout=5)
        self.executor.shutdown(wait=True)
        self.logger.info("Agent orchestrator shutdown complete")


# Factory function for easy instantiation
def create_orchestrator(config: EnterpriseConfig, 
                       knowledge_graph: KnowledgeGraphEngine) -> AgentOrchestrator:
    """Create and initialize an Agent Orchestrator instance"""
    return AgentOrchestrator(config, knowledge_graph)

