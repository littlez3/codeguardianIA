"""
CodeGuardian AI - Multi-Agent Integration Controller
Enterprise-grade integration system for coordinating all agents

This module provides the main integration point for the entire
CodeGuardian AI multi-agent framework, coordinating:
- 6 Specialized Agents (Security, Architecture, DevOps, Testing, Performance, Compliance)
- Knowledge Graph Engine with Neo4j
- Meta-Learning System with continuous optimization
- Agent Orchestration with intelligent coordination
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Union
from dataclasses import dataclass, asdict
from enum import Enum
import uuid

from ..agents.base_agent import BaseAgent, AgentCapability, AgentResult
from ..agents.security_agent import SecurityAgent
from ..agents.architecture_agent import ArchitectureAgent
from ..agents.devops_agent import DevOpsAgent
from ..agents.testing_agent import TestingAgent
from ..agents.performance_agent import PerformanceAgent
from ..agents.compliance_agent import ComplianceAgent

from ..orchestration.orchestrator import (
    AgentOrchestrator, TaskRequest, OrchestrationResult, 
    OrchestrationStrategy, create_orchestrator
)
from ..knowledge_graph.engine import KnowledgeGraphEngine, create_knowledge_graph
from ..meta_learning.system import (
    MetaLearningSystem, LearningEvent, LearningType, 
    PerformanceMetrics, create_meta_learning_system
)
from ..config.enterprise_config import EnterpriseConfig


class AnalysisType(Enum):
    """Types of analysis supported by the system"""
    SECURITY_ANALYSIS = "security_analysis"
    ARCHITECTURE_REVIEW = "architecture_review"
    DEVOPS_ASSESSMENT = "devops_assessment"
    TESTING_EVALUATION = "testing_evaluation"
    PERFORMANCE_ANALYSIS = "performance_analysis"
    COMPLIANCE_CHECK = "compliance_check"
    COMPREHENSIVE_ANALYSIS = "comprehensive_analysis"


class IntegrationMode(Enum):
    """Integration modes for different use cases"""
    FAST_ANALYSIS = "fast_analysis"          # Quick analysis with essential agents
    STANDARD_ANALYSIS = "standard_analysis"  # Balanced analysis with most agents
    DEEP_ANALYSIS = "deep_analysis"          # Comprehensive analysis with all agents
    CUSTOM_ANALYSIS = "custom_analysis"      # User-defined agent selection


@dataclass
class AnalysisRequest:
    """Request for multi-agent analysis"""
    id: str
    code: str
    analysis_type: AnalysisType
    integration_mode: IntegrationMode
    context: Dict[str, Any]
    priority: int = 5  # 1-10, higher is more urgent
    timeout: int = 300  # seconds
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


@dataclass
class IntegratedAnalysisResult:
    """Result from integrated multi-agent analysis"""
    request_id: str
    analysis_type: AnalysisType
    integration_mode: IntegrationMode
    
    # Agent results
    agent_results: Dict[str, AgentResult]
    
    # Orchestration results
    orchestration_result: OrchestrationResult
    
    # Consolidated findings
    consolidated_findings: Dict[str, Any]
    
    # Performance metrics
    execution_time: float
    agents_used: List[str]
    total_issues_found: int
    risk_score: float
    confidence_score: float
    
    # Meta-learning insights
    learning_insights: Dict[str, Any]
    
    # Timestamps
    started_at: datetime
    completed_at: datetime
    
    # Status
    success: bool
    error_message: Optional[str] = None


class MultiAgentIntegrationController:
    """
    Enterprise Multi-Agent Integration Controller
    
    Coordinates all CodeGuardian AI components:
    - 6 Specialized Agents
    - Knowledge Graph Engine
    - Meta-Learning System
    - Agent Orchestration
    - Performance Optimization
    """
    
    def __init__(self, config: EnterpriseConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Core components
        self.knowledge_graph: Optional[KnowledgeGraphEngine] = None
        self.meta_learning: Optional[MetaLearningSystem] = None
        self.orchestrator: Optional[AgentOrchestrator] = None
        
        # Specialized agents
        self.agents: Dict[str, BaseAgent] = {}
        
        # Integration state
        self.is_initialized = False
        self.active_analyses: Dict[str, AnalysisRequest] = {}
        self.performance_stats = {
            'total_analyses': 0,
            'successful_analyses': 0,
            'failed_analyses': 0,
            'average_execution_time': 0.0,
            'agents_performance': {}
        }
        
        # Agent configurations for different modes
        self.mode_configurations = {
            IntegrationMode.FAST_ANALYSIS: {
                'agents': ['security', 'architecture'],
                'strategy': OrchestrationStrategy.PARALLEL,
                'timeout_multiplier': 0.5
            },
            IntegrationMode.STANDARD_ANALYSIS: {
                'agents': ['security', 'architecture', 'devops', 'testing'],
                'strategy': OrchestrationStrategy.ADAPTIVE,
                'timeout_multiplier': 1.0
            },
            IntegrationMode.DEEP_ANALYSIS: {
                'agents': ['security', 'architecture', 'devops', 'testing', 'performance', 'compliance'],
                'strategy': OrchestrationStrategy.CONSENSUS,
                'timeout_multiplier': 2.0
            }
        }
    
    async def initialize(self) -> bool:
        """Initialize all system components"""
        try:
            self.logger.info("Initializing Multi-Agent Integration Controller")
            
            # Initialize Knowledge Graph
            self.knowledge_graph = create_knowledge_graph(self.config)
            await self.knowledge_graph.initialize()
            
            # Initialize Meta-Learning System
            self.meta_learning = create_meta_learning_system(self.config, self.knowledge_graph)
            
            # Initialize Agents
            await self._initialize_agents()
            
            # Initialize Orchestrator
            self.orchestrator = create_orchestrator(
                agents=list(self.agents.values()),
                knowledge_graph=self.knowledge_graph,
                config=self.config
            )
            
            # Validate initialization
            await self._validate_initialization()
            
            self.is_initialized = True
            self.logger.info("Multi-Agent Integration Controller initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Initialization failed: {e}")
            return False
    
    async def _initialize_agents(self):
        """Initialize all specialized agents"""
        agent_classes = {
            'security': SecurityAgent,
            'architecture': ArchitectureAgent,
            'devops': DevOpsAgent,
            'testing': TestingAgent,
            'performance': PerformanceAgent,
            'compliance': ComplianceAgent
        }
        
        for agent_name, agent_class in agent_classes.items():
            try:
                agent = agent_class(
                    config=self.config,
                    knowledge_graph=self.knowledge_graph
                )
                await agent.initialize()
                self.agents[agent_name] = agent
                
                # Initialize performance tracking
                self.performance_stats['agents_performance'][agent_name] = {
                    'total_executions': 0,
                    'successful_executions': 0,
                    'average_execution_time': 0.0,
                    'average_confidence': 0.0
                }
                
                self.logger.info(f"Initialized {agent_name} agent")
                
            except Exception as e:
                self.logger.error(f"Failed to initialize {agent_name} agent: {e}")
                raise
    
    async def _validate_initialization(self):
        """Validate that all components are properly initialized"""
        # Check Knowledge Graph
        if not self.knowledge_graph or not await self.knowledge_graph.health_check():
            raise RuntimeError("Knowledge Graph initialization failed")
        
        # Check Meta-Learning System
        if not self.meta_learning:
            raise RuntimeError("Meta-Learning System initialization failed")
        
        # Check Agents
        if len(self.agents) != 6:
            raise RuntimeError(f"Expected 6 agents, got {len(self.agents)}")
        
        # Check Orchestrator
        if not self.orchestrator:
            raise RuntimeError("Orchestrator initialization failed")
        
        # Test basic functionality
        await self._run_initialization_tests()
    
    async def _run_initialization_tests(self):
        """Run basic tests to ensure system is working"""
        test_code = """
def test_function():
    password = "hardcoded_password"
    return password
"""
        
        # Test each agent individually
        for agent_name, agent in self.agents.items():
            try:
                result = await agent.analyze(test_code, {})
                if not result.success:
                    raise RuntimeError(f"{agent_name} agent test failed")
            except Exception as e:
                raise RuntimeError(f"{agent_name} agent test error: {e}")
        
        self.logger.info("All initialization tests passed")
    
    async def analyze(self, request: AnalysisRequest) -> IntegratedAnalysisResult:
        """Perform integrated multi-agent analysis"""
        if not self.is_initialized:
            raise RuntimeError("System not initialized")
        
        start_time = time.time()
        self.active_analyses[request.id] = request
        
        try:
            self.logger.info(f"Starting analysis {request.id} - {request.analysis_type.value}")
            
            # Get adaptive behavior for the analysis
            context = await self._prepare_analysis_context(request)
            
            # Select agents based on analysis type and mode
            selected_agents = await self._select_agents(request)
            
            # Create orchestration task
            task_request = TaskRequest(
                id=request.id,
                code=request.code,
                context=context,
                agent_ids=[agent.agent_id for agent in selected_agents],
                strategy=self._get_orchestration_strategy(request),
                timeout=request.timeout
            )
            
            # Execute orchestrated analysis
            orchestration_result = await self.orchestrator.execute_task(task_request)
            
            # Consolidate results
            consolidated_findings = await self._consolidate_findings(
                orchestration_result, request
            )
            
            # Record learning events
            await self._record_learning_events(request, orchestration_result)
            
            # Calculate performance metrics
            execution_time = time.time() - start_time
            
            # Create integrated result
            result = IntegratedAnalysisResult(
                request_id=request.id,
                analysis_type=request.analysis_type,
                integration_mode=request.integration_mode,
                agent_results={
                    result.agent_id: result 
                    for result in orchestration_result.agent_results
                },
                orchestration_result=orchestration_result,
                consolidated_findings=consolidated_findings,
                execution_time=execution_time,
                agents_used=[agent.agent_id for agent in selected_agents],
                total_issues_found=sum(
                    len(result.findings.get('issues', [])) 
                    for result in orchestration_result.agent_results
                ),
                risk_score=consolidated_findings.get('overall_risk_score', 0.0),
                confidence_score=orchestration_result.confidence,
                learning_insights=await self._generate_learning_insights(
                    request, orchestration_result
                ),
                started_at=datetime.fromtimestamp(start_time),
                completed_at=datetime.utcnow(),
                success=orchestration_result.success,
                error_message=orchestration_result.error_message
            )
            
            # Update performance statistics
            await self._update_performance_stats(result)
            
            self.logger.info(
                f"Analysis {request.id} completed in {execution_time:.2f}s - "
                f"Success: {result.success}"
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Analysis {request.id} failed: {e}")
            
            # Create error result
            execution_time = time.time() - start_time
            return IntegratedAnalysisResult(
                request_id=request.id,
                analysis_type=request.analysis_type,
                integration_mode=request.integration_mode,
                agent_results={},
                orchestration_result=OrchestrationResult(
                    task_id=request.id,
                    success=False,
                    agent_results=[],
                    execution_time=execution_time,
                    confidence=0.0,
                    error_message=str(e)
                ),
                consolidated_findings={},
                execution_time=execution_time,
                agents_used=[],
                total_issues_found=0,
                risk_score=0.0,
                confidence_score=0.0,
                learning_insights={},
                started_at=datetime.fromtimestamp(start_time),
                completed_at=datetime.utcnow(),
                success=False,
                error_message=str(e)
            )
            
        finally:
            # Clean up
            if request.id in self.active_analyses:
                del self.active_analyses[request.id]
    
    async def _prepare_analysis_context(self, request: AnalysisRequest) -> Dict[str, Any]:
        """Prepare analysis context with adaptive behavior"""
        context = request.context.copy()
        
        # Add system context
        context.update({
            'analysis_type': request.analysis_type.value,
            'integration_mode': request.integration_mode.value,
            'priority': request.priority,
            'timeout': request.timeout,
            'code_length': len(request.code),
            'timestamp': datetime.utcnow().isoformat()
        })
        
        # Get adaptive behavior from meta-learning
        if self.meta_learning:
            adaptive_behavior = await self.meta_learning.get_adaptive_behavior(
                'system', context
            )
            context['adaptive_behavior'] = adaptive_behavior
        
        return context
    
    async def _select_agents(self, request: AnalysisRequest) -> List[BaseAgent]:
        """Select agents based on analysis type and mode"""
        if request.integration_mode == IntegrationMode.CUSTOM_ANALYSIS:
            # Custom agent selection from request
            agent_names = request.metadata.get('selected_agents', [])
        else:
            # Predefined agent selection
            config = self.mode_configurations.get(request.integration_mode, {})
            agent_names = config.get('agents', [])
        
        # Filter by analysis type if specific
        if request.analysis_type != AnalysisType.COMPREHENSIVE_ANALYSIS:
            type_mapping = {
                AnalysisType.SECURITY_ANALYSIS: ['security'],
                AnalysisType.ARCHITECTURE_REVIEW: ['architecture'],
                AnalysisType.DEVOPS_ASSESSMENT: ['devops'],
                AnalysisType.TESTING_EVALUATION: ['testing'],
                AnalysisType.PERFORMANCE_ANALYSIS: ['performance'],
                AnalysisType.COMPLIANCE_CHECK: ['compliance']
            }
            
            specific_agents = type_mapping.get(request.analysis_type, [])
            if specific_agents:
                agent_names = specific_agents
        
        # Return selected agent instances
        selected_agents = []
        for agent_name in agent_names:
            if agent_name in self.agents:
                selected_agents.append(self.agents[agent_name])
        
        if not selected_agents:
            # Fallback to security agent
            selected_agents = [self.agents['security']]
        
        return selected_agents
    
    def _get_orchestration_strategy(self, request: AnalysisRequest) -> OrchestrationStrategy:
        """Get orchestration strategy based on request"""
        if request.integration_mode == IntegrationMode.CUSTOM_ANALYSIS:
            strategy_name = request.metadata.get('strategy', 'adaptive')
            return OrchestrationStrategy(strategy_name)
        
        config = self.mode_configurations.get(request.integration_mode, {})
        return config.get('strategy', OrchestrationStrategy.ADAPTIVE)
    
    async def _consolidate_findings(self, orchestration_result: OrchestrationResult, 
                                  request: AnalysisRequest) -> Dict[str, Any]:
        """Consolidate findings from all agents"""
        consolidated = {
            'summary': {},
            'issues': [],
            'recommendations': [],
            'metrics': {},
            'risk_assessment': {},
            'overall_risk_score': 0.0,
            'confidence_breakdown': {}
        }
        
        total_issues = 0
        risk_scores = []
        confidence_scores = []
        
        # Process each agent result
        for agent_result in orchestration_result.agent_results:
            agent_findings = agent_result.findings
            
            # Collect issues
            agent_issues = agent_findings.get('issues', [])
            for issue in agent_issues:
                issue['source_agent'] = agent_result.agent_id
                consolidated['issues'].append(issue)
            
            total_issues += len(agent_issues)
            
            # Collect recommendations
            agent_recommendations = agent_findings.get('recommendations', [])
            for rec in agent_recommendations:
                rec['source_agent'] = agent_result.agent_id
                consolidated['recommendations'].append(rec)
            
            # Collect metrics
            agent_metrics = agent_findings.get('metrics', {})
            consolidated['metrics'][agent_result.agent_id] = agent_metrics
            
            # Collect risk scores
            agent_risk = agent_findings.get('risk_score', 0.0)
            if agent_risk > 0:
                risk_scores.append(agent_risk)
            
            # Collect confidence scores
            confidence_scores.append(agent_result.confidence)
            consolidated['confidence_breakdown'][agent_result.agent_id] = agent_result.confidence
        
        # Calculate overall risk score
        if risk_scores:
            # Use weighted average based on agent confidence
            weighted_risk = sum(
                risk * conf for risk, conf in zip(risk_scores, confidence_scores)
            ) / sum(confidence_scores)
            consolidated['overall_risk_score'] = min(weighted_risk, 1.0)
        
        # Create summary
        consolidated['summary'] = {
            'total_issues': total_issues,
            'agents_executed': len(orchestration_result.agent_results),
            'execution_time': orchestration_result.execution_time,
            'overall_confidence': orchestration_result.confidence,
            'analysis_type': request.analysis_type.value,
            'integration_mode': request.integration_mode.value
        }
        
        # Risk assessment
        consolidated['risk_assessment'] = self._assess_overall_risk(
            consolidated['overall_risk_score'], total_issues
        )
        
        return consolidated
    
    def _assess_overall_risk(self, risk_score: float, issue_count: int) -> Dict[str, Any]:
        """Assess overall risk level"""
        if risk_score >= 0.8 or issue_count >= 10:
            level = "CRITICAL"
            priority = "IMMEDIATE"
        elif risk_score >= 0.6 or issue_count >= 5:
            level = "HIGH"
            priority = "URGENT"
        elif risk_score >= 0.4 or issue_count >= 2:
            level = "MEDIUM"
            priority = "MODERATE"
        elif risk_score >= 0.2 or issue_count >= 1:
            level = "LOW"
            priority = "LOW"
        else:
            level = "MINIMAL"
            priority = "INFORMATIONAL"
        
        return {
            'level': level,
            'priority': priority,
            'score': risk_score,
            'issue_count': issue_count,
            'description': f"{level} risk level with {issue_count} issues found"
        }
    
    async def _record_learning_events(self, request: AnalysisRequest, 
                                    orchestration_result: OrchestrationResult):
        """Record learning events for meta-learning system"""
        if not self.meta_learning:
            return
        
        # Record performance learning event
        performance_event = LearningEvent(
            id=f"perf_{request.id}",
            type=LearningType.PERFORMANCE_OPTIMIZATION,
            context={
                'analysis_type': request.analysis_type.value,
                'integration_mode': request.integration_mode.value,
                'code_length': len(request.code)
            },
            input_data={
                'code': request.code,
                'context': request.context
            },
            output_data={
                'execution_time': orchestration_result.execution_time,
                'success': orchestration_result.success,
                'agent_count': len(orchestration_result.agent_results)
            },
            feedback={},
            confidence=orchestration_result.confidence
        )
        
        await self.meta_learning.record_learning_event(performance_event)
        
        # Record performance metrics for each agent
        for agent_result in orchestration_result.agent_results:
            metrics = PerformanceMetrics(
                accuracy=1.0 if agent_result.success else 0.0,
                execution_time=agent_result.execution_time,
                confidence=agent_result.confidence
            )
            
            await self.meta_learning.record_performance_metrics(
                agent_result.agent_id, metrics, request.context
            )
    
    async def _generate_learning_insights(self, request: AnalysisRequest,
                                        orchestration_result: OrchestrationResult) -> Dict[str, Any]:
        """Generate learning insights from the analysis"""
        insights = {
            'performance_analysis': {},
            'agent_effectiveness': {},
            'optimization_suggestions': [],
            'pattern_recognition': {}
        }
        
        # Performance analysis
        insights['performance_analysis'] = {
            'execution_time': orchestration_result.execution_time,
            'efficiency_score': min(1.0, 30.0 / orchestration_result.execution_time),  # 30s baseline
            'agent_coordination': orchestration_result.confidence,
            'resource_utilization': len(orchestration_result.agent_results) / 6.0  # Fraction of agents used
        }
        
        # Agent effectiveness
        for agent_result in orchestration_result.agent_results:
            insights['agent_effectiveness'][agent_result.agent_id] = {
                'success_rate': 1.0 if agent_result.success else 0.0,
                'confidence': agent_result.confidence,
                'execution_time': agent_result.execution_time,
                'findings_count': len(agent_result.findings.get('issues', []))
            }
        
        # Optimization suggestions
        if orchestration_result.execution_time > 60:
            insights['optimization_suggestions'].append(
                "Consider using FAST_ANALYSIS mode for quicker results"
            )
        
        if orchestration_result.confidence < 0.7:
            insights['optimization_suggestions'].append(
                "Low confidence detected - consider DEEP_ANALYSIS mode for better accuracy"
            )
        
        return insights
    
    async def _update_performance_stats(self, result: IntegratedAnalysisResult):
        """Update system performance statistics"""
        self.performance_stats['total_analyses'] += 1
        
        if result.success:
            self.performance_stats['successful_analyses'] += 1
        else:
            self.performance_stats['failed_analyses'] += 1
        
        # Update average execution time
        total = self.performance_stats['total_analyses']
        current_avg = self.performance_stats['average_execution_time']
        new_avg = ((current_avg * (total - 1)) + result.execution_time) / total
        self.performance_stats['average_execution_time'] = new_avg
        
        # Update agent performance stats
        for agent_id, agent_result in result.agent_results.items():
            if agent_id in self.performance_stats['agents_performance']:
                agent_stats = self.performance_stats['agents_performance'][agent_id]
                agent_stats['total_executions'] += 1
                
                if agent_result.success:
                    agent_stats['successful_executions'] += 1
                
                # Update average execution time
                total_exec = agent_stats['total_executions']
                current_avg_time = agent_stats['average_execution_time']
                new_avg_time = ((current_avg_time * (total_exec - 1)) + agent_result.execution_time) / total_exec
                agent_stats['average_execution_time'] = new_avg_time
                
                # Update average confidence
                current_avg_conf = agent_stats['average_confidence']
                new_avg_conf = ((current_avg_conf * (total_exec - 1)) + agent_result.confidence) / total_exec
                agent_stats['average_confidence'] = new_avg_conf
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system status"""
        status = {
            'initialized': self.is_initialized,
            'active_analyses': len(self.active_analyses),
            'performance_stats': self.performance_stats.copy(),
            'agents_status': {},
            'knowledge_graph_status': {},
            'meta_learning_status': {},
            'orchestrator_status': {}
        }
        
        # Agent status
        for agent_name, agent in self.agents.items():
            status['agents_status'][agent_name] = {
                'initialized': hasattr(agent, 'is_initialized') and agent.is_initialized,
                'capabilities': [cap.value for cap in agent.capabilities],
                'performance': self.performance_stats['agents_performance'].get(agent_name, {})
            }
        
        # Knowledge Graph status
        if self.knowledge_graph:
            status['knowledge_graph_status'] = await self.knowledge_graph.get_statistics()
        
        # Meta-Learning status
        if self.meta_learning:
            status['meta_learning_status'] = self.meta_learning.get_learning_statistics()
        
        # Orchestrator status
        if self.orchestrator:
            status['orchestrator_status'] = {
                'strategies_available': [s.value for s in OrchestrationStrategy],
                'agents_registered': len(self.orchestrator.agents)
            }
        
        return status
    
    async def health_check(self) -> Dict[str, Any]:
        """Perform comprehensive health check"""
        health = {
            'overall_status': 'healthy',
            'components': {},
            'issues': [],
            'timestamp': datetime.utcnow().isoformat()
        }
        
        try:
            # Check initialization
            if not self.is_initialized:
                health['overall_status'] = 'unhealthy'
                health['issues'].append('System not initialized')
                return health
            
            # Check Knowledge Graph
            if self.knowledge_graph:
                kg_healthy = await self.knowledge_graph.health_check()
                health['components']['knowledge_graph'] = 'healthy' if kg_healthy else 'unhealthy'
                if not kg_healthy:
                    health['issues'].append('Knowledge Graph unhealthy')
            
            # Check agents
            for agent_name, agent in self.agents.items():
                try:
                    # Simple health check - try to get capabilities
                    agent_healthy = hasattr(agent, 'capabilities') and len(agent.capabilities) > 0
                    health['components'][f'agent_{agent_name}'] = 'healthy' if agent_healthy else 'unhealthy'
                    if not agent_healthy:
                        health['issues'].append(f'Agent {agent_name} unhealthy')
                except Exception as e:
                    health['components'][f'agent_{agent_name}'] = 'unhealthy'
                    health['issues'].append(f'Agent {agent_name} error: {str(e)}')
            
            # Check Meta-Learning
            if self.meta_learning:
                ml_healthy = self.meta_learning.learning_enabled
                health['components']['meta_learning'] = 'healthy' if ml_healthy else 'unhealthy'
                if not ml_healthy:
                    health['issues'].append('Meta-Learning disabled')
            
            # Overall status
            if health['issues']:
                health['overall_status'] = 'degraded' if len(health['issues']) < 3 else 'unhealthy'
            
        except Exception as e:
            health['overall_status'] = 'unhealthy'
            health['issues'].append(f'Health check error: {str(e)}')
        
        return health
    
    async def shutdown(self):
        """Shutdown the integration controller"""
        self.logger.info("Shutting down Multi-Agent Integration Controller")
        
        # Shutdown Meta-Learning
        if self.meta_learning:
            await self.meta_learning.shutdown()
        
        # Shutdown agents
        for agent_name, agent in self.agents.items():
            try:
                if hasattr(agent, 'shutdown'):
                    await agent.shutdown()
            except Exception as e:
                self.logger.error(f"Error shutting down {agent_name}: {e}")
        
        # Shutdown Knowledge Graph
        if self.knowledge_graph:
            await self.knowledge_graph.shutdown()
        
        self.is_initialized = False
        self.logger.info("Multi-Agent Integration Controller shutdown complete")


# Factory function for easy instantiation
def create_integration_controller(config: EnterpriseConfig) -> MultiAgentIntegrationController:
    """Create and initialize a Multi-Agent Integration Controller"""
    return MultiAgentIntegrationController(config)

