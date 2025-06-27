"""
CodeGuardian AI - Meta-Learning System
Enterprise-grade continuous learning and optimization engine

This module implements sophisticated meta-learning capabilities:
- Continuous improvement based on feedback and results
- Pattern recognition for automatic optimization
- Adaptive behavior for different domains and contexts
- Self-healing and performance optimization
- Knowledge evolution and pruning
"""

import asyncio
import json
import logging
import time
import numpy as np
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set, Callable
from dataclasses import dataclass, asdict, field
from enum import Enum
import pickle
import hashlib
from collections import defaultdict, deque
import statistics
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import silhouette_score
import joblib

from ..knowledge_graph.engine import KnowledgeGraphEngine, KnowledgeEntity, EntityType, RelationType
from ..orchestration.orchestrator import OrchestrationResult, AgentResult
from ..config.enterprise_config import EnterpriseConfig


class LearningType(Enum):
    """Types of learning supported by the meta-learning system"""
    PERFORMANCE_OPTIMIZATION = "performance_optimization"
    PATTERN_RECOGNITION = "pattern_recognition"
    STRATEGY_ADAPTATION = "strategy_adaptation"
    CONFIDENCE_CALIBRATION = "confidence_calibration"
    KNOWLEDGE_EVOLUTION = "knowledge_evolution"
    RESOURCE_OPTIMIZATION = "resource_optimization"


class FeedbackType(Enum):
    """Types of feedback for learning"""
    USER_VALIDATION = "user_validation"
    AUTOMATED_VALIDATION = "automated_validation"
    PERFORMANCE_METRICS = "performance_metrics"
    ERROR_ANALYSIS = "error_analysis"
    COMPARATIVE_ANALYSIS = "comparative_analysis"


@dataclass
class LearningEvent:
    """Represents a learning event in the system"""
    id: str
    type: LearningType
    context: Dict[str, Any]
    input_data: Dict[str, Any]
    output_data: Dict[str, Any]
    feedback: Dict[str, Any]
    confidence: float
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PerformanceMetrics:
    """Performance metrics for learning optimization"""
    accuracy: float = 0.0
    precision: float = 0.0
    recall: float = 0.0
    f1_score: float = 0.0
    execution_time: float = 0.0
    confidence: float = 0.0
    user_satisfaction: float = 0.0
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0


@dataclass
class LearningPattern:
    """Represents a learned pattern"""
    id: str
    pattern_type: str
    features: Dict[str, Any]
    outcomes: List[Dict[str, Any]]
    confidence: float
    frequency: int
    last_seen: datetime
    effectiveness: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class PatternRecognitionEngine:
    """Recognizes patterns in analysis results and feedback"""
    
    def __init__(self):
        self.patterns: Dict[str, LearningPattern] = {}
        self.feature_extractors: Dict[str, Callable] = {}
        self.clustering_models: Dict[str, Any] = {}
        self.logger = logging.getLogger(__name__)
        
        # Initialize feature extractors
        self._initialize_feature_extractors()
    
    def _initialize_feature_extractors(self):
        """Initialize feature extraction functions"""
        self.feature_extractors = {
            'code_complexity': self._extract_code_complexity_features,
            'security_patterns': self._extract_security_features,
            'performance_patterns': self._extract_performance_features,
            'architecture_patterns': self._extract_architecture_features,
            'error_patterns': self._extract_error_features
        }
    
    def _extract_code_complexity_features(self, data: Dict[str, Any]) -> Dict[str, float]:
        """Extract code complexity features"""
        code = data.get('code', '')
        
        features = {
            'line_count': len(code.split('\n')),
            'char_count': len(code),
            'function_count': code.count('def '),
            'class_count': code.count('class '),
            'import_count': code.count('import '),
            'comment_ratio': code.count('#') / max(len(code.split('\n')), 1),
            'indentation_levels': max([len(line) - len(line.lstrip()) for line in code.split('\n')], default=0) // 4
        }
        
        return features
    
    def _extract_security_features(self, data: Dict[str, Any]) -> Dict[str, float]:
        """Extract security-related features"""
        code = data.get('code', '')
        results = data.get('results', {})
        
        features = {
            'sql_patterns': code.lower().count('select ') + code.lower().count('insert ') + code.lower().count('update '),
            'crypto_patterns': code.lower().count('password') + code.lower().count('secret') + code.lower().count('key'),
            'network_patterns': code.lower().count('request') + code.lower().count('http') + code.lower().count('url'),
            'file_patterns': code.lower().count('open(') + code.lower().count('file') + code.lower().count('read'),
            'vulnerability_count': len(results.get('vulnerabilities', [])),
            'risk_score': results.get('risk_score', 0.0)
        }
        
        return features
    
    def _extract_performance_features(self, data: Dict[str, Any]) -> Dict[str, float]:
        """Extract performance-related features"""
        code = data.get('code', '')
        results = data.get('results', {})
        
        features = {
            'loop_count': code.count('for ') + code.count('while '),
            'nested_loops': self._count_nested_patterns(code, ['for ', 'while ']),
            'recursive_calls': code.count('return ') if 'def ' in code else 0,
            'list_comprehensions': code.count('[') + code.count('('),
            'database_calls': code.lower().count('query') + code.lower().count('execute'),
            'complexity_score': results.get('complexity_score', 0.0)
        }
        
        return features
    
    def _extract_architecture_features(self, data: Dict[str, Any]) -> Dict[str, float]:
        """Extract architecture-related features"""
        code = data.get('code', '')
        results = data.get('results', {})
        
        features = {
            'class_inheritance': code.count('class ') if '(' in code else 0,
            'method_count': code.count('def '),
            'decorator_count': code.count('@'),
            'exception_handling': code.count('try:') + code.count('except:'),
            'design_patterns': len(results.get('design_patterns', [])),
            'coupling_score': results.get('coupling_score', 0.0)
        }
        
        return features
    
    def _extract_error_features(self, data: Dict[str, Any]) -> Dict[str, float]:
        """Extract error-related features"""
        error = data.get('error', '')
        context = data.get('context', {})
        
        features = {
            'error_type': hash(error.split(':')[0]) % 1000 if error else 0,
            'error_length': len(error),
            'stack_depth': error.count('File "') if error else 0,
            'syntax_error': 1.0 if 'SyntaxError' in error else 0.0,
            'runtime_error': 1.0 if any(e in error for e in ['RuntimeError', 'ValueError', 'TypeError']) else 0.0,
            'context_complexity': len(str(context))
        }
        
        return features
    
    def _count_nested_patterns(self, code: str, patterns: List[str]) -> int:
        """Count nested patterns in code"""
        lines = code.split('\n')
        max_nesting = 0
        current_nesting = 0
        
        for line in lines:
            stripped = line.strip()
            if any(pattern in stripped for pattern in patterns):
                current_nesting += 1
                max_nesting = max(max_nesting, current_nesting)
            elif stripped.startswith('def ') or stripped.startswith('class '):
                current_nesting = 0
        
        return max_nesting
    
    async def analyze_patterns(self, events: List[LearningEvent]) -> List[LearningPattern]:
        """Analyze events to discover patterns"""
        if len(events) < 10:  # Need minimum events for pattern recognition
            return []
        
        patterns = []
        
        # Group events by type
        events_by_type = defaultdict(list)
        for event in events:
            events_by_type[event.type.value].append(event)
        
        # Analyze patterns for each type
        for event_type, type_events in events_by_type.items():
            if len(type_events) >= 5:  # Minimum for clustering
                type_patterns = await self._discover_patterns_for_type(event_type, type_events)
                patterns.extend(type_patterns)
        
        return patterns
    
    async def _discover_patterns_for_type(self, event_type: str, events: List[LearningEvent]) -> List[LearningPattern]:
        """Discover patterns for a specific event type"""
        try:
            # Extract features
            feature_vectors = []
            event_data = []
            
            for event in events:
                if event_type in self.feature_extractors:
                    features = self.feature_extractors[event_type](event.input_data)
                    feature_vectors.append(list(features.values()))
                    event_data.append({
                        'event': event,
                        'features': features
                    })
            
            if len(feature_vectors) < 5:
                return []
            
            # Normalize features
            scaler = StandardScaler()
            normalized_features = scaler.fit_transform(feature_vectors)
            
            # Perform clustering
            optimal_clusters = self._find_optimal_clusters(normalized_features)
            if optimal_clusters < 2:
                return []
            
            kmeans = KMeans(n_clusters=optimal_clusters, random_state=42)
            cluster_labels = kmeans.fit_predict(normalized_features)
            
            # Create patterns from clusters
            patterns = []
            for cluster_id in range(optimal_clusters):
                cluster_events = [event_data[i] for i, label in enumerate(cluster_labels) if label == cluster_id]
                
                if len(cluster_events) >= 3:  # Minimum events per pattern
                    pattern = self._create_pattern_from_cluster(event_type, cluster_id, cluster_events)
                    patterns.append(pattern)
            
            # Store clustering model
            self.clustering_models[event_type] = {
                'scaler': scaler,
                'kmeans': kmeans,
                'timestamp': datetime.utcnow()
            }
            
            return patterns
            
        except Exception as e:
            self.logger.error(f"Pattern discovery failed for {event_type}: {e}")
            return []
    
    def _find_optimal_clusters(self, features: np.ndarray, max_clusters: int = 10) -> int:
        """Find optimal number of clusters using silhouette analysis"""
        if len(features) < 4:
            return 1
        
        max_clusters = min(max_clusters, len(features) // 2)
        best_score = -1
        best_clusters = 2
        
        for n_clusters in range(2, max_clusters + 1):
            try:
                kmeans = KMeans(n_clusters=n_clusters, random_state=42)
                cluster_labels = kmeans.fit_predict(features)
                score = silhouette_score(features, cluster_labels)
                
                if score > best_score:
                    best_score = score
                    best_clusters = n_clusters
            except:
                continue
        
        return best_clusters if best_score > 0.3 else 1
    
    def _create_pattern_from_cluster(self, event_type: str, cluster_id: int, 
                                   cluster_events: List[Dict[str, Any]]) -> LearningPattern:
        """Create a learning pattern from a cluster of events"""
        # Calculate average features
        all_features = [event['features'] for event in cluster_events]
        avg_features = {}
        
        if all_features:
            feature_keys = all_features[0].keys()
            for key in feature_keys:
                values = [features[key] for features in all_features if key in features]
                avg_features[key] = statistics.mean(values) if values else 0.0
        
        # Analyze outcomes
        outcomes = []
        confidences = []
        
        for event_data in cluster_events:
            event = event_data['event']
            outcomes.append(event.output_data)
            confidences.append(event.confidence)
        
        # Calculate pattern effectiveness
        avg_confidence = statistics.mean(confidences) if confidences else 0.0
        effectiveness = avg_confidence * (len(cluster_events) / 10.0)  # Frequency bonus
        
        pattern_id = f"{event_type}_cluster_{cluster_id}_{int(time.time())}"
        
        return LearningPattern(
            id=pattern_id,
            pattern_type=event_type,
            features=avg_features,
            outcomes=outcomes,
            confidence=avg_confidence,
            frequency=len(cluster_events),
            last_seen=max(event['event'].timestamp for event in cluster_events),
            effectiveness=min(effectiveness, 1.0),
            metadata={
                'cluster_id': cluster_id,
                'event_count': len(cluster_events),
                'feature_variance': self._calculate_feature_variance(all_features)
            }
        )
    
    def _calculate_feature_variance(self, features_list: List[Dict[str, float]]) -> Dict[str, float]:
        """Calculate variance for each feature across the cluster"""
        if not features_list:
            return {}
        
        variance = {}
        feature_keys = features_list[0].keys()
        
        for key in feature_keys:
            values = [features[key] for features in features_list if key in features]
            if len(values) > 1:
                variance[key] = statistics.variance(values)
            else:
                variance[key] = 0.0
        
        return variance


class AdaptiveBehaviorEngine:
    """Adapts agent behavior based on context and learning"""
    
    def __init__(self):
        self.behavior_profiles: Dict[str, Dict[str, Any]] = {}
        self.context_adaptations: Dict[str, Dict[str, Any]] = {}
        self.performance_history: Dict[str, deque] = defaultdict(lambda: deque(maxlen=100))
        self.logger = logging.getLogger(__name__)
    
    async def adapt_agent_behavior(self, agent_id: str, context: Dict[str, Any], 
                                 performance_metrics: PerformanceMetrics) -> Dict[str, Any]:
        """Adapt agent behavior based on context and performance"""
        context_key = self._generate_context_key(context)
        
        # Get or create behavior profile
        if agent_id not in self.behavior_profiles:
            self.behavior_profiles[agent_id] = self._create_default_profile()
        
        profile = self.behavior_profiles[agent_id]
        
        # Update performance history
        self.performance_history[f"{agent_id}_{context_key}"].append({
            'metrics': performance_metrics,
            'timestamp': datetime.utcnow()
        })
        
        # Analyze performance trends
        adaptations = await self._analyze_performance_trends(agent_id, context_key)
        
        # Apply adaptations
        adapted_profile = self._apply_adaptations(profile, adaptations)
        
        # Update behavior profile
        self.behavior_profiles[agent_id] = adapted_profile
        
        return adapted_profile
    
    def _generate_context_key(self, context: Dict[str, Any]) -> str:
        """Generate a key representing the context"""
        key_components = []
        
        # Extract key context features
        if 'code_type' in context:
            key_components.append(f"type:{context['code_type']}")
        if 'complexity' in context:
            complexity_level = 'high' if context['complexity'] > 0.7 else 'medium' if context['complexity'] > 0.3 else 'low'
            key_components.append(f"complexity:{complexity_level}")
        if 'domain' in context:
            key_components.append(f"domain:{context['domain']}")
        if 'file_size' in context:
            size_level = 'large' if context['file_size'] > 1000 else 'medium' if context['file_size'] > 100 else 'small'
            key_components.append(f"size:{size_level}")
        
        return "_".join(key_components) if key_components else "default"
    
    def _create_default_profile(self) -> Dict[str, Any]:
        """Create default behavior profile"""
        return {
            'confidence_threshold': 0.7,
            'analysis_depth': 'medium',
            'timeout_multiplier': 1.0,
            'parallel_processing': True,
            'cache_usage': True,
            'detailed_reporting': False,
            'risk_tolerance': 'medium',
            'performance_priority': 'balanced'
        }
    
    async def _analyze_performance_trends(self, agent_id: str, context_key: str) -> Dict[str, Any]:
        """Analyze performance trends to determine adaptations"""
        history_key = f"{agent_id}_{context_key}"
        history = self.performance_history[history_key]
        
        if len(history) < 5:  # Need minimum history
            return {}
        
        adaptations = {}
        
        # Analyze recent performance
        recent_metrics = [entry['metrics'] for entry in list(history)[-10:]]
        
        # Check accuracy trends
        accuracies = [m.accuracy for m in recent_metrics if m.accuracy > 0]
        if accuracies:
            avg_accuracy = statistics.mean(accuracies)
            if avg_accuracy < 0.7:
                adaptations['increase_analysis_depth'] = True
                adaptations['lower_confidence_threshold'] = True
        
        # Check execution time trends
        exec_times = [m.execution_time for m in recent_metrics if m.execution_time > 0]
        if exec_times:
            avg_time = statistics.mean(exec_times)
            if avg_time > 30:  # Too slow
                adaptations['reduce_analysis_depth'] = True
                adaptations['enable_caching'] = True
            elif avg_time < 5:  # Very fast, can do more
                adaptations['increase_analysis_depth'] = True
        
        # Check false positive/negative rates
        fp_rates = [m.false_positive_rate for m in recent_metrics if m.false_positive_rate >= 0]
        fn_rates = [m.false_negative_rate for m in recent_metrics if m.false_negative_rate >= 0]
        
        if fp_rates and statistics.mean(fp_rates) > 0.1:
            adaptations['increase_confidence_threshold'] = True
        
        if fn_rates and statistics.mean(fn_rates) > 0.1:
            adaptations['decrease_confidence_threshold'] = True
            adaptations['increase_analysis_depth'] = True
        
        return adaptations
    
    def _apply_adaptations(self, profile: Dict[str, Any], adaptations: Dict[str, Any]) -> Dict[str, Any]:
        """Apply adaptations to behavior profile"""
        adapted_profile = profile.copy()
        
        if adaptations.get('increase_analysis_depth'):
            if adapted_profile['analysis_depth'] == 'shallow':
                adapted_profile['analysis_depth'] = 'medium'
            elif adapted_profile['analysis_depth'] == 'medium':
                adapted_profile['analysis_depth'] = 'deep'
        
        if adaptations.get('reduce_analysis_depth'):
            if adapted_profile['analysis_depth'] == 'deep':
                adapted_profile['analysis_depth'] = 'medium'
            elif adapted_profile['analysis_depth'] == 'medium':
                adapted_profile['analysis_depth'] = 'shallow'
        
        if adaptations.get('increase_confidence_threshold'):
            adapted_profile['confidence_threshold'] = min(0.9, adapted_profile['confidence_threshold'] + 0.1)
        
        if adaptations.get('decrease_confidence_threshold') or adaptations.get('lower_confidence_threshold'):
            adapted_profile['confidence_threshold'] = max(0.3, adapted_profile['confidence_threshold'] - 0.1)
        
        if adaptations.get('enable_caching'):
            adapted_profile['cache_usage'] = True
        
        return adapted_profile


class KnowledgeEvolutionEngine:
    """Evolves and maintains the knowledge graph"""
    
    def __init__(self, knowledge_graph: KnowledgeGraphEngine):
        self.knowledge_graph = knowledge_graph
        self.evolution_history: List[Dict[str, Any]] = []
        self.pruning_rules: List[Callable] = []
        self.logger = logging.getLogger(__name__)
        
        # Initialize pruning rules
        self._initialize_pruning_rules()
    
    def _initialize_pruning_rules(self):
        """Initialize knowledge pruning rules"""
        self.pruning_rules = [
            self._prune_low_confidence_entities,
            self._prune_outdated_entities,
            self._prune_redundant_entities,
            self._prune_unused_entities
        ]
    
    async def evolve_knowledge(self, learning_events: List[LearningEvent], 
                             patterns: List[LearningPattern]) -> Dict[str, Any]:
        """Evolve knowledge based on learning events and patterns"""
        evolution_stats = {
            'entities_added': 0,
            'entities_updated': 0,
            'entities_pruned': 0,
            'relationships_added': 0,
            'patterns_integrated': 0
        }
        
        try:
            # Integrate new patterns
            for pattern in patterns:
                await self._integrate_pattern(pattern)
                evolution_stats['patterns_integrated'] += 1
            
            # Update entity confidences based on feedback
            for event in learning_events:
                if event.type == LearningType.CONFIDENCE_CALIBRATION:
                    await self._update_entity_confidence(event)
                    evolution_stats['entities_updated'] += 1
            
            # Discover new relationships
            new_relationships = await self._discover_relationships(learning_events)
            evolution_stats['relationships_added'] = len(new_relationships)
            
            # Prune obsolete knowledge
            pruned_count = await self._prune_knowledge()
            evolution_stats['entities_pruned'] = pruned_count
            
            # Record evolution
            self.evolution_history.append({
                'timestamp': datetime.utcnow(),
                'stats': evolution_stats,
                'event_count': len(learning_events),
                'pattern_count': len(patterns)
            })
            
            return evolution_stats
            
        except Exception as e:
            self.logger.error(f"Knowledge evolution failed: {e}")
            return evolution_stats
    
    async def _integrate_pattern(self, pattern: LearningPattern):
        """Integrate a learned pattern into the knowledge graph"""
        # Create entity for the pattern
        entity = KnowledgeEntity(
            id=None,
            type=EntityType.PATTERN,
            name=f"pattern_{pattern.pattern_type}_{pattern.id}",
            properties={
                'pattern_type': pattern.pattern_type,
                'features': pattern.features,
                'effectiveness': pattern.effectiveness,
                'frequency': pattern.frequency,
                'outcomes': pattern.outcomes[:5]  # Store sample outcomes
            },
            confidence=pattern.confidence,
            source_agent='meta_learning_system'
        )
        
        await self.knowledge_graph.add_entity(entity)
    
    async def _update_entity_confidence(self, event: LearningEvent):
        """Update entity confidence based on feedback"""
        entity_id = event.context.get('entity_id')
        if not entity_id:
            return
        
        feedback_score = event.feedback.get('score', 0.5)
        new_confidence = (feedback_score + event.confidence) / 2
        
        await self.knowledge_graph.update_entity_confidence(
            entity_id, 
            new_confidence, 
            'meta_learning_feedback'
        )
    
    async def _discover_relationships(self, events: List[LearningEvent]) -> List[str]:
        """Discover new relationships from learning events"""
        relationships = []
        
        # Group events by context similarity
        context_groups = self._group_events_by_context(events)
        
        for group in context_groups:
            if len(group) >= 3:  # Minimum for relationship discovery
                group_relationships = await self._find_relationships_in_group(group)
                relationships.extend(group_relationships)
        
        return relationships
    
    def _group_events_by_context(self, events: List[LearningEvent]) -> List[List[LearningEvent]]:
        """Group events by context similarity"""
        groups = []
        
        for event in events:
            placed = False
            for group in groups:
                if self._are_contexts_similar(event.context, group[0].context):
                    group.append(event)
                    placed = True
                    break
            
            if not placed:
                groups.append([event])
        
        return groups
    
    def _are_contexts_similar(self, context1: Dict[str, Any], context2: Dict[str, Any]) -> bool:
        """Check if two contexts are similar"""
        common_keys = set(context1.keys()) & set(context2.keys())
        if not common_keys:
            return False
        
        matches = 0
        for key in common_keys:
            if context1[key] == context2[key]:
                matches += 1
        
        similarity = matches / len(common_keys)
        return similarity >= 0.7
    
    async def _find_relationships_in_group(self, events: List[LearningEvent]) -> List[str]:
        """Find relationships within a group of similar events"""
        # This is a simplified implementation
        # In practice, this would use more sophisticated relationship discovery
        relationships = []
        
        # Look for cause-effect relationships
        for i, event1 in enumerate(events):
            for event2 in events[i+1:]:
                if self._might_be_related(event1, event2):
                    # Create relationship (simplified)
                    relationships.append(f"{event1.id}_relates_to_{event2.id}")
        
        return relationships
    
    def _might_be_related(self, event1: LearningEvent, event2: LearningEvent) -> bool:
        """Check if two events might be related"""
        # Simple heuristic - events close in time with similar outcomes
        time_diff = abs((event1.timestamp - event2.timestamp).total_seconds())
        
        if time_diff > 3600:  # More than 1 hour apart
            return False
        
        # Check outcome similarity
        outcome1 = event1.output_data
        outcome2 = event2.output_data
        
        if not outcome1 or not outcome2:
            return False
        
        # Simple similarity check
        common_keys = set(outcome1.keys()) & set(outcome2.keys())
        if common_keys:
            matches = sum(1 for key in common_keys if outcome1[key] == outcome2[key])
            similarity = matches / len(common_keys)
            return similarity >= 0.5
        
        return False
    
    async def _prune_knowledge(self) -> int:
        """Prune obsolete or low-quality knowledge"""
        pruned_count = 0
        
        for rule in self.pruning_rules:
            try:
                count = await rule()
                pruned_count += count
            except Exception as e:
                self.logger.error(f"Pruning rule failed: {e}")
        
        return pruned_count
    
    async def _prune_low_confidence_entities(self) -> int:
        """Prune entities with consistently low confidence"""
        # This would query the knowledge graph for low confidence entities
        # and remove them if they haven't been validated recently
        return 0  # Placeholder
    
    async def _prune_outdated_entities(self) -> int:
        """Prune entities that are too old and no longer relevant"""
        cutoff_date = datetime.utcnow() - timedelta(days=90)
        # Implementation would query and remove old entities
        return 0  # Placeholder
    
    async def _prune_redundant_entities(self) -> int:
        """Prune entities that are redundant or duplicated"""
        # Implementation would find and merge similar entities
        return 0  # Placeholder
    
    async def _prune_unused_entities(self) -> int:
        """Prune entities that are never accessed or referenced"""
        # Implementation would track usage and remove unused entities
        return 0  # Placeholder


class MetaLearningSystem:
    """
    Enterprise Meta-Learning System for CodeGuardian AI
    
    Provides continuous learning and optimization capabilities:
    - Performance optimization based on feedback
    - Pattern recognition for automatic improvement
    - Adaptive behavior for different contexts
    - Knowledge evolution and maintenance
    - Self-healing and optimization
    """
    
    def __init__(self, config: EnterpriseConfig, knowledge_graph: KnowledgeGraphEngine):
        self.config = config
        self.knowledge_graph = knowledge_graph
        self.logger = logging.getLogger(__name__)
        
        # Learning components
        self.pattern_engine = PatternRecognitionEngine()
        self.behavior_engine = AdaptiveBehaviorEngine()
        self.evolution_engine = KnowledgeEvolutionEngine(knowledge_graph)
        
        # Learning data
        self.learning_events: deque = deque(maxlen=10000)
        self.performance_metrics: Dict[str, deque] = defaultdict(lambda: deque(maxlen=1000))
        self.feedback_history: deque = deque(maxlen=5000)
        
        # Learning state
        self.learning_enabled = True
        self.last_learning_cycle = datetime.utcnow()
        self.learning_cycle_interval = timedelta(hours=1)
        
        # Performance tracking
        self.learning_stats = {
            'total_events': 0,
            'patterns_discovered': 0,
            'adaptations_made': 0,
            'knowledge_updates': 0,
            'performance_improvements': 0
        }
        
        # Start background learning
        self._start_background_learning()
    
    def _start_background_learning(self):
        """Start background learning process"""
        asyncio.create_task(self._learning_loop())
    
    async def _learning_loop(self):
        """Main learning loop"""
        while self.learning_enabled:
            try:
                await asyncio.sleep(300)  # Check every 5 minutes
                
                if datetime.utcnow() - self.last_learning_cycle >= self.learning_cycle_interval:
                    await self._perform_learning_cycle()
                    self.last_learning_cycle = datetime.utcnow()
                    
            except Exception as e:
                self.logger.error(f"Learning loop error: {e}")
                await asyncio.sleep(60)  # Wait before retrying
    
    async def record_learning_event(self, event: LearningEvent):
        """Record a learning event"""
        self.learning_events.append(event)
        self.learning_stats['total_events'] += 1
        
        # Immediate learning for critical events
        if event.type in [LearningType.PERFORMANCE_OPTIMIZATION, LearningType.CONFIDENCE_CALIBRATION]:
            await self._process_immediate_learning(event)
    
    async def record_performance_metrics(self, agent_id: str, metrics: PerformanceMetrics, 
                                       context: Dict[str, Any] = None):
        """Record performance metrics for an agent"""
        self.performance_metrics[agent_id].append({
            'metrics': metrics,
            'context': context or {},
            'timestamp': datetime.utcnow()
        })
    
    async def record_feedback(self, feedback_type: FeedbackType, content: Dict[str, Any]):
        """Record user or system feedback"""
        feedback_event = {
            'type': feedback_type,
            'content': content,
            'timestamp': datetime.utcnow()
        }
        self.feedback_history.append(feedback_event)
        
        # Create learning event from feedback
        learning_event = LearningEvent(
            id=str(time.time()),
            type=LearningType.CONFIDENCE_CALIBRATION,
            context=content.get('context', {}),
            input_data=content.get('input', {}),
            output_data=content.get('output', {}),
            feedback=content,
            confidence=content.get('confidence', 0.5)
        )
        
        await self.record_learning_event(learning_event)
    
    async def get_adaptive_behavior(self, agent_id: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Get adaptive behavior profile for an agent"""
        # Get recent performance metrics
        recent_metrics = list(self.performance_metrics[agent_id])[-10:]
        
        if recent_metrics:
            # Calculate average metrics
            avg_metrics = self._calculate_average_metrics(recent_metrics)
            
            # Get adaptive behavior
            behavior = await self.behavior_engine.adapt_agent_behavior(
                agent_id, context, avg_metrics
            )
            
            return behavior
        
        # Return default behavior if no metrics available
        return self.behavior_engine._create_default_profile()
    
    def _calculate_average_metrics(self, metrics_history: List[Dict[str, Any]]) -> PerformanceMetrics:
        """Calculate average performance metrics"""
        if not metrics_history:
            return PerformanceMetrics()
        
        metrics_list = [entry['metrics'] for entry in metrics_history]
        
        return PerformanceMetrics(
            accuracy=statistics.mean([m.accuracy for m in metrics_list if m.accuracy > 0]) or 0.0,
            precision=statistics.mean([m.precision for m in metrics_list if m.precision > 0]) or 0.0,
            recall=statistics.mean([m.recall for m in metrics_list if m.recall > 0]) or 0.0,
            f1_score=statistics.mean([m.f1_score for m in metrics_list if m.f1_score > 0]) or 0.0,
            execution_time=statistics.mean([m.execution_time for m in metrics_list if m.execution_time > 0]) or 0.0,
            confidence=statistics.mean([m.confidence for m in metrics_list if m.confidence > 0]) or 0.0,
            user_satisfaction=statistics.mean([m.user_satisfaction for m in metrics_list if m.user_satisfaction > 0]) or 0.0,
            false_positive_rate=statistics.mean([m.false_positive_rate for m in metrics_list if m.false_positive_rate >= 0]) or 0.0,
            false_negative_rate=statistics.mean([m.false_negative_rate for m in metrics_list if m.false_negative_rate >= 0]) or 0.0
        )
    
    async def _process_immediate_learning(self, event: LearningEvent):
        """Process immediate learning for critical events"""
        if event.type == LearningType.PERFORMANCE_OPTIMIZATION:
            # Immediate performance optimization
            await self._optimize_performance(event)
        elif event.type == LearningType.CONFIDENCE_CALIBRATION:
            # Immediate confidence calibration
            await self._calibrate_confidence(event)
    
    async def _optimize_performance(self, event: LearningEvent):
        """Optimize performance based on event"""
        agent_id = event.context.get('agent_id')
        if not agent_id:
            return
        
        # Analyze performance issue
        performance_data = event.input_data.get('performance', {})
        
        if performance_data.get('execution_time', 0) > 30:
            # Slow execution - adapt behavior
            context = event.context
            current_behavior = await self.get_adaptive_behavior(agent_id, context)
            
            # Reduce analysis depth for faster execution
            if current_behavior.get('analysis_depth') == 'deep':
                current_behavior['analysis_depth'] = 'medium'
                self.behavior_engine.behavior_profiles[agent_id] = current_behavior
                self.learning_stats['adaptations_made'] += 1
    
    async def _calibrate_confidence(self, event: LearningEvent):
        """Calibrate confidence based on feedback"""
        entity_id = event.context.get('entity_id')
        feedback_score = event.feedback.get('score', 0.5)
        
        if entity_id and abs(feedback_score - event.confidence) > 0.2:
            # Significant confidence mismatch - update
            await self.evolution_engine._update_entity_confidence(event)
            self.learning_stats['knowledge_updates'] += 1
    
    async def _perform_learning_cycle(self):
        """Perform a complete learning cycle"""
        self.logger.info("Starting learning cycle")
        
        try:
            # Get recent events
            recent_events = list(self.learning_events)[-1000:]  # Last 1000 events
            
            if len(recent_events) < 10:
                return
            
            # Discover patterns
            patterns = await self.pattern_engine.analyze_patterns(recent_events)
            self.learning_stats['patterns_discovered'] += len(patterns)
            
            # Evolve knowledge
            evolution_stats = await self.evolution_engine.evolve_knowledge(recent_events, patterns)
            self.learning_stats['knowledge_updates'] += evolution_stats['entities_updated']
            
            # Analyze performance improvements
            improvements = await self._analyze_performance_improvements()
            self.learning_stats['performance_improvements'] += improvements
            
            self.logger.info(f"Learning cycle completed: {len(patterns)} patterns, {evolution_stats['entities_updated']} updates")
            
        except Exception as e:
            self.logger.error(f"Learning cycle failed: {e}")
    
    async def _analyze_performance_improvements(self) -> int:
        """Analyze and count performance improvements"""
        improvements = 0
        
        # Check each agent's performance trend
        for agent_id, metrics_history in self.performance_metrics.items():
            if len(metrics_history) >= 20:  # Need sufficient history
                recent_metrics = list(metrics_history)[-10:]
                older_metrics = list(metrics_history)[-20:-10]
                
                recent_avg = self._calculate_average_metrics(recent_metrics)
                older_avg = self._calculate_average_metrics(older_metrics)
                
                # Check for improvements
                if (recent_avg.accuracy > older_avg.accuracy + 0.05 or
                    recent_avg.execution_time < older_avg.execution_time * 0.9 or
                    recent_avg.confidence > older_avg.confidence + 0.05):
                    improvements += 1
        
        return improvements
    
    def get_learning_statistics(self) -> Dict[str, Any]:
        """Get learning system statistics"""
        return {
            'learning_stats': self.learning_stats.copy(),
            'total_events': len(self.learning_events),
            'total_feedback': len(self.feedback_history),
            'agents_tracked': len(self.performance_metrics),
            'patterns_stored': len(self.pattern_engine.patterns),
            'last_learning_cycle': self.last_learning_cycle.isoformat(),
            'learning_enabled': self.learning_enabled
        }
    
    def enable_learning(self):
        """Enable learning system"""
        self.learning_enabled = True
        self.logger.info("Meta-learning system enabled")
    
    def disable_learning(self):
        """Disable learning system"""
        self.learning_enabled = False
        self.logger.info("Meta-learning system disabled")
    
    async def export_learned_knowledge(self, file_path: str):
        """Export learned knowledge to file"""
        knowledge_export = {
            'patterns': [asdict(pattern) for pattern in self.pattern_engine.patterns.values()],
            'behavior_profiles': self.behavior_engine.behavior_profiles,
            'learning_stats': self.learning_stats,
            'export_timestamp': datetime.utcnow().isoformat()
        }
        
        with open(file_path, 'wb') as f:
            pickle.dump(knowledge_export, f)
        
        self.logger.info(f"Learned knowledge exported to {file_path}")
    
    async def import_learned_knowledge(self, file_path: str):
        """Import learned knowledge from file"""
        try:
            with open(file_path, 'rb') as f:
                knowledge_import = pickle.load(f)
            
            # Import patterns
            for pattern_data in knowledge_import.get('patterns', []):
                pattern = LearningPattern(**pattern_data)
                self.pattern_engine.patterns[pattern.id] = pattern
            
            # Import behavior profiles
            imported_profiles = knowledge_import.get('behavior_profiles', {})
            self.behavior_engine.behavior_profiles.update(imported_profiles)
            
            self.logger.info(f"Learned knowledge imported from {file_path}")
            
        except Exception as e:
            self.logger.error(f"Failed to import knowledge: {e}")
    
    async def shutdown(self):
        """Shutdown the meta-learning system"""
        self.learning_enabled = False
        self.logger.info("Meta-learning system shutdown")


# Factory function for easy instantiation
def create_meta_learning_system(config: EnterpriseConfig, 
                               knowledge_graph: KnowledgeGraphEngine) -> MetaLearningSystem:
    """Create and initialize a Meta-Learning System instance"""
    return MetaLearningSystem(config, knowledge_graph)

