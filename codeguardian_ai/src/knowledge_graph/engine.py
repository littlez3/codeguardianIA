"""
CodeGuardian AI - Knowledge Graph Engine
Enterprise-grade knowledge management with Neo4j integration

This module implements a sophisticated knowledge graph system that:
- Stores and manages relationships between code entities
- Provides semantic search capabilities
- Enables context-aware decision making
- Supports dynamic updates and machine learning integration
"""

import asyncio
import json
import logging
import time
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Tuple, Set
from dataclasses import dataclass, asdict
from enum import Enum
import hashlib
import uuid

try:
    from neo4j import GraphDatabase, basic_auth
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    logging.warning("Neo4j driver not available. Using in-memory fallback.")

from ..config.enterprise_config import EnterpriseConfig


class EntityType(Enum):
    """Types of entities in the knowledge graph"""
    FUNCTION = "function"
    CLASS = "class"
    MODULE = "module"
    VULNERABILITY = "vulnerability"
    PATTERN = "pattern"
    DEPENDENCY = "dependency"
    TEST = "test"
    METRIC = "metric"
    RECOMMENDATION = "recommendation"
    AGENT_FINDING = "agent_finding"


class RelationType(Enum):
    """Types of relationships in the knowledge graph"""
    CALLS = "CALLS"
    INHERITS = "INHERITS"
    IMPORTS = "IMPORTS"
    CONTAINS = "CONTAINS"
    DEPENDS_ON = "DEPENDS_ON"
    AFFECTS = "AFFECTS"
    SIMILAR_TO = "SIMILAR_TO"
    FOUND_BY = "FOUND_BY"
    RECOMMENDS = "RECOMMENDS"
    VALIDATES = "VALIDATES"


@dataclass
class KnowledgeEntity:
    """Represents an entity in the knowledge graph"""
    id: str
    type: EntityType
    name: str
    properties: Dict[str, Any]
    confidence: float = 1.0
    created_at: datetime = None
    updated_at: datetime = None
    source_agent: str = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if self.updated_at is None:
            self.updated_at = datetime.utcnow()
        if self.id is None:
            self.id = self._generate_id()
    
    def _generate_id(self) -> str:
        """Generate unique ID for entity"""
        content = f"{self.type.value}:{self.name}:{json.dumps(self.properties, sort_keys=True)}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


@dataclass
class KnowledgeRelation:
    """Represents a relationship in the knowledge graph"""
    id: str
    source_id: str
    target_id: str
    type: RelationType
    properties: Dict[str, Any]
    confidence: float = 1.0
    created_at: datetime = None
    source_agent: str = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if self.id is None:
            self.id = self._generate_id()
    
    def _generate_id(self) -> str:
        """Generate unique ID for relationship"""
        content = f"{self.source_id}:{self.type.value}:{self.target_id}"
        return hashlib.sha256(content.encode()).hexdigest()[:16]


class KnowledgeGraphEngine:
    """
    Enterprise Knowledge Graph Engine for CodeGuardian AI
    
    Provides sophisticated knowledge management with:
    - Neo4j integration for graph database operations
    - Semantic search capabilities
    - Context-aware querying
    - Dynamic updates and versioning
    - Machine learning integration points
    """
    
    def __init__(self, config: EnterpriseConfig):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Neo4j connection
        self.driver = None
        self.neo4j_enabled = False
        
        # In-memory fallback
        self.entities: Dict[str, KnowledgeEntity] = {}
        self.relations: Dict[str, KnowledgeRelation] = {}
        self.entity_index: Dict[str, Set[str]] = {}  # name -> entity_ids
        
        # Performance metrics
        self.query_cache: Dict[str, Tuple[Any, datetime]] = {}
        self.cache_ttl = timedelta(minutes=15)
        
        # Initialize connection
        self._initialize_connection()
    
    def _initialize_connection(self):
        """Initialize Neo4j connection or fallback to in-memory"""
        if not NEO4J_AVAILABLE:
            self.logger.warning("Neo4j not available, using in-memory storage")
            return
        
        try:
            neo4j_config = self.config.get_database_config().get('neo4j', {})
            if not neo4j_config:
                self.logger.warning("Neo4j configuration not found, using in-memory storage")
                return
            
            uri = neo4j_config.get('uri', 'bolt://localhost:7687')
            username = neo4j_config.get('username', 'neo4j')
            password = neo4j_config.get('password', 'password')
            
            self.driver = GraphDatabase.driver(
                uri,
                auth=basic_auth(username, password),
                max_connection_lifetime=3600,
                max_connection_pool_size=50,
                connection_acquisition_timeout=60
            )
            
            # Test connection
            with self.driver.session() as session:
                session.run("RETURN 1")
            
            self.neo4j_enabled = True
            self.logger.info("Neo4j connection established successfully")
            
            # Create indexes for performance
            self._create_indexes()
            
        except Exception as e:
            self.logger.error(f"Failed to connect to Neo4j: {e}")
            self.logger.info("Falling back to in-memory storage")
    
    def _create_indexes(self):
        """Create Neo4j indexes for performance"""
        if not self.neo4j_enabled:
            return
        
        indexes = [
            "CREATE INDEX entity_id_index IF NOT EXISTS FOR (e:Entity) ON (e.id)",
            "CREATE INDEX entity_type_index IF NOT EXISTS FOR (e:Entity) ON (e.type)",
            "CREATE INDEX entity_name_index IF NOT EXISTS FOR (e:Entity) ON (e.name)",
            "CREATE INDEX relation_type_index IF NOT EXISTS FOR ()-[r:RELATION]-() ON (r.type)",
            "CREATE INDEX confidence_index IF NOT EXISTS FOR (e:Entity) ON (e.confidence)",
        ]
        
        try:
            with self.driver.session() as session:
                for index_query in indexes:
                    session.run(index_query)
            self.logger.info("Neo4j indexes created successfully")
        except Exception as e:
            self.logger.error(f"Failed to create Neo4j indexes: {e}")
    
    async def add_entity(self, entity: KnowledgeEntity) -> bool:
        """Add or update an entity in the knowledge graph"""
        try:
            if self.neo4j_enabled:
                return await self._add_entity_neo4j(entity)
            else:
                return self._add_entity_memory(entity)
        except Exception as e:
            self.logger.error(f"Failed to add entity {entity.id}: {e}")
            return False
    
    async def _add_entity_neo4j(self, entity: KnowledgeEntity) -> bool:
        """Add entity to Neo4j database"""
        query = """
        MERGE (e:Entity {id: $id})
        SET e.type = $type,
            e.name = $name,
            e.properties = $properties,
            e.confidence = $confidence,
            e.created_at = $created_at,
            e.updated_at = $updated_at,
            e.source_agent = $source_agent
        RETURN e
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query, {
                    'id': entity.id,
                    'type': entity.type.value,
                    'name': entity.name,
                    'properties': json.dumps(entity.properties),
                    'confidence': entity.confidence,
                    'created_at': entity.created_at.isoformat(),
                    'updated_at': entity.updated_at.isoformat(),
                    'source_agent': entity.source_agent
                })
                return result.single() is not None
        except Exception as e:
            self.logger.error(f"Neo4j entity insertion failed: {e}")
            return False
    
    def _add_entity_memory(self, entity: KnowledgeEntity) -> bool:
        """Add entity to in-memory storage"""
        self.entities[entity.id] = entity
        
        # Update name index
        if entity.name not in self.entity_index:
            self.entity_index[entity.name] = set()
        self.entity_index[entity.name].add(entity.id)
        
        return True
    
    async def add_relation(self, relation: KnowledgeRelation) -> bool:
        """Add a relationship to the knowledge graph"""
        try:
            if self.neo4j_enabled:
                return await self._add_relation_neo4j(relation)
            else:
                return self._add_relation_memory(relation)
        except Exception as e:
            self.logger.error(f"Failed to add relation {relation.id}: {e}")
            return False
    
    async def _add_relation_neo4j(self, relation: KnowledgeRelation) -> bool:
        """Add relationship to Neo4j database"""
        query = """
        MATCH (source:Entity {id: $source_id})
        MATCH (target:Entity {id: $target_id})
        MERGE (source)-[r:RELATION {id: $id}]->(target)
        SET r.type = $type,
            r.properties = $properties,
            r.confidence = $confidence,
            r.created_at = $created_at,
            r.source_agent = $source_agent
        RETURN r
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query, {
                    'id': relation.id,
                    'source_id': relation.source_id,
                    'target_id': relation.target_id,
                    'type': relation.type.value,
                    'properties': json.dumps(relation.properties),
                    'confidence': relation.confidence,
                    'created_at': relation.created_at.isoformat(),
                    'source_agent': relation.source_agent
                })
                return result.single() is not None
        except Exception as e:
            self.logger.error(f"Neo4j relation insertion failed: {e}")
            return False
    
    def _add_relation_memory(self, relation: KnowledgeRelation) -> bool:
        """Add relationship to in-memory storage"""
        # Verify entities exist
        if (relation.source_id not in self.entities or 
            relation.target_id not in self.entities):
            return False
        
        self.relations[relation.id] = relation
        return True
    
    async def semantic_search(self, query: str, entity_types: List[EntityType] = None, 
                            limit: int = 10, min_confidence: float = 0.5) -> List[KnowledgeEntity]:
        """
        Perform semantic search across the knowledge graph
        
        Args:
            query: Search query string
            entity_types: Filter by entity types
            limit: Maximum number of results
            min_confidence: Minimum confidence threshold
            
        Returns:
            List of matching entities
        """
        cache_key = f"search:{query}:{entity_types}:{limit}:{min_confidence}"
        
        # Check cache
        if cache_key in self.query_cache:
            result, timestamp = self.query_cache[cache_key]
            if datetime.utcnow() - timestamp < self.cache_ttl:
                return result
        
        try:
            if self.neo4j_enabled:
                results = await self._semantic_search_neo4j(query, entity_types, limit, min_confidence)
            else:
                results = self._semantic_search_memory(query, entity_types, limit, min_confidence)
            
            # Cache results
            self.query_cache[cache_key] = (results, datetime.utcnow())
            return results
            
        except Exception as e:
            self.logger.error(f"Semantic search failed: {e}")
            return []
    
    async def _semantic_search_neo4j(self, query: str, entity_types: List[EntityType], 
                                   limit: int, min_confidence: float) -> List[KnowledgeEntity]:
        """Perform semantic search using Neo4j"""
        type_filter = ""
        if entity_types:
            types_str = "', '".join([t.value for t in entity_types])
            type_filter = f"AND e.type IN ['{types_str}']"
        
        cypher_query = f"""
        MATCH (e:Entity)
        WHERE (e.name CONTAINS $query OR 
               any(key IN keys(e.properties) WHERE toString(e.properties[key]) CONTAINS $query))
        {type_filter}
        AND e.confidence >= $min_confidence
        RETURN e
        ORDER BY e.confidence DESC, e.updated_at DESC
        LIMIT $limit
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(cypher_query, {
                    'query': query.lower(),
                    'min_confidence': min_confidence,
                    'limit': limit
                })
                
                entities = []
                for record in result:
                    node = record['e']
                    entity = KnowledgeEntity(
                        id=node['id'],
                        type=EntityType(node['type']),
                        name=node['name'],
                        properties=json.loads(node['properties']) if node['properties'] else {},
                        confidence=node['confidence'],
                        created_at=datetime.fromisoformat(node['created_at']),
                        updated_at=datetime.fromisoformat(node['updated_at']),
                        source_agent=node.get('source_agent')
                    )
                    entities.append(entity)
                
                return entities
                
        except Exception as e:
            self.logger.error(f"Neo4j semantic search failed: {e}")
            return []
    
    def _semantic_search_memory(self, query: str, entity_types: List[EntityType], 
                              limit: int, min_confidence: float) -> List[KnowledgeEntity]:
        """Perform semantic search using in-memory storage"""
        query_lower = query.lower()
        matches = []
        
        for entity in self.entities.values():
            # Filter by confidence
            if entity.confidence < min_confidence:
                continue
            
            # Filter by type
            if entity_types and entity.type not in entity_types:
                continue
            
            # Check name match
            score = 0.0
            if query_lower in entity.name.lower():
                score += 0.8
            
            # Check properties match
            for key, value in entity.properties.items():
                if query_lower in str(value).lower():
                    score += 0.5
                    break
            
            if score > 0:
                matches.append((entity, score))
        
        # Sort by score and confidence
        matches.sort(key=lambda x: (x[1], x[0].confidence), reverse=True)
        
        return [entity for entity, _ in matches[:limit]]
    
    async def get_related_entities(self, entity_id: str, relation_types: List[RelationType] = None,
                                 max_depth: int = 2) -> Dict[str, List[KnowledgeEntity]]:
        """
        Get entities related to a given entity
        
        Args:
            entity_id: ID of the source entity
            relation_types: Filter by relationship types
            max_depth: Maximum traversal depth
            
        Returns:
            Dictionary mapping relationship types to related entities
        """
        try:
            if self.neo4j_enabled:
                return await self._get_related_neo4j(entity_id, relation_types, max_depth)
            else:
                return self._get_related_memory(entity_id, relation_types, max_depth)
        except Exception as e:
            self.logger.error(f"Failed to get related entities for {entity_id}: {e}")
            return {}
    
    async def _get_related_neo4j(self, entity_id: str, relation_types: List[RelationType],
                               max_depth: int) -> Dict[str, List[KnowledgeEntity]]:
        """Get related entities using Neo4j"""
        type_filter = ""
        if relation_types:
            types_str = "', '".join([t.value for t in relation_types])
            type_filter = f"AND r.type IN ['{types_str}']"
        
        query = f"""
        MATCH (source:Entity {{id: $entity_id}})
        MATCH (source)-[r:RELATION*1..{max_depth}]->(target:Entity)
        WHERE true {type_filter}
        RETURN r, target
        ORDER BY r[0].confidence DESC
        """
        
        try:
            with self.driver.session() as session:
                result = session.run(query, {'entity_id': entity_id})
                
                related = {}
                for record in result:
                    relations = record['r']
                    target_node = record['target']
                    
                    # Get the first relation type (direct relationship)
                    rel_type = relations[0]['type']
                    
                    if rel_type not in related:
                        related[rel_type] = []
                    
                    entity = KnowledgeEntity(
                        id=target_node['id'],
                        type=EntityType(target_node['type']),
                        name=target_node['name'],
                        properties=json.loads(target_node['properties']) if target_node['properties'] else {},
                        confidence=target_node['confidence'],
                        created_at=datetime.fromisoformat(target_node['created_at']),
                        updated_at=datetime.fromisoformat(target_node['updated_at']),
                        source_agent=target_node.get('source_agent')
                    )
                    related[rel_type].append(entity)
                
                return related
                
        except Exception as e:
            self.logger.error(f"Neo4j related entities query failed: {e}")
            return {}
    
    def _get_related_memory(self, entity_id: str, relation_types: List[RelationType],
                          max_depth: int) -> Dict[str, List[KnowledgeEntity]]:
        """Get related entities using in-memory storage"""
        if entity_id not in self.entities:
            return {}
        
        related = {}
        visited = set()
        queue = [(entity_id, 0)]  # (entity_id, depth)
        
        while queue:
            current_id, depth = queue.pop(0)
            
            if current_id in visited or depth >= max_depth:
                continue
            
            visited.add(current_id)
            
            # Find outgoing relations
            for relation in self.relations.values():
                if relation.source_id != current_id:
                    continue
                
                # Filter by relation type
                if relation_types and relation.type not in relation_types:
                    continue
                
                rel_type = relation.type.value
                if rel_type not in related:
                    related[rel_type] = []
                
                target_entity = self.entities.get(relation.target_id)
                if target_entity:
                    related[rel_type].append(target_entity)
                    queue.append((relation.target_id, depth + 1))
        
        return related
    
    async def get_context_for_analysis(self, code_snippet: str, file_path: str = None) -> Dict[str, Any]:
        """
        Get contextual information for code analysis
        
        Args:
            code_snippet: Code to analyze
            file_path: Optional file path for additional context
            
        Returns:
            Dictionary containing contextual information
        """
        context = {
            'related_functions': [],
            'dependencies': [],
            'similar_patterns': [],
            'historical_issues': [],
            'recommendations': []
        }
        
        try:
            # Extract function/class names from code
            import ast
            try:
                tree = ast.parse(code_snippet)
                names = []
                for node in ast.walk(tree):
                    if isinstance(node, (ast.FunctionDef, ast.ClassDef)):
                        names.append(node.name)
                
                # Search for related entities
                for name in names:
                    entities = await self.semantic_search(name, [EntityType.FUNCTION, EntityType.CLASS])
                    context['related_functions'].extend(entities)
                
            except SyntaxError:
                # If parsing fails, do text-based search
                pass
            
            # Search for similar patterns
            patterns = await self.semantic_search(
                code_snippet[:100],  # First 100 chars
                [EntityType.PATTERN, EntityType.VULNERABILITY],
                limit=5
            )
            context['similar_patterns'] = patterns
            
            # Get historical issues if file path provided
            if file_path:
                file_entities = await self.semantic_search(
                    file_path,
                    [EntityType.VULNERABILITY, EntityType.RECOMMENDATION],
                    limit=10
                )
                context['historical_issues'] = file_entities
            
            return context
            
        except Exception as e:
            self.logger.error(f"Failed to get context for analysis: {e}")
            return context
    
    async def update_entity_confidence(self, entity_id: str, new_confidence: float, 
                                     feedback_source: str = None):
        """Update entity confidence based on feedback"""
        try:
            if self.neo4j_enabled:
                await self._update_confidence_neo4j(entity_id, new_confidence, feedback_source)
            else:
                self._update_confidence_memory(entity_id, new_confidence, feedback_source)
        except Exception as e:
            self.logger.error(f"Failed to update confidence for {entity_id}: {e}")
    
    async def _update_confidence_neo4j(self, entity_id: str, new_confidence: float, 
                                     feedback_source: str):
        """Update confidence in Neo4j"""
        query = """
        MATCH (e:Entity {id: $entity_id})
        SET e.confidence = $confidence,
            e.updated_at = $updated_at,
            e.feedback_source = $feedback_source
        RETURN e
        """
        
        with self.driver.session() as session:
            session.run(query, {
                'entity_id': entity_id,
                'confidence': new_confidence,
                'updated_at': datetime.utcnow().isoformat(),
                'feedback_source': feedback_source
            })
    
    def _update_confidence_memory(self, entity_id: str, new_confidence: float, 
                                feedback_source: str):
        """Update confidence in memory"""
        if entity_id in self.entities:
            entity = self.entities[entity_id]
            entity.confidence = new_confidence
            entity.updated_at = datetime.utcnow()
            if feedback_source:
                entity.properties['feedback_source'] = feedback_source
    
    async def get_statistics(self) -> Dict[str, Any]:
        """Get knowledge graph statistics"""
        try:
            if self.neo4j_enabled:
                return await self._get_statistics_neo4j()
            else:
                return self._get_statistics_memory()
        except Exception as e:
            self.logger.error(f"Failed to get statistics: {e}")
            return {}
    
    async def _get_statistics_neo4j(self) -> Dict[str, Any]:
        """Get statistics from Neo4j"""
        queries = {
            'total_entities': "MATCH (e:Entity) RETURN count(e) as count",
            'total_relations': "MATCH ()-[r:RELATION]->() RETURN count(r) as count",
            'entity_types': "MATCH (e:Entity) RETURN e.type, count(e) as count",
            'relation_types': "MATCH ()-[r:RELATION]->() RETURN r.type, count(r) as count",
            'avg_confidence': "MATCH (e:Entity) RETURN avg(e.confidence) as avg_confidence"
        }
        
        stats = {}
        
        with self.driver.session() as session:
            for key, query in queries.items():
                result = session.run(query)
                if key in ['entity_types', 'relation_types']:
                    stats[key] = {record[0]: record[1] for record in result}
                else:
                    record = result.single()
                    stats[key] = record[0] if record else 0
        
        return stats
    
    def _get_statistics_memory(self) -> Dict[str, Any]:
        """Get statistics from memory"""
        entity_types = {}
        relation_types = {}
        total_confidence = 0
        
        for entity in self.entities.values():
            entity_type = entity.type.value
            entity_types[entity_type] = entity_types.get(entity_type, 0) + 1
            total_confidence += entity.confidence
        
        for relation in self.relations.values():
            rel_type = relation.type.value
            relation_types[rel_type] = relation_types.get(rel_type, 0) + 1
        
        return {
            'total_entities': len(self.entities),
            'total_relations': len(self.relations),
            'entity_types': entity_types,
            'relation_types': relation_types,
            'avg_confidence': total_confidence / len(self.entities) if self.entities else 0
        }
    
    def close(self):
        """Close database connections"""
        if self.driver:
            self.driver.close()
            self.logger.info("Neo4j connection closed")


# Factory function for easy instantiation
def create_knowledge_graph(config: EnterpriseConfig) -> KnowledgeGraphEngine:
    """Create and initialize a Knowledge Graph Engine instance"""
    return KnowledgeGraphEngine(config)

