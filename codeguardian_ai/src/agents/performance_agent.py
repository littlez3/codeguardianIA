"""
CodeGuardian AI - Performance Agent
Enterprise-grade performance analysis agent specializing in algorithm complexity analysis,
memory optimization, bottleneck detection, and scalability assessment.

This agent implements advanced performance analysis capabilities including:
- Algorithm complexity analysis (Big O notation detection)
- Memory usage optimization and leak detection
- Performance bottleneck identification
- Scalability assessment and recommendations
- Performance profiling integration
- Code optimization suggestions
"""

import re
import ast
import json
import time
import psutil
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass
from pathlib import Path
import hashlib

from .base_agent import BaseAgent, AgentCapability, AnalysisTask
from ..config.enterprise_config import EnterpriseConfig


@dataclass
class PerformanceIssue:
    """Represents a performance issue found in code."""
    issue_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # e.g., "complexity", "memory", "bottleneck", "scalability"
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    impact: str  # PERFORMANCE, SCALABILITY, MEMORY, CPU
    confidence: float = 0.0
    remediation: Optional[str] = None
    complexity_class: str = "UNKNOWN"  # O(1), O(log n), O(n), O(n²), etc.
    performance_impact: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    optimization_potential: str = "MEDIUM"  # LOW, MEDIUM, HIGH
    
    def __post_init__(self):
        pass


@dataclass
class PerformanceMetrics:
    """Comprehensive performance metrics."""
    complexity_score: float
    memory_efficiency_score: float
    cpu_efficiency_score: float
    scalability_score: float
    bottleneck_count: int
    optimization_opportunities: int
    overall_performance_score: float
    estimated_improvement_potential: float


@dataclass
class AlgorithmComplexity:
    """Represents algorithm complexity analysis."""
    function_name: str
    time_complexity: str  # Big O notation
    space_complexity: str  # Big O notation
    complexity_class: str  # CONSTANT, LOGARITHMIC, LINEAR, QUADRATIC, etc.
    confidence: float
    optimization_suggestions: List[str]
    critical_operations: List[str]


@dataclass
class PerformanceBottleneck:
    """Represents a performance bottleneck."""
    location: str
    bottleneck_type: str  # CPU, MEMORY, IO, NETWORK, DATABASE
    severity: str
    description: str
    impact_estimation: str
    optimization_suggestions: List[str]


class PerformanceAgent(BaseAgent):
    """
    Specialized agent for comprehensive performance analysis and optimization.
    
    This agent provides enterprise-grade performance analysis capabilities including
    algorithm complexity detection, memory optimization, bottleneck identification,
    and scalability assessment.
    """
    
    # Performance anti-patterns
    PERFORMANCE_ANTI_PATTERNS = {
        'nested_loops': [
            r'for\s+\w+\s+in\s+.*:\s*\n\s*for\s+\w+\s+in\s+.*:',
            r'while\s+.*:\s*\n\s*while\s+.*:',
            r'for\s+.*:\s*\n\s*.*for\s+.*:'
        ],
        'inefficient_data_structures': [
            r'\.append\s*\(\s*.*\s*\)\s*.*for\s+.*in\s+.*',  # List comprehension opportunity
            r'list\s*\(\s*.*\s*\)\s*\[\s*0\s*\]',  # Inefficient first element access
            r'len\s*\(\s*.*\s*\)\s*==\s*0',  # Inefficient empty check
            r'.*\s+in\s+.*\.keys\s*\(\s*\)'  # Inefficient dict key check
        ],
        'string_concatenation': [
            r'\+\s*=\s*.*\+\s*.*',  # String concatenation in loop
            r'.*\s*\+\s*.*\s*\+\s*.*\s*\+.*'  # Multiple string concatenations
        ],
        'database_queries_in_loops': [
            r'for\s+.*:\s*\n\s*.*\.execute\s*\(',
            r'for\s+.*:\s*\n\s*.*\.query\s*\(',
            r'for\s+.*:\s*\n\s*.*\.get\s*\(',
            r'for\s+.*:\s*\n\s*.*\.filter\s*\('
        ],
        'memory_leaks': [
            r'global\s+.*\[\s*\]',  # Global list that might grow
            r'cache\s*=\s*\{\s*\}',  # Unbounded cache
            r'.*\.append\s*\(.*\).*(?!.*\.clear\(\))',  # Append without clear
        ],
        'inefficient_algorithms': [
            r'sorted\s*\(\s*.*\s*\)\s*\[\s*0\s*\]',  # Sorting for min/max
            r'list\s*\(\s*set\s*\(\s*.*\s*\)\s*\)',  # Inefficient deduplication
            r'.*\.sort\s*\(\s*\).*\[\s*0\s*\]'  # Sort for first element
        ],
        'blocking_operations': [
            r'time\.sleep\s*\(',
            r'requests\.get\s*\(',
            r'urllib\..*\.open\s*\(',
            r'socket\..*\.connect\s*\('
        ]
    }
    
    # Complexity patterns (simplified heuristics)
    COMPLEXITY_PATTERNS = {
        'O(1)': [
            r'return\s+.*',
            r'.*\[\s*\d+\s*\]',  # Direct array access
            r'.*\.get\s*\(\s*.*\s*\)'  # Dict get
        ],
        'O(log n)': [
            r'binary.*search',
            r'bisect\.',
            r'heapq\.',
            r'.*\/\/\s*2',  # Division by 2 (binary search pattern)
        ],
        'O(n)': [
            r'for\s+.*in\s+.*:(?!\s*\n\s*for)',  # Single loop
            r'sum\s*\(',
            r'max\s*\(',
            r'min\s*\(',
            r'.*\.count\s*\(',
            r'.*\.index\s*\('
        ],
        'O(n log n)': [
            r'sorted\s*\(',
            r'.*\.sort\s*\(',
            r'merge.*sort',
            r'quick.*sort',
            r'heap.*sort'
        ],
        'O(n²)': [
            r'for\s+.*in\s+.*:\s*\n\s*for\s+.*in\s+.*:',  # Nested loops
            r'.*\.sort\s*\(.*bubble.*\)',
            r'.*\.sort\s*\(.*insertion.*\)'
        ],
        'O(2^n)': [
            r'fibonacci.*recursive',
            r'def\s+.*\(.*\):\s*\n\s*.*\(\s*.*-1\s*\).*\(\s*.*-2\s*\)',  # Recursive pattern
        ],
        'O(n!)': [
            r'permutation',
            r'factorial',
            r'itertools\.permutations'
        ]
    }
    
    # Memory optimization patterns
    MEMORY_PATTERNS = {
        'memory_inefficient': [
            r'.*\[\s*:\s*\]',  # Full list copy
            r'list\s*\(\s*.*\s*\)',  # Unnecessary list conversion
            r'.*\*\s*\d+',  # List multiplication
            r'range\s*\(\s*\d{6,}\s*\)'  # Large range
        ],
        'generator_opportunities': [
            r'\[\s*.*for\s+.*in\s+.*\]',  # List comprehension that could be generator
            r'sum\s*\(\s*\[.*for.*in.*\]\s*\)',  # Sum of list comprehension
        ],
        'caching_opportunities': [
            r'def\s+.*\(.*\):\s*\n\s*.*expensive.*operation',
            r'def\s+.*\(.*\):\s*\n\s*.*database.*query',
            r'def\s+.*\(.*\):\s*\n\s*.*api.*call'
        ]
    }
    
    # I/O and network patterns
    IO_PATTERNS = {
        'synchronous_io': [
            r'open\s*\(',
            r'requests\.get\s*\(',
            r'urllib\..*\.urlopen\s*\(',
            r'socket\..*\.recv\s*\('
        ],
        'inefficient_file_operations': [
            r'for\s+.*in\s+.*:\s*\n\s*.*open\s*\(',  # File open in loop
            r'.*\.read\s*\(\s*\)\s*\.split\s*\(',  # Read entire file then split
            r'.*\.readlines\s*\(\s*\)\s*\[\s*0\s*\]'  # Read all lines for first
        ],
        'database_inefficiencies': [
            r'for\s+.*:\s*\n\s*.*\.execute\s*\(',  # Query in loop
            r'SELECT\s+\*\s+FROM',  # Select all columns
            r'.*\.fetchall\s*\(\s*\)\s*\[\s*0\s*\]'  # Fetch all for one
        ]
    }
    
    def __init__(self, agent_id: str, config: EnterpriseConfig, **kwargs):
        """Initialize the Performance Agent with specialized capabilities."""
        super().__init__(agent_id, "performance", config, **kwargs)
        
        # Initialize performance-specific components
        self.complexity_cache = {}
        self.performance_thresholds = {
            'max_complexity': 'O(n²)',
            'max_nesting_depth': 3,
            'max_function_length': 50,
            'memory_efficiency_threshold': 80.0
        }
        self.optimization_suggestions = {}
        
        # Load performance knowledge base
        self._load_performance_knowledge()
        
        self.logger.info("Performance Agent initialized with advanced algorithm and optimization analysis capabilities")
    
    def _initialize_capabilities(self) -> None:
        """Initialize performance-specific capabilities."""
        capabilities = [
            AgentCapability(
                name="algorithm_complexity_analysis",
                description="Algorithm complexity analysis with Big O notation detection",
                confidence_level=0.91
            ),
            AgentCapability(
                name="memory_optimization_analysis",
                description="Memory usage optimization and leak detection",
                confidence_level=0.89
            ),
            AgentCapability(
                name="performance_bottleneck_detection",
                description="Performance bottleneck identification and analysis",
                confidence_level=0.93
            ),
            AgentCapability(
                name="scalability_assessment",
                description="Code scalability assessment and recommendations",
                confidence_level=0.87
            ),
            AgentCapability(
                name="cpu_optimization_analysis",
                description="CPU usage optimization and efficiency analysis",
                confidence_level=0.88
            ),
            AgentCapability(
                name="io_performance_analysis",
                description="I/O operations performance analysis and optimization",
                confidence_level=0.86
            ),
            AgentCapability(
                name="caching_strategy_analysis",
                description="Caching strategy analysis and optimization recommendations",
                confidence_level=0.85
            ),
            AgentCapability(
                name="concurrency_analysis",
                description="Concurrency and parallelization opportunity analysis",
                confidence_level=0.84
            )
        ]
        
        for capability in capabilities:
            self.add_capability(capability)
    
    def _load_performance_knowledge(self) -> None:
        """Load performance optimization patterns and best practices."""
        try:
            # Load optimization strategies
            self.optimization_strategies = {
                'algorithm_optimization': {
                    'use_appropriate_data_structures': True,
                    'avoid_nested_loops': True,
                    'use_built_in_functions': True,
                    'implement_caching': True
                },
                'memory_optimization': {
                    'use_generators': True,
                    'avoid_global_variables': True,
                    'implement_object_pooling': True,
                    'use_slots_for_classes': True
                },
                'io_optimization': {
                    'use_async_operations': True,
                    'implement_connection_pooling': True,
                    'use_batch_operations': True,
                    'implement_lazy_loading': True
                }
            }
            
            # Load performance benchmarks
            self.performance_benchmarks = {
                'response_time': {
                    'excellent': 100,  # ms
                    'good': 500,
                    'acceptable': 1000,
                    'poor': 5000
                },
                'memory_usage': {
                    'excellent': 50,  # MB
                    'good': 100,
                    'acceptable': 200,
                    'poor': 500
                },
                'cpu_usage': {
                    'excellent': 10,  # %
                    'good': 25,
                    'acceptable': 50,
                    'poor': 80
                }
            }
            
            self.logger.info("Performance knowledge base loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to load performance knowledge: {str(e)}")
    
    async def analyze(self, task: AnalysisTask) -> Dict[str, Any]:
        """
        Perform comprehensive performance analysis on the provided code.
        
        Args:
            task: Analysis task containing code and context
            
        Returns:
            Dictionary containing performance analysis results
        """
        try:
            content = task.payload.get('content', task.payload.get('code', ''))
            file_type = task.payload.get('file_type', 'python')
            file_path = task.payload.get('file_path', 'unknown')
            
            if not content:
                raise ValueError("No content provided for performance analysis")
            
            self.logger.info(f"Starting performance analysis for {file_path}")
            
            # Perform comprehensive performance analysis
            results = {
                "analysis_type": "performance",
                "agent_id": self.agent_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "file_path": file_path,
                "file_type": file_type,
                "performance_issues": [],
                "complexity_analysis": {},
                "memory_analysis": {},
                "bottleneck_analysis": {},
                "scalability_analysis": {},
                "optimization_opportunities": [],
                "performance_metrics": {},
                "recommendations": [],
                "summary": {}
            }
            
            # 1. Algorithm Complexity Analysis
            complexity_analysis = await self._analyze_algorithm_complexity(content, file_path)
            results["complexity_analysis"] = complexity_analysis
            results["performance_issues"].extend(complexity_analysis.get("issues", []))
            
            # 2. Memory Usage Analysis
            memory_analysis = await self._analyze_memory_usage(content, file_path)
            results["memory_analysis"] = memory_analysis
            results["performance_issues"].extend(memory_analysis.get("issues", []))
            
            # 3. Performance Bottleneck Detection
            bottleneck_analysis = await self._detect_performance_bottlenecks(content, file_path)
            results["bottleneck_analysis"] = bottleneck_analysis
            results["performance_issues"].extend(bottleneck_analysis.get("issues", []))
            
            # 4. Scalability Assessment
            scalability_analysis = await self._assess_scalability(content, file_path)
            results["scalability_analysis"] = scalability_analysis
            results["performance_issues"].extend(scalability_analysis.get("issues", []))
            
            # 5. I/O Performance Analysis
            io_analysis = await self._analyze_io_performance(content, file_path)
            results["io_analysis"] = io_analysis
            results["performance_issues"].extend(io_analysis.get("issues", []))
            
            # 6. Generate Optimization Opportunities
            optimization_opportunities = await self._identify_optimization_opportunities(
                content, file_path, results["performance_issues"]
            )
            results["optimization_opportunities"] = optimization_opportunities
            
            # 7. Calculate Performance Metrics
            performance_metrics = await self._calculate_performance_metrics(
                content, results["performance_issues"]
            )
            results["performance_metrics"] = performance_metrics
            
            # 8. Generate Recommendations
            recommendations = await self._generate_performance_recommendations(
                results["performance_issues"], performance_metrics
            )
            results["recommendations"] = recommendations
            
            # 9. Generate Summary
            results["summary"] = self._generate_performance_summary(results)
            
            self.logger.info(f"Performance analysis completed. Found {len(results['performance_issues'])} issues")
            
            return {
                "success": True,
                "data": results,
                "meta": {
                    "analysis_time": (datetime.now(timezone.utc) - datetime.fromisoformat(results["timestamp"])).total_seconds(),
                    "issues_found": len(results["performance_issues"]),
                    "complexity_score": complexity_analysis.get("complexity_score", 0),
                    "memory_score": memory_analysis.get("memory_score", 0),
                    "scalability_score": scalability_analysis.get("scalability_score", 0),
                    "optimization_potential": len(optimization_opportunities)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Performance analysis failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "data": None
            }
    
    async def _analyze_algorithm_complexity(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze algorithm complexity and detect inefficient patterns."""
        issues = []
        complexity_data = {
            "functions": [],
            "complexity_distribution": {},
            "complexity_score": 0,
            "issues": issues,
            "recommendations": []
        }
        
        try:
            # Extract functions for complexity analysis
            functions = self._extract_functions_with_body(content)
            
            for func in functions:
                func_complexity = self._analyze_function_complexity(func, file_path)
                complexity_data["functions"].append(func_complexity)
                
                # Check for high complexity
                if func_complexity["time_complexity"] in ["O(n²)", "O(2^n)", "O(n!)"]:
                    issue = PerformanceIssue(
                        issue_id=f"PERF_HIGH_COMPLEXITY_{hashlib.md5(f'{file_path}:{func['line']}'.encode()).hexdigest()[:8]}",
                        severity="HIGH",
                        category="complexity",
                        title=f"High Algorithm Complexity: {func_complexity['time_complexity']}",
                        description=f"Function '{func['name']}' has {func_complexity['time_complexity']} complexity",
                        file_path=file_path,
                        line_number=func["line"],
                        code_snippet=func["signature"],
                        impact="PERFORMANCE",
                        confidence=func_complexity["confidence"],
                        remediation=f"Optimize algorithm to reduce complexity from {func_complexity['time_complexity']}",
                        complexity_class=func_complexity["time_complexity"],
                        performance_impact="HIGH",
                        optimization_potential="HIGH"
                    )
                    issues.append(issue)
            
            # Detect nested loops (O(n²) or worse)
            nested_loop_patterns = self.PERFORMANCE_ANTI_PATTERNS['nested_loops']
            for pattern in nested_loop_patterns:
                matches = re.finditer(pattern, content, re.MULTILINE | re.DOTALL)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    
                    issue = PerformanceIssue(
                        issue_id=f"PERF_NESTED_LOOPS_{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                        severity="HIGH",
                        category="complexity",
                        title="Nested Loops Detected",
                        description="Nested loops can lead to O(n²) or worse complexity",
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=content.split('\n')[line_num-1] if line_num <= len(content.split('\n')) else "",
                        impact="PERFORMANCE",
                        confidence=0.9,
                        remediation="Consider using more efficient algorithms or data structures",
                        complexity_class="O(n²)",
                        performance_impact="HIGH",
                        optimization_potential="HIGH"
                    )
                    issues.append(issue)
            
            # Calculate complexity distribution
            complexity_counts = {}
            for func in complexity_data["functions"]:
                complexity = func["time_complexity"]
                complexity_counts[complexity] = complexity_counts.get(complexity, 0) + 1
            
            complexity_data["complexity_distribution"] = complexity_counts
            
            # Calculate overall complexity score
            complexity_data["complexity_score"] = self._calculate_complexity_score(
                complexity_data["functions"], issues
            )
            
            # Generate complexity recommendations
            complexity_data["recommendations"] = self._generate_complexity_recommendations(issues)
            
        except Exception as e:
            self.logger.warning(f"Algorithm complexity analysis failed: {str(e)}")
        
        return complexity_data
    
    async def _analyze_memory_usage(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze memory usage patterns and detect inefficiencies."""
        issues = []
        memory_data = {
            "memory_issues": [],
            "optimization_opportunities": [],
            "memory_score": 0,
            "issues": issues,
            "recommendations": []
        }
        
        try:
            # Check for memory inefficient patterns
            for category, patterns in self.MEMORY_PATTERNS.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.MULTILINE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        
                        issue = PerformanceIssue(
                            issue_id=f"PERF_MEMORY_{category.upper()}_{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                            severity=self._get_memory_issue_severity(category),
                            category="memory",
                            title=f"Memory Issue: {category.replace('_', ' ').title()}",
                            description=f"Detected {category} pattern that may impact memory usage",
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=content.split('\n')[line_num-1] if line_num <= len(content.split('\n')) else "",
                            impact="MEMORY",
                            confidence=0.8,
                            remediation=self._get_memory_remediation(category),
                            performance_impact="MEDIUM",
                            optimization_potential="HIGH"
                        )
                        issues.append(issue)
            
            # Check for potential memory leaks
            memory_leak_patterns = self.PERFORMANCE_ANTI_PATTERNS['memory_leaks']
            for pattern in memory_leak_patterns:
                matches = re.finditer(pattern, content, re.MULTILINE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    
                    issue = PerformanceIssue(
                        issue_id=f"PERF_MEMORY_LEAK_{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                        severity="HIGH",
                        category="memory",
                        title="Potential Memory Leak",
                        description="Pattern that may lead to memory leaks",
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=content.split('\n')[line_num-1] if line_num <= len(content.split('\n')) else "",
                        impact="MEMORY",
                        confidence=0.7,
                        remediation="Implement proper memory management and cleanup",
                        performance_impact="HIGH",
                        optimization_potential="HIGH"
                    )
                    issues.append(issue)
            
            # Calculate memory score
            memory_data["memory_score"] = self._calculate_memory_score(issues)
            
            # Generate memory recommendations
            memory_data["recommendations"] = self._generate_memory_recommendations(issues)
            
        except Exception as e:
            self.logger.warning(f"Memory usage analysis failed: {str(e)}")
        
        return memory_data
    
    async def _detect_performance_bottlenecks(self, content: str, file_path: str) -> Dict[str, Any]:
        """Detect performance bottlenecks in code."""
        issues = []
        bottleneck_data = {
            "bottlenecks": [],
            "bottleneck_score": 0,
            "issues": issues,
            "recommendations": []
        }
        
        try:
            # Check for blocking operations
            blocking_patterns = self.PERFORMANCE_ANTI_PATTERNS['blocking_operations']
            for pattern in blocking_patterns:
                matches = re.finditer(pattern, content, re.MULTILINE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    
                    issue = PerformanceIssue(
                        issue_id=f"PERF_BLOCKING_{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                        severity="MEDIUM",
                        category="bottleneck",
                        title="Blocking Operation Detected",
                        description="Synchronous operation that may block execution",
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=content.split('\n')[line_num-1] if line_num <= len(content.split('\n')) else "",
                        impact="PERFORMANCE",
                        confidence=0.8,
                        remediation="Consider using asynchronous operations",
                        performance_impact="MEDIUM",
                        optimization_potential="HIGH"
                    )
                    issues.append(issue)
            
            # Check for database queries in loops
            db_loop_patterns = self.PERFORMANCE_ANTI_PATTERNS['database_queries_in_loops']
            for pattern in db_loop_patterns:
                matches = re.finditer(pattern, content, re.MULTILINE | re.DOTALL)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    
                    issue = PerformanceIssue(
                        issue_id=f"PERF_DB_LOOP_{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                        severity="HIGH",
                        category="bottleneck",
                        title="Database Query in Loop",
                        description="Database query inside loop can cause N+1 problem",
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=content.split('\n')[line_num-1] if line_num <= len(content.split('\n')) else "",
                        impact="PERFORMANCE",
                        confidence=0.9,
                        remediation="Use batch queries or optimize database access",
                        performance_impact="HIGH",
                        optimization_potential="HIGH"
                    )
                    issues.append(issue)
            
            # Check for inefficient algorithms
            inefficient_patterns = self.PERFORMANCE_ANTI_PATTERNS['inefficient_algorithms']
            for pattern in inefficient_patterns:
                matches = re.finditer(pattern, content, re.MULTILINE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    
                    issue = PerformanceIssue(
                        issue_id=f"PERF_INEFFICIENT_{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                        severity="MEDIUM",
                        category="bottleneck",
                        title="Inefficient Algorithm Pattern",
                        description="Algorithm pattern that can be optimized",
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=content.split('\n')[line_num-1] if line_num <= len(content.split('\n')) else "",
                        impact="PERFORMANCE",
                        confidence=0.8,
                        remediation="Use more efficient algorithms or built-in functions",
                        performance_impact="MEDIUM",
                        optimization_potential="HIGH"
                    )
                    issues.append(issue)
            
            # Calculate bottleneck score
            bottleneck_data["bottleneck_score"] = self._calculate_bottleneck_score(issues)
            
            # Generate bottleneck recommendations
            bottleneck_data["recommendations"] = self._generate_bottleneck_recommendations(issues)
            
        except Exception as e:
            self.logger.warning(f"Performance bottleneck detection failed: {str(e)}")
        
        return bottleneck_data
    
    async def _assess_scalability(self, content: str, file_path: str) -> Dict[str, Any]:
        """Assess code scalability and identify scaling issues."""
        issues = []
        scalability_data = {
            "scalability_issues": [],
            "scalability_score": 0,
            "scaling_recommendations": [],
            "issues": issues,
            "recommendations": []
        }
        
        try:
            # Check for scalability anti-patterns
            scalability_patterns = {
                'global_state': [
                    r'global\s+\w+',
                    r'^\s*\w+\s*=\s*\[\s*\]',  # Global list
                    r'^\s*\w+\s*=\s*\{\s*\}'   # Global dict
                ],
                'hardcoded_limits': [
                    r'range\s*\(\s*\d{4,}\s*\)',  # Large hardcoded range
                    r'.*\[\s*:\s*\d{4,}\s*\]',    # Large slice
                    r'.*\*\s*\d{4,}'              # Large multiplication
                ],
                'synchronous_processing': [
                    r'for\s+.*in\s+.*:\s*\n\s*.*process\s*\(',
                    r'for\s+.*in\s+.*:\s*\n\s*.*handle\s*\(',
                    r'map\s*\(\s*.*,\s*.*\)'
                ]
            }
            
            for category, patterns in scalability_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.MULTILINE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        
                        issue = PerformanceIssue(
                            issue_id=f"PERF_SCALABILITY_{category.upper()}_{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                            severity=self._get_scalability_issue_severity(category),
                            category="scalability",
                            title=f"Scalability Issue: {category.replace('_', ' ').title()}",
                            description=f"Pattern that may impact scalability: {category}",
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=content.split('\n')[line_num-1] if line_num <= len(content.split('\n')) else "",
                            impact="SCALABILITY",
                            confidence=0.7,
                            remediation=self._get_scalability_remediation(category),
                            performance_impact="MEDIUM",
                            optimization_potential="MEDIUM"
                        )
                        issues.append(issue)
            
            # Calculate scalability score
            scalability_data["scalability_score"] = self._calculate_scalability_score(issues)
            
            # Generate scalability recommendations
            scalability_data["recommendations"] = self._generate_scalability_recommendations(issues)
            
        except Exception as e:
            self.logger.warning(f"Scalability assessment failed: {str(e)}")
        
        return scalability_data
    
    async def _analyze_io_performance(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze I/O performance patterns."""
        issues = []
        io_data = {
            "io_issues": [],
            "io_score": 0,
            "issues": issues,
            "recommendations": []
        }
        
        try:
            # Check for I/O performance patterns
            for category, patterns in self.IO_PATTERNS.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.MULTILINE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        
                        issue = PerformanceIssue(
                            issue_id=f"PERF_IO_{category.upper()}_{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                            severity=self._get_io_issue_severity(category),
                            category="io_performance",
                            title=f"I/O Performance Issue: {category.replace('_', ' ').title()}",
                            description=f"I/O pattern that may impact performance: {category}",
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=content.split('\n')[line_num-1] if line_num <= len(content.split('\n')) else "",
                            impact="PERFORMANCE",
                            confidence=0.8,
                            remediation=self._get_io_remediation(category),
                            performance_impact="MEDIUM",
                            optimization_potential="HIGH"
                        )
                        issues.append(issue)
            
            # Calculate I/O score
            io_data["io_score"] = self._calculate_io_score(issues)
            
            # Generate I/O recommendations
            io_data["recommendations"] = self._generate_io_recommendations(issues)
            
        except Exception as e:
            self.logger.warning(f"I/O performance analysis failed: {str(e)}")
        
        return io_data
    
    async def _identify_optimization_opportunities(self, content: str, file_path: str, issues: List[PerformanceIssue]) -> List[Dict[str, Any]]:
        """Identify optimization opportunities based on analysis."""
        opportunities = []
        
        try:
            # Group issues by optimization potential
            high_potential = [i for i in issues if i.optimization_potential == "HIGH"]
            medium_potential = [i for i in issues if i.optimization_potential == "MEDIUM"]
            
            # Algorithm optimization opportunities
            complexity_issues = [i for i in issues if i.category == "complexity"]
            if complexity_issues:
                opportunities.append({
                    "category": "algorithm_optimization",
                    "priority": "HIGH",
                    "title": "Algorithm Complexity Optimization",
                    "description": f"Found {len(complexity_issues)} algorithm complexity issues",
                    "potential_improvement": "50-90% performance improvement",
                    "effort_estimation": "Medium to High",
                    "techniques": ["Use efficient data structures", "Optimize algorithms", "Reduce complexity"]
                })
            
            # Memory optimization opportunities
            memory_issues = [i for i in issues if i.category == "memory"]
            if memory_issues:
                opportunities.append({
                    "category": "memory_optimization",
                    "priority": "HIGH",
                    "title": "Memory Usage Optimization",
                    "description": f"Found {len(memory_issues)} memory optimization opportunities",
                    "potential_improvement": "30-70% memory reduction",
                    "effort_estimation": "Low to Medium",
                    "techniques": ["Use generators", "Implement caching", "Optimize data structures"]
                })
            
            # I/O optimization opportunities
            io_issues = [i for i in issues if i.category == "io_performance"]
            if io_issues:
                opportunities.append({
                    "category": "io_optimization",
                    "priority": "MEDIUM",
                    "title": "I/O Performance Optimization",
                    "description": f"Found {len(io_issues)} I/O optimization opportunities",
                    "potential_improvement": "40-80% I/O performance improvement",
                    "effort_estimation": "Medium",
                    "techniques": ["Use async operations", "Implement connection pooling", "Batch operations"]
                })
            
        except Exception as e:
            self.logger.warning(f"Optimization opportunity identification failed: {str(e)}")
        
        return opportunities
    
    async def _calculate_performance_metrics(self, content: str, issues: List[PerformanceIssue]) -> Dict[str, Any]:
        """Calculate comprehensive performance metrics."""
        try:
            # Count issues by category
            complexity_issues = len([i for i in issues if i.category == "complexity"])
            memory_issues = len([i for i in issues if i.category == "memory"])
            bottleneck_issues = len([i for i in issues if i.category == "bottleneck"])
            scalability_issues = len([i for i in issues if i.category == "scalability"])
            
            # Calculate scores
            complexity_score = max(0, 100 - complexity_issues * 20)
            memory_score = max(0, 100 - memory_issues * 15)
            bottleneck_score = max(0, 100 - bottleneck_issues * 25)
            scalability_score = max(0, 100 - scalability_issues * 18)
            
            # Calculate overall performance score
            overall_score = (complexity_score + memory_score + bottleneck_score + scalability_score) / 4
            
            # Estimate improvement potential
            high_impact_issues = len([i for i in issues if i.performance_impact == "HIGH"])
            improvement_potential = min(100, high_impact_issues * 15)
            
            return {
                "complexity_score": complexity_score,
                "memory_efficiency_score": memory_score,
                "bottleneck_score": bottleneck_score,
                "scalability_score": scalability_score,
                "overall_performance_score": overall_score,
                "total_issues": len(issues),
                "high_impact_issues": high_impact_issues,
                "optimization_opportunities": len([i for i in issues if i.optimization_potential == "HIGH"]),
                "estimated_improvement_potential": improvement_potential,
                "performance_grade": self._get_performance_grade(overall_score)
            }
            
        except Exception as e:
            self.logger.warning(f"Performance metrics calculation failed: {str(e)}")
            return {}
    
    async def _generate_performance_recommendations(self, issues: List[PerformanceIssue], metrics: Dict[str, Any]) -> List[str]:
        """Generate performance optimization recommendations."""
        recommendations = []
        
        try:
            # Algorithm recommendations
            complexity_issues = [i for i in issues if i.category == "complexity"]
            if complexity_issues:
                recommendations.append("Optimize algorithm complexity using efficient data structures")
                recommendations.append("Replace nested loops with more efficient algorithms")
            
            # Memory recommendations
            memory_issues = [i for i in issues if i.category == "memory"]
            if memory_issues:
                recommendations.append("Implement memory optimization techniques")
                recommendations.append("Use generators instead of lists where appropriate")
                recommendations.append("Implement proper caching strategies")
            
            # Bottleneck recommendations
            bottleneck_issues = [i for i in issues if i.category == "bottleneck"]
            if bottleneck_issues:
                recommendations.append("Address performance bottlenecks with async operations")
                recommendations.append("Optimize database queries and reduce N+1 problems")
            
            # Scalability recommendations
            scalability_issues = [i for i in issues if i.category == "scalability"]
            if scalability_issues:
                recommendations.append("Improve code scalability with better architecture")
                recommendations.append("Implement horizontal scaling patterns")
            
            # General recommendations
            recommendations.extend([
                "Profile code to identify actual performance bottlenecks",
                "Implement performance monitoring and alerting",
                "Use appropriate caching strategies",
                "Consider using compiled extensions for CPU-intensive operations",
                "Implement connection pooling for database operations"
            ])
            
        except Exception as e:
            self.logger.warning(f"Performance recommendations generation failed: {str(e)}")
        
        return recommendations
    
    def _generate_performance_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive performance analysis summary."""
        try:
            issues = results.get("performance_issues", [])
            metrics = results.get("performance_metrics", {})
            
            summary = {
                "total_issues": len(issues),
                "severity_breakdown": {
                    "CRITICAL": len([i for i in issues if i.severity == "CRITICAL"]),
                    "HIGH": len([i for i in issues if i.severity == "HIGH"]),
                    "MEDIUM": len([i for i in issues if i.severity == "MEDIUM"]),
                    "LOW": len([i for i in issues if i.severity == "LOW"])
                },
                "category_breakdown": {},
                "overall_performance_score": metrics.get("overall_performance_score", 0),
                "performance_grade": metrics.get("performance_grade", "C"),
                "optimization_opportunities": metrics.get("optimization_opportunities", 0),
                "improvement_potential": metrics.get("estimated_improvement_potential", 0),
                "top_recommendations": results.get("recommendations", [])[:5],
                "critical_issues": [i.title for i in issues if i.severity in ["CRITICAL", "HIGH"]][:3]
            }
            
            # Calculate category breakdown
            for issue in issues:
                category = issue.category
                summary["category_breakdown"][category] = summary["category_breakdown"].get(category, 0) + 1
            
            return summary
            
        except Exception as e:
            self.logger.warning(f"Performance summary generation failed: {str(e)}")
            return {}
    
    # Helper methods
    def _extract_functions_with_body(self, content: str) -> List[Dict[str, Any]]:
        """Extract function definitions with their bodies."""
        functions = []
        
        try:
            tree = ast.parse(content)
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    functions.append({
                        "name": node.name,
                        "line": node.lineno,
                        "signature": f"def {node.name}(...)",
                        "body_lines": node.end_lineno - node.lineno if hasattr(node, 'end_lineno') else 10
                    })
        except:
            # Fallback to regex if AST parsing fails
            matches = re.finditer(r'def\s+(\w+)\s*\([^)]*\):', content)
            for match in matches:
                functions.append({
                    "name": match.group(1),
                    "line": content[:match.start()].count('\n') + 1,
                    "signature": match.group(0),
                    "body_lines": 10  # Estimate
                })
        
        return functions
    
    def _analyze_function_complexity(self, func: Dict[str, Any], file_path: str) -> Dict[str, Any]:
        """Analyze complexity of a single function."""
        # Simplified complexity analysis
        complexity_analysis = {
            "function_name": func["name"],
            "time_complexity": "O(n)",  # Default assumption
            "space_complexity": "O(1)",  # Default assumption
            "confidence": 0.5,
            "complexity_factors": [],
            "optimization_suggestions": []
        }
        
        # This would be much more sophisticated in a real implementation
        # For now, we'll use simple heuristics based on function name and body size
        
        if func["body_lines"] > 50:
            complexity_analysis["time_complexity"] = "O(n²)"
            complexity_analysis["confidence"] = 0.6
            complexity_analysis["complexity_factors"].append("Large function body")
        
        if "sort" in func["name"].lower():
            complexity_analysis["time_complexity"] = "O(n log n)"
            complexity_analysis["confidence"] = 0.8
        
        if "search" in func["name"].lower():
            complexity_analysis["time_complexity"] = "O(log n)"
            complexity_analysis["confidence"] = 0.7
        
        return complexity_analysis
    
    # Score calculation methods
    def _calculate_complexity_score(self, functions: List[Dict], issues: List[PerformanceIssue]) -> float:
        """Calculate algorithm complexity score."""
        base_score = 100
        
        # Deduct points for complexity issues
        complexity_issues = [i for i in issues if i.category == "complexity"]
        for issue in complexity_issues:
            if issue.severity == "CRITICAL":
                base_score -= 30
            elif issue.severity == "HIGH":
                base_score -= 20
            elif issue.severity == "MEDIUM":
                base_score -= 10
        
        return max(0, base_score)
    
    def _calculate_memory_score(self, issues: List[PerformanceIssue]) -> float:
        """Calculate memory efficiency score."""
        base_score = 100
        
        memory_issues = [i for i in issues if i.category == "memory"]
        for issue in memory_issues:
            if issue.severity == "HIGH":
                base_score -= 25
            elif issue.severity == "MEDIUM":
                base_score -= 15
            elif issue.severity == "LOW":
                base_score -= 8
        
        return max(0, base_score)
    
    def _calculate_bottleneck_score(self, issues: List[PerformanceIssue]) -> float:
        """Calculate bottleneck score."""
        base_score = 100
        
        bottleneck_issues = [i for i in issues if i.category == "bottleneck"]
        for issue in bottleneck_issues:
            if issue.severity == "HIGH":
                base_score -= 30
            elif issue.severity == "MEDIUM":
                base_score -= 18
            elif issue.severity == "LOW":
                base_score -= 10
        
        return max(0, base_score)
    
    def _calculate_scalability_score(self, issues: List[PerformanceIssue]) -> float:
        """Calculate scalability score."""
        base_score = 100
        
        scalability_issues = [i for i in issues if i.category == "scalability"]
        for issue in scalability_issues:
            if issue.severity == "HIGH":
                base_score -= 25
            elif issue.severity == "MEDIUM":
                base_score -= 15
            elif issue.severity == "LOW":
                base_score -= 8
        
        return max(0, base_score)
    
    def _calculate_io_score(self, issues: List[PerformanceIssue]) -> float:
        """Calculate I/O performance score."""
        base_score = 100
        
        io_issues = [i for i in issues if i.category == "io_performance"]
        for issue in io_issues:
            if issue.severity == "HIGH":
                base_score -= 20
            elif issue.severity == "MEDIUM":
                base_score -= 12
            elif issue.severity == "LOW":
                base_score -= 6
        
        return max(0, base_score)
    
    def _get_performance_grade(self, score: float) -> str:
        """Get performance grade based on score."""
        if score >= 90:
            return "A"
        elif score >= 80:
            return "B"
        elif score >= 70:
            return "C"
        elif score >= 60:
            return "D"
        else:
            return "F"
    
    # Severity and remediation methods
    def _get_memory_issue_severity(self, category: str) -> str:
        severity_map = {
            'memory_inefficient': 'MEDIUM',
            'generator_opportunities': 'LOW',
            'caching_opportunities': 'MEDIUM'
        }
        return severity_map.get(category, 'MEDIUM')
    
    def _get_memory_remediation(self, category: str) -> str:
        remediation_map = {
            'memory_inefficient': 'Use more memory-efficient data structures and operations',
            'generator_opportunities': 'Replace list comprehensions with generators where appropriate',
            'caching_opportunities': 'Implement caching for expensive operations'
        }
        return remediation_map.get(category, 'Optimize memory usage')
    
    def _get_scalability_issue_severity(self, category: str) -> str:
        severity_map = {
            'global_state': 'HIGH',
            'hardcoded_limits': 'MEDIUM',
            'synchronous_processing': 'MEDIUM'
        }
        return severity_map.get(category, 'MEDIUM')
    
    def _get_scalability_remediation(self, category: str) -> str:
        remediation_map = {
            'global_state': 'Avoid global state and use dependency injection',
            'hardcoded_limits': 'Use configurable limits and dynamic sizing',
            'synchronous_processing': 'Implement asynchronous or parallel processing'
        }
        return remediation_map.get(category, 'Improve scalability design')
    
    def _get_io_issue_severity(self, category: str) -> str:
        severity_map = {
            'synchronous_io': 'MEDIUM',
            'inefficient_file_operations': 'HIGH',
            'database_inefficiencies': 'HIGH'
        }
        return severity_map.get(category, 'MEDIUM')
    
    def _get_io_remediation(self, category: str) -> str:
        remediation_map = {
            'synchronous_io': 'Use asynchronous I/O operations',
            'inefficient_file_operations': 'Optimize file operations and avoid repeated opens',
            'database_inefficiencies': 'Optimize database queries and use proper indexing'
        }
        return remediation_map.get(category, 'Optimize I/O operations')
    
    # Recommendation generation methods
    def _generate_complexity_recommendations(self, issues: List[PerformanceIssue]) -> List[str]:
        return [
            "Use appropriate data structures for the problem",
            "Replace nested loops with more efficient algorithms",
            "Consider using built-in functions and libraries",
            "Implement caching for expensive computations"
        ]
    
    def _generate_memory_recommendations(self, issues: List[PerformanceIssue]) -> List[str]:
        return [
            "Use generators instead of lists where possible",
            "Implement proper object lifecycle management",
            "Use memory profiling tools to identify leaks",
            "Consider using __slots__ for classes with many instances"
        ]
    
    def _generate_bottleneck_recommendations(self, issues: List[PerformanceIssue]) -> List[str]:
        return [
            "Profile code to identify actual bottlenecks",
            "Use asynchronous operations for I/O bound tasks",
            "Implement connection pooling for database operations",
            "Consider using compiled extensions for CPU-intensive tasks"
        ]
    
    def _generate_scalability_recommendations(self, issues: List[PerformanceIssue]) -> List[str]:
        return [
            "Design for horizontal scaling from the start",
            "Avoid global state and shared mutable data",
            "Implement proper caching strategies",
            "Use microservices architecture for large applications"
        ]
    
    def _generate_io_recommendations(self, issues: List[PerformanceIssue]) -> List[str]:
        return [
            "Use asynchronous I/O for better concurrency",
            "Implement connection pooling and reuse",
            "Use batch operations to reduce I/O overhead",
            "Implement proper error handling and retries"
        ]

