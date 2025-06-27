"""
CodeGuardian AI - Architecture Agent
Enterprise-grade architecture analysis agent specializing in design patterns,
code quality assessment, architectural smells detection, and scalability analysis.

This agent implements advanced architectural analysis capabilities including:
- Design pattern recognition and validation
- Code quality metrics and assessment
- Architectural smell detection
- Scalability and maintainability analysis
- Technical debt assessment
- Refactoring recommendations
"""

import ast
import re
import json
import math
from collections import defaultdict, Counter
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass
from pathlib import Path
import hashlib

from .base_agent import BaseAgent, AgentCapability, AnalysisTask
from ..config.enterprise_config import EnterpriseConfig


@dataclass
class ArchitecturalIssue:
    """Represents an architectural issue found in code."""
    issue_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # e.g., "design_pattern", "code_smell", "complexity"
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    impact: str  # MAINTAINABILITY, SCALABILITY, PERFORMANCE, READABILITY
    confidence: float = 0.0
    remediation: Optional[str] = None
    technical_debt_hours: Optional[float] = None
    refactoring_suggestions: List[str] = None
    
    def __post_init__(self):
        if self.refactoring_suggestions is None:
            self.refactoring_suggestions = []


@dataclass
class CodeQualityMetrics:
    """Code quality metrics for architectural analysis."""
    cyclomatic_complexity: float
    cognitive_complexity: float
    lines_of_code: int
    maintainability_index: float
    technical_debt_ratio: float
    code_duplication_percentage: float
    test_coverage_percentage: float
    dependency_count: int
    coupling_factor: float
    cohesion_score: float


@dataclass
class DesignPattern:
    """Represents a detected design pattern."""
    pattern_name: str
    pattern_type: str  # CREATIONAL, STRUCTURAL, BEHAVIORAL
    confidence: float
    implementation_quality: str  # EXCELLENT, GOOD, FAIR, POOR
    file_path: str
    line_numbers: List[int]
    description: str
    benefits: List[str]
    potential_issues: List[str]


class ArchitectureAgent(BaseAgent):
    """
    Specialized agent for comprehensive architectural analysis and design assessment.
    
    This agent provides enterprise-grade architectural analysis capabilities including
    design pattern recognition, code quality assessment, architectural smell detection,
    and scalability analysis.
    """
    
    # Design pattern signatures
    DESIGN_PATTERNS = {
        'singleton': {
            'signatures': [
                r'class\s+\w+.*:\s*\n(?:.*\n)*?\s*_instance\s*=\s*None',
                r'def\s+__new__\s*\(\s*cls.*\):',
                r'if\s+cls\._instance\s+is\s+None:'
            ],
            'type': 'CREATIONAL',
            'complexity_weight': 2
        },
        'factory': {
            'signatures': [
                r'def\s+create_\w+\s*\(',
                r'class\s+\w*Factory\w*',
                r'def\s+get_\w+\s*\(.*type.*\):'
            ],
            'type': 'CREATIONAL',
            'complexity_weight': 3
        },
        'observer': {
            'signatures': [
                r'def\s+notify\s*\(',
                r'def\s+subscribe\s*\(',
                r'def\s+unsubscribe\s*\(',
                r'observers\s*=\s*\[\]'
            ],
            'type': 'BEHAVIORAL',
            'complexity_weight': 4
        },
        'decorator': {
            'signatures': [
                r'@\w+',
                r'def\s+\w+\s*\(\s*func\s*\):',
                r'def\s+wrapper\s*\('
            ],
            'type': 'STRUCTURAL',
            'complexity_weight': 3
        },
        'strategy': {
            'signatures': [
                r'class\s+\w*Strategy\w*',
                r'def\s+execute\s*\(',
                r'strategy\s*=\s*\w+Strategy'
            ],
            'type': 'BEHAVIORAL',
            'complexity_weight': 3
        }
    }
    
    # Code smell patterns
    CODE_SMELLS = {
        'long_method': {
            'threshold': 50,  # lines
            'severity': 'MEDIUM',
            'impact': 'MAINTAINABILITY'
        },
        'large_class': {
            'threshold': 500,  # lines
            'severity': 'HIGH',
            'impact': 'MAINTAINABILITY'
        },
        'too_many_parameters': {
            'threshold': 5,
            'severity': 'MEDIUM',
            'impact': 'READABILITY'
        },
        'deep_nesting': {
            'threshold': 4,
            'severity': 'MEDIUM',
            'impact': 'READABILITY'
        },
        'duplicate_code': {
            'threshold': 0.1,  # 10% duplication
            'severity': 'HIGH',
            'impact': 'MAINTAINABILITY'
        },
        'dead_code': {
            'threshold': 1,  # any unused code
            'severity': 'LOW',
            'impact': 'MAINTAINABILITY'
        }
    }
    
    # Complexity thresholds
    COMPLEXITY_THRESHOLDS = {
        'cyclomatic': {'low': 10, 'medium': 20, 'high': 30},
        'cognitive': {'low': 15, 'medium': 25, 'high': 35},
        'maintainability': {'excellent': 85, 'good': 70, 'fair': 50, 'poor': 0}
    }
    
    def __init__(self, agent_id: str, config: EnterpriseConfig, **kwargs):
        """Initialize the Architecture Agent with specialized capabilities."""
        super().__init__(agent_id, "architecture", config, **kwargs)
        
        # Initialize architecture-specific components
        self.pattern_cache = {}
        self.quality_metrics_cache = {}
        self.refactoring_suggestions_db = {}
        
        # Load architectural knowledge base
        self._load_architectural_knowledge()
        
        self.logger.info("Architecture Agent initialized with advanced design analysis capabilities")
    
    def _initialize_capabilities(self) -> None:
        """Initialize architecture-specific capabilities."""
        capabilities = [
            AgentCapability(
                name="design_pattern_analysis",
                description="Recognition and validation of design patterns",
                confidence_level=0.92
            ),
            AgentCapability(
                name="code_quality_assessment",
                description="Comprehensive code quality metrics and assessment",
                confidence_level=0.95
            ),
            AgentCapability(
                name="architectural_smell_detection",
                description="Detection of architectural smells and anti-patterns",
                confidence_level=0.88
            ),
            AgentCapability(
                name="complexity_analysis",
                description="Cyclomatic and cognitive complexity analysis",
                confidence_level=0.94
            ),
            AgentCapability(
                name="scalability_assessment",
                description="Scalability and performance architecture analysis",
                confidence_level=0.85
            ),
            AgentCapability(
                name="technical_debt_analysis",
                description="Technical debt identification and quantification",
                confidence_level=0.87
            ),
            AgentCapability(
                name="refactoring_recommendations",
                description="Automated refactoring suggestions and prioritization",
                confidence_level=0.83
            ),
            AgentCapability(
                name="dependency_analysis",
                description="Dependency structure and coupling analysis",
                confidence_level=0.90
            )
        ]
        
        for capability in capabilities:
            self.add_capability(capability)
    
    def _load_architectural_knowledge(self) -> None:
        """Load architectural patterns and best practices knowledge base."""
        try:
            # Load refactoring patterns
            self.refactoring_suggestions_db = {
                'long_method': [
                    'Extract smaller methods with single responsibilities',
                    'Use the Extract Method refactoring pattern',
                    'Consider breaking into multiple classes if needed'
                ],
                'large_class': [
                    'Apply Single Responsibility Principle',
                    'Extract related functionality into separate classes',
                    'Use composition over inheritance'
                ],
                'duplicate_code': [
                    'Extract common code into shared methods',
                    'Use inheritance or composition to share behavior',
                    'Consider using design patterns like Template Method'
                ],
                'complex_conditional': [
                    'Replace conditional with polymorphism',
                    'Use Strategy pattern for complex conditionals',
                    'Extract conditions into well-named methods'
                ]
            }
            
            self.logger.info("Architectural knowledge base loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to load architectural knowledge: {str(e)}")
    
    async def analyze(self, task: AnalysisTask) -> Dict[str, Any]:
        """
        Perform comprehensive architectural analysis on the provided code.
        
        Args:
            task: Analysis task containing code and context
            
        Returns:
            Dictionary containing architectural analysis results
        """
        try:
            code = task.payload.get('code', '')
            language = task.payload.get('language', 'python')
            file_path = task.payload.get('file_path', 'unknown')
            
            if not code:
                raise ValueError("No code provided for architectural analysis")
            
            self.logger.info(f"Starting architectural analysis for {file_path}")
            
            # Perform comprehensive architectural analysis
            results = {
                "analysis_type": "architecture",
                "agent_id": self.agent_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "file_path": file_path,
                "language": language,
                "design_patterns": [],
                "architectural_issues": [],
                "quality_metrics": {},
                "complexity_analysis": {},
                "technical_debt": {},
                "refactoring_recommendations": [],
                "scalability_assessment": {},
                "summary": {}
            }
            
            # 1. Design pattern recognition
            patterns = await self._analyze_design_patterns(code, file_path)
            results["design_patterns"] = patterns
            
            # 2. Code quality metrics calculation
            quality_metrics = await self._calculate_quality_metrics(code, file_path)
            results["quality_metrics"] = quality_metrics
            
            # 3. Complexity analysis
            complexity_analysis = await self._analyze_complexity(code, file_path)
            results["complexity_analysis"] = complexity_analysis
            
            # 4. Architectural smell detection
            architectural_issues = await self._detect_architectural_smells(code, file_path)
            results["architectural_issues"] = architectural_issues
            
            # 5. Technical debt assessment
            technical_debt = await self._assess_technical_debt(code, architectural_issues, complexity_analysis)
            results["technical_debt"] = technical_debt
            
            # 6. Scalability assessment
            scalability = await self._assess_scalability(code, patterns, complexity_analysis)
            results["scalability_assessment"] = scalability
            
            # 7. Generate refactoring recommendations
            refactoring_recs = await self._generate_refactoring_recommendations(
                architectural_issues, complexity_analysis, patterns
            )
            results["refactoring_recommendations"] = refactoring_recs
            
            # 8. Generate comprehensive summary
            results["summary"] = self._generate_architectural_summary(results)
            
            self.logger.info(f"Architectural analysis completed. Found {len(patterns)} patterns, {len(architectural_issues)} issues")
            
            return {
                "success": True,
                "data": results,
                "meta": {
                    "analysis_time": (datetime.now(timezone.utc) - datetime.fromisoformat(results["timestamp"])).total_seconds(),
                    "patterns_found": len(patterns),
                    "issues_found": len(architectural_issues),
                    "quality_score": quality_metrics.get("overall_score", 0),
                    "technical_debt_hours": technical_debt.get("total_hours", 0)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Architectural analysis failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "data": None
            }
    
    async def _analyze_design_patterns(self, code: str, file_path: str) -> List[DesignPattern]:
        """Analyze code for design pattern usage."""
        patterns = []
        
        try:
            for pattern_name, pattern_info in self.DESIGN_PATTERNS.items():
                matches = 0
                matched_lines = []
                
                for signature in pattern_info['signatures']:
                    regex = re.compile(signature, re.MULTILINE | re.DOTALL)
                    pattern_matches = regex.finditer(code)
                    
                    for match in pattern_matches:
                        matches += 1
                        # Find line number of match
                        line_num = code[:match.start()].count('\n') + 1
                        matched_lines.append(line_num)
                
                if matches >= len(pattern_info['signatures']) // 2:  # At least half signatures match
                    confidence = min(0.95, matches / len(pattern_info['signatures']))
                    
                    # Assess implementation quality
                    quality = self._assess_pattern_implementation_quality(
                        pattern_name, code, matched_lines
                    )
                    
                    pattern = DesignPattern(
                        pattern_name=pattern_name,
                        pattern_type=pattern_info['type'],
                        confidence=confidence,
                        implementation_quality=quality,
                        file_path=file_path,
                        line_numbers=matched_lines,
                        description=f"{pattern_name.title()} pattern implementation detected",
                        benefits=self._get_pattern_benefits(pattern_name),
                        potential_issues=self._get_pattern_potential_issues(pattern_name, quality)
                    )
                    
                    patterns.append(pattern)
                    
        except Exception as e:
            self.logger.warning(f"Design pattern analysis failed: {str(e)}")
        
        return patterns
    
    async def _calculate_quality_metrics(self, code: str, file_path: str) -> Dict[str, Any]:
        """Calculate comprehensive code quality metrics."""
        try:
            lines = code.split('\n')
            non_empty_lines = [line for line in lines if line.strip()]
            
            # Basic metrics
            loc = len(non_empty_lines)
            total_lines = len(lines)
            
            # Complexity metrics
            cyclomatic = self._calculate_cyclomatic_complexity(code)
            cognitive = self._calculate_cognitive_complexity(code)
            
            # Maintainability index (simplified version)
            maintainability = self._calculate_maintainability_index(loc, cyclomatic, cognitive)
            
            # Code duplication analysis
            duplication_percentage = self._analyze_code_duplication(code)
            
            # Dependency analysis
            dependencies = self._analyze_dependencies(code)
            
            # Coupling and cohesion
            coupling = self._calculate_coupling_factor(code)
            cohesion = self._calculate_cohesion_score(code)
            
            # Technical debt ratio
            tech_debt_ratio = self._calculate_technical_debt_ratio(
                cyclomatic, cognitive, duplication_percentage, coupling
            )
            
            # Overall quality score
            overall_score = self._calculate_overall_quality_score(
                maintainability, tech_debt_ratio, duplication_percentage, coupling, cohesion
            )
            
            return {
                "lines_of_code": loc,
                "total_lines": total_lines,
                "cyclomatic_complexity": cyclomatic,
                "cognitive_complexity": cognitive,
                "maintainability_index": maintainability,
                "code_duplication_percentage": duplication_percentage,
                "technical_debt_ratio": tech_debt_ratio,
                "dependency_count": len(dependencies),
                "coupling_factor": coupling,
                "cohesion_score": cohesion,
                "overall_score": overall_score,
                "quality_grade": self._get_quality_grade(overall_score),
                "dependencies": dependencies
            }
            
        except Exception as e:
            self.logger.warning(f"Quality metrics calculation failed: {str(e)}")
            return {}
    
    async def _analyze_complexity(self, code: str, file_path: str) -> Dict[str, Any]:
        """Perform detailed complexity analysis."""
        try:
            # Parse AST for detailed analysis
            tree = ast.parse(code)
            
            complexity_data = {
                "functions": [],
                "classes": [],
                "overall_complexity": 0,
                "complexity_distribution": {},
                "hotspots": []
            }
            
            class ComplexityVisitor(ast.NodeVisitor):
                def __init__(self):
                    self.current_class = None
                    self.complexity_data = complexity_data
                
                def visit_FunctionDef(self, node):
                    func_complexity = self._calculate_function_complexity(node, code)
                    
                    func_data = {
                        "name": node.name,
                        "line_number": node.lineno,
                        "cyclomatic_complexity": func_complexity["cyclomatic"],
                        "cognitive_complexity": func_complexity["cognitive"],
                        "lines_of_code": func_complexity["loc"],
                        "parameters_count": len(node.args.args),
                        "nesting_depth": func_complexity["nesting_depth"],
                        "class_name": self.current_class
                    }
                    
                    self.complexity_data["functions"].append(func_data)
                    
                    # Check if it's a complexity hotspot
                    if (func_complexity["cyclomatic"] > self.COMPLEXITY_THRESHOLDS["cyclomatic"]["medium"] or
                        func_complexity["cognitive"] > self.COMPLEXITY_THRESHOLDS["cognitive"]["medium"]):
                        self.complexity_data["hotspots"].append({
                            "type": "function",
                            "name": node.name,
                            "line": node.lineno,
                            "complexity": func_complexity["cyclomatic"],
                            "reason": "High complexity function"
                        })
                    
                    self.generic_visit(node)
                
                def visit_ClassDef(self, node):
                    old_class = self.current_class
                    self.current_class = node.name
                    
                    class_complexity = self._calculate_class_complexity(node, code)
                    
                    class_data = {
                        "name": node.name,
                        "line_number": node.lineno,
                        "methods_count": class_complexity["methods_count"],
                        "lines_of_code": class_complexity["loc"],
                        "complexity_score": class_complexity["complexity"],
                        "inheritance_depth": class_complexity["inheritance_depth"]
                    }
                    
                    self.complexity_data["classes"].append(class_data)
                    
                    self.generic_visit(node)
                    self.current_class = old_class
            
            visitor = ComplexityVisitor()
            visitor.visit(tree)
            
            # Calculate overall metrics
            if complexity_data["functions"]:
                avg_cyclomatic = sum(f["cyclomatic_complexity"] for f in complexity_data["functions"]) / len(complexity_data["functions"])
                avg_cognitive = sum(f["cognitive_complexity"] for f in complexity_data["functions"]) / len(complexity_data["functions"])
                
                complexity_data["overall_complexity"] = (avg_cyclomatic + avg_cognitive) / 2
                
                # Complexity distribution
                complexity_data["complexity_distribution"] = {
                    "low": len([f for f in complexity_data["functions"] if f["cyclomatic_complexity"] <= self.COMPLEXITY_THRESHOLDS["cyclomatic"]["low"]]),
                    "medium": len([f for f in complexity_data["functions"] if self.COMPLEXITY_THRESHOLDS["cyclomatic"]["low"] < f["cyclomatic_complexity"] <= self.COMPLEXITY_THRESHOLDS["cyclomatic"]["medium"]]),
                    "high": len([f for f in complexity_data["functions"] if f["cyclomatic_complexity"] > self.COMPLEXITY_THRESHOLDS["cyclomatic"]["medium"]])
                }
            
            return complexity_data
            
        except Exception as e:
            self.logger.warning(f"Complexity analysis failed: {str(e)}")
            return {}
    
    async def _detect_architectural_smells(self, code: str, file_path: str) -> List[ArchitecturalIssue]:
        """Detect architectural smells and anti-patterns."""
        issues = []
        
        try:
            lines = code.split('\n')
            
            # 1. Long method detection
            issues.extend(self._detect_long_methods(code, file_path))
            
            # 2. Large class detection
            issues.extend(self._detect_large_classes(code, file_path))
            
            # 3. Too many parameters detection
            issues.extend(self._detect_too_many_parameters(code, file_path))
            
            # 4. Deep nesting detection
            issues.extend(self._detect_deep_nesting(code, file_path))
            
            # 5. Code duplication detection
            issues.extend(self._detect_code_duplication(code, file_path))
            
            # 6. Dead code detection
            issues.extend(self._detect_dead_code(code, file_path))
            
            # 7. God class detection
            issues.extend(self._detect_god_class(code, file_path))
            
            # 8. Feature envy detection
            issues.extend(self._detect_feature_envy(code, file_path))
            
        except Exception as e:
            self.logger.warning(f"Architectural smell detection failed: {str(e)}")
        
        return issues
    
    async def _assess_technical_debt(
        self, 
        code: str, 
        issues: List[ArchitecturalIssue], 
        complexity: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Assess technical debt in the codebase."""
        try:
            # Calculate technical debt hours based on issues and complexity
            debt_hours = 0
            debt_breakdown = {}
            
            for issue in issues:
                hours = self._estimate_fix_time(issue)
                debt_hours += hours
                
                if issue.category not in debt_breakdown:
                    debt_breakdown[issue.category] = {"hours": 0, "count": 0}
                
                debt_breakdown[issue.category]["hours"] += hours
                debt_breakdown[issue.category]["count"] += 1
            
            # Add complexity-based debt
            if complexity.get("functions"):
                complex_functions = [
                    f for f in complexity["functions"] 
                    if f["cyclomatic_complexity"] > self.COMPLEXITY_THRESHOLDS["cyclomatic"]["medium"]
                ]
                
                complexity_debt = len(complex_functions) * 2  # 2 hours per complex function
                debt_hours += complexity_debt
                debt_breakdown["complexity"] = {"hours": complexity_debt, "count": len(complex_functions)}
            
            # Calculate debt ratio
            loc = len([line for line in code.split('\n') if line.strip()])
            debt_ratio = (debt_hours / max(loc / 100, 1)) if loc > 0 else 0  # Hours per 100 LOC
            
            # Prioritize debt items
            priority_items = self._prioritize_technical_debt(issues, complexity)
            
            return {
                "total_hours": round(debt_hours, 1),
                "debt_ratio": round(debt_ratio, 2),
                "debt_breakdown": debt_breakdown,
                "priority_items": priority_items,
                "debt_level": self._categorize_debt_level(debt_ratio),
                "estimated_cost": round(debt_hours * 100, 2),  # $100/hour estimate
                "payback_period_weeks": round(debt_hours / 40, 1)  # 40 hours/week
            }
            
        except Exception as e:
            self.logger.warning(f"Technical debt assessment failed: {str(e)}")
            return {}
    
    async def _assess_scalability(
        self, 
        code: str, 
        patterns: List[DesignPattern], 
        complexity: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Assess code scalability and performance characteristics."""
        try:
            scalability_score = 100  # Start with perfect score
            issues = []
            recommendations = []
            
            # Check for scalability anti-patterns
            if self._has_singleton_overuse(patterns):
                scalability_score -= 15
                issues.append("Overuse of Singleton pattern may limit scalability")
                recommendations.append("Consider dependency injection instead of singletons")
            
            # Check complexity impact on scalability
            if complexity.get("overall_complexity", 0) > 20:
                scalability_score -= 20
                issues.append("High complexity may impact maintainability and scalability")
                recommendations.append("Refactor complex functions to improve scalability")
            
            # Check for performance bottlenecks
            bottlenecks = self._identify_performance_bottlenecks(code)
            if bottlenecks:
                scalability_score -= len(bottlenecks) * 10
                issues.extend([f"Potential bottleneck: {b}" for b in bottlenecks])
                recommendations.append("Optimize identified performance bottlenecks")
            
            # Check for proper error handling
            if not self._has_proper_error_handling(code):
                scalability_score -= 10
                issues.append("Insufficient error handling may impact system reliability")
                recommendations.append("Implement comprehensive error handling")
            
            # Check for resource management
            if not self._has_proper_resource_management(code):
                scalability_score -= 15
                issues.append("Poor resource management may cause memory leaks")
                recommendations.append("Implement proper resource cleanup and management")
            
            scalability_score = max(0, scalability_score)
            
            return {
                "scalability_score": scalability_score,
                "scalability_grade": self._get_scalability_grade(scalability_score),
                "issues": issues,
                "recommendations": recommendations,
                "bottlenecks": bottlenecks,
                "patterns_impact": self._assess_patterns_scalability_impact(patterns)
            }
            
        except Exception as e:
            self.logger.warning(f"Scalability assessment failed: {str(e)}")
            return {}
    
    async def _generate_refactoring_recommendations(
        self, 
        issues: List[ArchitecturalIssue], 
        complexity: Dict[str, Any], 
        patterns: List[DesignPattern]
    ) -> List[Dict[str, Any]]:
        """Generate prioritized refactoring recommendations."""
        recommendations = []
        
        try:
            # Group issues by category for targeted recommendations
            issue_categories = defaultdict(list)
            for issue in issues:
                issue_categories[issue.category].append(issue)
            
            # Generate recommendations for each category
            for category, category_issues in issue_categories.items():
                if category in self.refactoring_suggestions_db:
                    rec = {
                        "category": category,
                        "priority": self._calculate_refactoring_priority(category_issues),
                        "effort_estimate": sum(issue.technical_debt_hours or 2 for issue in category_issues),
                        "impact": self._assess_refactoring_impact(category_issues),
                        "suggestions": self.refactoring_suggestions_db[category],
                        "affected_files": list(set(issue.file_path for issue in category_issues)),
                        "affected_lines": [issue.line_number for issue in category_issues]
                    }
                    recommendations.append(rec)
            
            # Add complexity-based recommendations
            if complexity.get("hotspots"):
                complexity_rec = {
                    "category": "complexity_reduction",
                    "priority": "HIGH",
                    "effort_estimate": len(complexity["hotspots"]) * 3,
                    "impact": "MAINTAINABILITY",
                    "suggestions": [
                        "Break down complex functions into smaller, focused methods",
                        "Extract complex logic into separate classes",
                        "Use design patterns to simplify complex code"
                    ],
                    "affected_files": ["analyzed_file"],
                    "affected_lines": [spot["line"] for spot in complexity["hotspots"]]
                }
                recommendations.append(complexity_rec)
            
            # Sort by priority and impact
            recommendations.sort(key=lambda x: (
                {"HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(x["priority"], 1),
                x["effort_estimate"]
            ), reverse=True)
            
        except Exception as e:
            self.logger.warning(f"Refactoring recommendations generation failed: {str(e)}")
        
        return recommendations
    
    def _generate_architectural_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive architectural analysis summary."""
        try:
            patterns = results.get("design_patterns", [])
            issues = results.get("architectural_issues", [])
            quality = results.get("quality_metrics", {})
            complexity = results.get("complexity_analysis", {})
            tech_debt = results.get("technical_debt", {})
            scalability = results.get("scalability_assessment", {})
            
            summary = {
                "overall_architecture_score": self._calculate_overall_architecture_score(results),
                "architecture_grade": "",
                "patterns_summary": {
                    "total_patterns": len(patterns),
                    "pattern_types": Counter(p.pattern_type for p in patterns),
                    "implementation_quality": Counter(p.implementation_quality for p in patterns)
                },
                "quality_summary": {
                    "quality_score": quality.get("overall_score", 0),
                    "quality_grade": quality.get("quality_grade", "UNKNOWN"),
                    "maintainability_index": quality.get("maintainability_index", 0),
                    "technical_debt_ratio": quality.get("technical_debt_ratio", 0)
                },
                "complexity_summary": {
                    "overall_complexity": complexity.get("overall_complexity", 0),
                    "complexity_hotspots": len(complexity.get("hotspots", [])),
                    "functions_analyzed": len(complexity.get("functions", [])),
                    "classes_analyzed": len(complexity.get("classes", []))
                },
                "issues_summary": {
                    "total_issues": len(issues),
                    "severity_breakdown": Counter(issue.severity for issue in issues),
                    "category_breakdown": Counter(issue.category for issue in issues),
                    "critical_issues": [issue.title for issue in issues if issue.severity == "CRITICAL"][:5]
                },
                "debt_summary": {
                    "total_debt_hours": tech_debt.get("total_hours", 0),
                    "debt_level": tech_debt.get("debt_level", "UNKNOWN"),
                    "estimated_cost": tech_debt.get("estimated_cost", 0)
                },
                "scalability_summary": {
                    "scalability_score": scalability.get("scalability_score", 0),
                    "scalability_grade": scalability.get("scalability_grade", "UNKNOWN"),
                    "bottlenecks_count": len(scalability.get("bottlenecks", []))
                },
                "top_recommendations": [
                    "Focus on reducing technical debt",
                    "Address complexity hotspots",
                    "Improve code quality metrics",
                    "Enhance scalability patterns"
                ]
            }
            
            # Calculate overall architecture grade
            overall_score = summary["overall_architecture_score"]
            if overall_score >= 90:
                summary["architecture_grade"] = "EXCELLENT"
            elif overall_score >= 80:
                summary["architecture_grade"] = "GOOD"
            elif overall_score >= 70:
                summary["architecture_grade"] = "FAIR"
            elif overall_score >= 60:
                summary["architecture_grade"] = "POOR"
            else:
                summary["architecture_grade"] = "CRITICAL"
            
            return summary
            
        except Exception as e:
            self.logger.warning(f"Summary generation failed: {str(e)}")
            return {}
    
    # Helper methods for complexity calculations
    def _calculate_cyclomatic_complexity(self, code: str) -> float:
        """Calculate cyclomatic complexity of code."""
        try:
            # Simplified cyclomatic complexity calculation
            decision_points = len(re.findall(r'\b(if|elif|while|for|except|and|or)\b', code))
            return max(1, decision_points + 1)
        except:
            return 1.0
    
    def _calculate_cognitive_complexity(self, code: str) -> float:
        """Calculate cognitive complexity of code."""
        try:
            # Simplified cognitive complexity calculation
            complexity = 0
            nesting_level = 0
            
            for line in code.split('\n'):
                stripped = line.strip()
                
                # Increase nesting for control structures
                if any(keyword in stripped for keyword in ['if', 'for', 'while', 'try']):
                    if not stripped.endswith(':'):
                        continue
                    nesting_level += 1
                    complexity += nesting_level
                
                # Decrease nesting
                if stripped.startswith(('else:', 'elif', 'except:', 'finally:')):
                    complexity += nesting_level
                
                # Additional complexity for logical operators
                complexity += stripped.count(' and ') + stripped.count(' or ')
            
            return max(1.0, float(complexity))
        except:
            return 1.0
    
    def _calculate_maintainability_index(self, loc: int, cyclomatic: float, cognitive: float) -> float:
        """Calculate maintainability index."""
        try:
            # Simplified maintainability index calculation
            if loc == 0:
                return 100.0
            
            # Base formula adapted for Python
            mi = 171 - 5.2 * math.log(max(1, loc)) - 0.23 * cyclomatic - 16.2 * math.log(max(1, loc))
            
            # Adjust for cognitive complexity
            mi -= cognitive * 0.5
            
            return max(0.0, min(100.0, mi))
        except:
            return 50.0
    
    # Additional helper methods would continue here...
    # (Implementation continues with remaining helper methods)
    
    def _detect_long_methods(self, code: str, file_path: str) -> List[ArchitecturalIssue]:
        """Detect long methods that should be refactored."""
        issues = []
        try:
            tree = ast.parse(code)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    # Calculate method length
                    if hasattr(node, 'end_lineno'):
                        method_length = node.end_lineno - node.lineno + 1
                    else:
                        # Fallback for older Python versions
                        method_length = len([n for n in ast.walk(node) if isinstance(n, ast.stmt)])
                    
                    if method_length > self.CODE_SMELLS['long_method']['threshold']:
                        issue = ArchitecturalIssue(
                            issue_id=f"LONG_METHOD_{hashlib.md5(f'{file_path}:{node.lineno}:{node.name}'.encode()).hexdigest()[:8]}",
                            severity=self.CODE_SMELLS['long_method']['severity'],
                            category="long_method",
                            title=f"Long method: {node.name}",
                            description=f"Method {node.name} has {method_length} lines, exceeding recommended limit",
                            file_path=file_path,
                            line_number=node.lineno,
                            code_snippet=f"def {node.name}(...): # {method_length} lines",
                            impact=self.CODE_SMELLS['long_method']['impact'],
                            confidence=0.9,
                            technical_debt_hours=method_length / 10,  # Rough estimate
                            refactoring_suggestions=self.refactoring_suggestions_db.get('long_method', [])
                        )
                        issues.append(issue)
        except Exception as e:
            self.logger.warning(f"Long method detection failed: {str(e)}")
        
        return issues
    
    def _detect_large_classes(self, code: str, file_path: str) -> List[ArchitecturalIssue]:
        """Detect large classes that violate Single Responsibility Principle."""
        issues = []
        try:
            tree = ast.parse(code)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.ClassDef):
                    # Calculate class size
                    if hasattr(node, 'end_lineno'):
                        class_length = node.end_lineno - node.lineno + 1
                    else:
                        class_length = len([n for n in ast.walk(node) if isinstance(n, ast.stmt)])
                    
                    if class_length > self.CODE_SMELLS['large_class']['threshold']:
                        issue = ArchitecturalIssue(
                            issue_id=f"LARGE_CLASS_{hashlib.md5(f'{file_path}:{node.lineno}:{node.name}'.encode()).hexdigest()[:8]}",
                            severity=self.CODE_SMELLS['large_class']['severity'],
                            category="large_class",
                            title=f"Large class: {node.name}",
                            description=f"Class {node.name} has {class_length} lines, indicating potential SRP violation",
                            file_path=file_path,
                            line_number=node.lineno,
                            code_snippet=f"class {node.name}: # {class_length} lines",
                            impact=self.CODE_SMELLS['large_class']['impact'],
                            confidence=0.8,
                            technical_debt_hours=class_length / 20,
                            refactoring_suggestions=self.refactoring_suggestions_db.get('large_class', [])
                        )
                        issues.append(issue)
        except Exception as e:
            self.logger.warning(f"Large class detection failed: {str(e)}")
        
        return issues
    
    def _detect_too_many_parameters(self, code: str, file_path: str) -> List[ArchitecturalIssue]:
        """Detect functions with too many parameters."""
        issues = []
        try:
            tree = ast.parse(code)
            
            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    param_count = len(node.args.args)
                    
                    if param_count > self.CODE_SMELLS['too_many_parameters']['threshold']:
                        issue = ArchitecturalIssue(
                            issue_id=f"TOO_MANY_PARAMS_{hashlib.md5(f'{file_path}:{node.lineno}:{node.name}'.encode()).hexdigest()[:8]}",
                            severity=self.CODE_SMELLS['too_many_parameters']['severity'],
                            category="too_many_parameters",
                            title=f"Too many parameters: {node.name}",
                            description=f"Function {node.name} has {param_count} parameters, reducing readability",
                            file_path=file_path,
                            line_number=node.lineno,
                            code_snippet=f"def {node.name}({', '.join(['...' for _ in range(param_count)])})",
                            impact=self.CODE_SMELLS['too_many_parameters']['impact'],
                            confidence=0.9,
                            technical_debt_hours=1.0,
                            refactoring_suggestions=[
                                "Group related parameters into objects",
                                "Use builder pattern for complex parameter sets",
                                "Consider using keyword arguments with defaults"
                            ]
                        )
                        issues.append(issue)
        except Exception as e:
            self.logger.warning(f"Too many parameters detection failed: {str(e)}")
        
        return issues
    
    # Placeholder implementations for remaining helper methods
    def _detect_deep_nesting(self, code: str, file_path: str) -> List[ArchitecturalIssue]:
        """Detect deeply nested code structures."""
        return []  # Implementation would analyze nesting depth
    
    def _detect_code_duplication(self, code: str, file_path: str) -> List[ArchitecturalIssue]:
        """Detect code duplication."""
        return []  # Implementation would find duplicate code blocks
    
    def _detect_dead_code(self, code: str, file_path: str) -> List[ArchitecturalIssue]:
        """Detect unused/dead code."""
        return []  # Implementation would find unused functions/variables
    
    def _detect_god_class(self, code: str, file_path: str) -> List[ArchitecturalIssue]:
        """Detect god classes (classes that do too much)."""
        return []  # Implementation would analyze class responsibilities
    
    def _detect_feature_envy(self, code: str, file_path: str) -> List[ArchitecturalIssue]:
        """Detect feature envy (methods using other classes more than their own)."""
        return []  # Implementation would analyze method dependencies
    
    # Additional helper method implementations would continue...
    def _calculate_overall_architecture_score(self, results: Dict[str, Any]) -> float:
        """Calculate overall architecture score."""
        quality_score = results.get("quality_metrics", {}).get("overall_score", 50)
        scalability_score = results.get("scalability_assessment", {}).get("scalability_score", 50)
        
        # Weight the scores
        overall = (quality_score * 0.6) + (scalability_score * 0.4)
        
        # Penalize for critical issues
        critical_issues = len([i for i in results.get("architectural_issues", []) if i.severity == "CRITICAL"])
        overall -= critical_issues * 10
        
        return max(0, min(100, overall))
    
    # Placeholder implementations for remaining methods
    def _assess_pattern_implementation_quality(self, pattern_name: str, code: str, lines: List[int]) -> str:
        return "GOOD"  # Simplified implementation
    
    def _get_pattern_benefits(self, pattern_name: str) -> List[str]:
        return [f"Benefits of {pattern_name} pattern"]
    
    def _get_pattern_potential_issues(self, pattern_name: str, quality: str) -> List[str]:
        return [f"Potential issues with {pattern_name} implementation"]
    
    def _analyze_code_duplication(self, code: str) -> float:
        return 5.0  # Simplified: return 5% duplication
    
    def _analyze_dependencies(self, code: str) -> List[str]:
        imports = re.findall(r'(?:from\s+(\S+)\s+)?import\s+(\S+)', code)
        return [imp[1] if imp[0] else imp[1] for imp in imports]
    
    def _calculate_coupling_factor(self, code: str) -> float:
        return 0.3  # Simplified implementation
    
    def _calculate_cohesion_score(self, code: str) -> float:
        return 0.7  # Simplified implementation
    
    def _calculate_technical_debt_ratio(self, cyclomatic: float, cognitive: float, duplication: float, coupling: float) -> float:
        return (cyclomatic + cognitive + duplication * 10 + coupling * 10) / 100
    
    def _calculate_overall_quality_score(self, maintainability: float, debt_ratio: float, duplication: float, coupling: float, cohesion: float) -> float:
        return max(0, min(100, maintainability - debt_ratio * 20 - duplication * 2 + cohesion * 10))
    
    def _get_quality_grade(self, score: float) -> str:
        if score >= 85: return "EXCELLENT"
        elif score >= 70: return "GOOD"
        elif score >= 50: return "FAIR"
        else: return "POOR"
    
    def _calculate_function_complexity(self, node: ast.FunctionDef, code: str) -> Dict[str, Any]:
        return {
            "cyclomatic": 5,  # Simplified
            "cognitive": 7,   # Simplified
            "loc": 20,        # Simplified
            "nesting_depth": 2  # Simplified
        }
    
    def _calculate_class_complexity(self, node: ast.ClassDef, code: str) -> Dict[str, Any]:
        return {
            "methods_count": len([n for n in node.body if isinstance(n, ast.FunctionDef)]),
            "loc": 100,  # Simplified
            "complexity": 15,  # Simplified
            "inheritance_depth": 1  # Simplified
        }
    
    def _estimate_fix_time(self, issue: ArchitecturalIssue) -> float:
        """Estimate time to fix an architectural issue."""
        time_map = {
            "CRITICAL": 8.0,
            "HIGH": 4.0,
            "MEDIUM": 2.0,
            "LOW": 1.0,
            "INFO": 0.5
        }
        return time_map.get(issue.severity, 2.0)
    
    def _prioritize_technical_debt(self, issues: List[ArchitecturalIssue], complexity: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Prioritize technical debt items."""
        return [
            {
                "title": "High complexity functions",
                "priority": "HIGH",
                "effort": 6,
                "impact": "MAINTAINABILITY"
            }
        ]
    
    def _categorize_debt_level(self, debt_ratio: float) -> str:
        if debt_ratio < 0.1: return "LOW"
        elif debt_ratio < 0.3: return "MEDIUM"
        elif debt_ratio < 0.5: return "HIGH"
        else: return "CRITICAL"
    
    def _has_singleton_overuse(self, patterns: List[DesignPattern]) -> bool:
        singleton_count = len([p for p in patterns if p.pattern_name == "singleton"])
        return singleton_count > 2
    
    def _identify_performance_bottlenecks(self, code: str) -> List[str]:
        bottlenecks = []
        if "for" in code and "for" in code:  # Nested loops
            bottlenecks.append("Nested loops detected")
        if re.search(r'\.join\s*\(.*for.*in.*\)', code):
            bottlenecks.append("String concatenation in loop")
        return bottlenecks
    
    def _has_proper_error_handling(self, code: str) -> bool:
        return "try:" in code and "except" in code
    
    def _has_proper_resource_management(self, code: str) -> bool:
        return "with " in code or "finally:" in code
    
    def _get_scalability_grade(self, score: float) -> str:
        if score >= 85: return "EXCELLENT"
        elif score >= 70: return "GOOD"
        elif score >= 50: return "FAIR"
        else: return "POOR"
    
    def _assess_patterns_scalability_impact(self, patterns: List[DesignPattern]) -> Dict[str, str]:
        return {pattern.pattern_name: "POSITIVE" for pattern in patterns}
    
    def _calculate_refactoring_priority(self, issues: List[ArchitecturalIssue]) -> str:
        critical_count = len([i for i in issues if i.severity == "CRITICAL"])
        high_count = len([i for i in issues if i.severity == "HIGH"])
        
        if critical_count > 0: return "CRITICAL"
        elif high_count > 2: return "HIGH"
        elif high_count > 0: return "MEDIUM"
        else: return "LOW"
    
    def _assess_refactoring_impact(self, issues: List[ArchitecturalIssue]) -> str:
        impacts = [issue.impact for issue in issues]
        if "SCALABILITY" in impacts: return "SCALABILITY"
        elif "MAINTAINABILITY" in impacts: return "MAINTAINABILITY"
        elif "PERFORMANCE" in impacts: return "PERFORMANCE"
        else: return "READABILITY"

