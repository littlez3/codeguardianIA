"""
CodeGuardian AI - Testing Agent
Enterprise-grade testing analysis agent specializing in test coverage analysis,
test quality assessment, test generation, and testing best practices validation.

This agent implements advanced testing analysis capabilities including:
- Test coverage analysis and gap identification
- Test quality and effectiveness assessment
- Automated test case generation
- Testing strategy recommendations
- Performance and load testing analysis
- Test automation optimization
"""

import re
import ast
import json
import subprocess
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass
from pathlib import Path
import hashlib

from .base_agent import BaseAgent, AgentCapability, AnalysisTask
from ..config.enterprise_config import EnterpriseConfig


@dataclass
class TestIssue:
    """Represents a testing issue found in code or test configuration."""
    issue_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # e.g., "coverage", "quality", "strategy", "automation"
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    impact: str  # QUALITY, RELIABILITY, MAINTAINABILITY, PERFORMANCE
    confidence: float = 0.0
    remediation: Optional[str] = None
    test_type: str = "UNIT"  # UNIT, INTEGRATION, E2E, PERFORMANCE
    automation_potential: str = "NONE"  # HIGH, MEDIUM, LOW, NONE
    
    def __post_init__(self):
        pass


@dataclass
class TestMetrics:
    """Comprehensive testing metrics."""
    line_coverage: float
    branch_coverage: float
    function_coverage: float
    statement_coverage: float
    test_count: int
    assertion_count: int
    test_quality_score: float
    automation_score: float
    performance_test_coverage: float
    integration_test_coverage: float


@dataclass
class TestSuite:
    """Represents a test suite with its characteristics."""
    suite_name: str
    test_count: int
    test_types: List[str]
    coverage_percentage: float
    quality_score: float
    automation_level: str
    execution_time: float
    flakiness_score: float
    maintainability_score: float


class TestingAgent(BaseAgent):
    """
    Specialized agent for comprehensive testing analysis and optimization.
    
    This agent provides enterprise-grade testing analysis capabilities including
    test coverage analysis, quality assessment, automated test generation,
    and testing strategy optimization.
    """
    
    # Test patterns and anti-patterns
    TEST_PATTERNS = {
        'unit_test_files': [
            r'test_.*\.py$',
            r'.*_test\.py$',
            r'tests?/.*\.py$',
            r'.*Test\.py$'
        ],
        'test_methods': [
            r'def\s+test_\w+',
            r'def\s+\w+_test\s*\(',
            r'@pytest\.mark\.',
            r'@unittest\.',
            r'class\s+Test\w+'
        ],
        'assertions': [
            r'assert\s+',
            r'assertEqual\s*\(',
            r'assertTrue\s*\(',
            r'assertFalse\s*\(',
            r'assertRaises\s*\(',
            r'expect\s*\(',
            r'should\s*\.'
        ],
        'mocking': [
            r'@mock\.',
            r'@patch\s*\(',
            r'Mock\s*\(',
            r'MagicMock\s*\(',
            r'mock\.',
            r'unittest\.mock'
        ]
    }
    
    # Test anti-patterns (bad practices)
    TEST_ANTI_PATTERNS = {
        'no_assertions': r'def\s+test_\w+.*?(?=def|\Z)',
        'empty_tests': r'def\s+test_\w+.*?:\s*pass',
        'hardcoded_values': r'assert.*==\s*["\'].*["\']',
        'sleep_in_tests': r'time\.sleep\s*\(',
        'print_debugging': r'print\s*\(',
        'commented_assertions': r'#.*assert',
        'too_many_assertions': r'def\s+test_\w+.*?(?=def|\Z)',  # Will be analyzed separately
        'test_dependencies': r'global\s+\w+',
        'database_in_unit_tests': r'(?:connect|cursor|execute).*(?:database|db|sql)',
        'network_in_unit_tests': r'(?:requests\.|urllib\.|http)'
    }
    
    # Test framework patterns
    TEST_FRAMEWORKS = {
        'pytest': [
            r'import\s+pytest',
            r'@pytest\.',
            r'pytest\.',
            r'conftest\.py'
        ],
        'unittest': [
            r'import\s+unittest',
            r'unittest\.',
            r'TestCase',
            r'setUp\s*\(',
            r'tearDown\s*\('
        ],
        'nose': [
            r'import\s+nose',
            r'@nose\.',
            r'nose\.'
        ],
        'doctest': [
            r'import\s+doctest',
            r'doctest\.',
            r'>>>'
        ]
    }
    
    # Performance test patterns
    PERFORMANCE_TEST_PATTERNS = {
        'load_testing': [
            r'locust',
            r'jmeter',
            r'artillery',
            r'k6',
            r'gatling'
        ],
        'benchmark_testing': [
            r'@benchmark',
            r'timeit',
            r'cProfile',
            r'memory_profiler'
        ],
        'stress_testing': [
            r'stress',
            r'concurrent',
            r'threading',
            r'multiprocessing'
        ]
    }
    
    def __init__(self, agent_id: str, config: EnterpriseConfig, **kwargs):
        """Initialize the Testing Agent with specialized capabilities."""
        super().__init__(agent_id, "testing", config, **kwargs)
        
        # Initialize testing-specific components
        self.test_frameworks = set()
        self.coverage_thresholds = {
            'line_coverage': 80.0,
            'branch_coverage': 70.0,
            'function_coverage': 90.0
        }
        self.test_quality_metrics = {}
        
        # Load testing knowledge base
        self._load_testing_knowledge()
        
        self.logger.info("Testing Agent initialized with comprehensive test analysis capabilities")
    
    def _initialize_capabilities(self) -> None:
        """Initialize testing-specific capabilities."""
        capabilities = [
            AgentCapability(
                name="test_coverage_analysis",
                description="Comprehensive test coverage analysis and gap identification",
                confidence_level=0.94
            ),
            AgentCapability(
                name="test_quality_assessment",
                description="Test quality and effectiveness assessment",
                confidence_level=0.92
            ),
            AgentCapability(
                name="test_generation",
                description="Automated test case generation and recommendations",
                confidence_level=0.88
            ),
            AgentCapability(
                name="testing_strategy_optimization",
                description="Testing strategy and framework optimization",
                confidence_level=0.90
            ),
            AgentCapability(
                name="performance_testing_analysis",
                description="Performance and load testing analysis",
                confidence_level=0.86
            ),
            AgentCapability(
                name="test_automation_optimization",
                description="Test automation and CI/CD integration optimization",
                confidence_level=0.91
            ),
            AgentCapability(
                name="mutation_testing",
                description="Mutation testing and test effectiveness validation",
                confidence_level=0.85
            ),
            AgentCapability(
                name="flaky_test_detection",
                description="Flaky test detection and stability analysis",
                confidence_level=0.87
            )
        ]
        
        for capability in capabilities:
            self.add_capability(capability)
    
    def _load_testing_knowledge(self) -> None:
        """Load testing patterns and best practices knowledge base."""
        try:
            # Load test quality metrics
            self.test_quality_metrics = {
                'assertion_density': {
                    'min_threshold': 1.0,  # At least 1 assertion per test
                    'optimal_range': (1.0, 5.0)
                },
                'test_method_length': {
                    'max_lines': 20,  # Tests should be concise
                    'optimal_range': (5, 15)
                },
                'cyclomatic_complexity': {
                    'max_complexity': 5,  # Tests should be simple
                    'optimal_threshold': 3
                },
                'test_isolation': {
                    'no_shared_state': True,
                    'independent_execution': True
                }
            }
            
            # Load testing best practices
            self.testing_best_practices = {
                'naming_conventions': [
                    'test_should_return_expected_result_when_valid_input',
                    'test_should_raise_exception_when_invalid_input',
                    'test_should_handle_edge_case_properly'
                ],
                'test_structure': {
                    'arrange_act_assert': True,
                    'given_when_then': True,
                    'single_responsibility': True
                },
                'test_data_management': {
                    'use_fixtures': True,
                    'avoid_hardcoded_data': True,
                    'parameterized_tests': True
                }
            }
            
            self.logger.info("Testing knowledge base loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to load testing knowledge: {str(e)}")
    
    async def analyze(self, task: AnalysisTask) -> Dict[str, Any]:
        """
        Perform comprehensive testing analysis on the provided code.
        
        Args:
            task: Analysis task containing code and context
            
        Returns:
            Dictionary containing testing analysis results
        """
        try:
            content = task.payload.get('content', task.payload.get('code', ''))
            file_type = task.payload.get('file_type', 'python')
            file_path = task.payload.get('file_path', 'unknown')
            
            if not content:
                raise ValueError("No content provided for testing analysis")
            
            self.logger.info(f"Starting testing analysis for {file_path}")
            
            # Perform comprehensive testing analysis
            results = {
                "analysis_type": "testing",
                "agent_id": self.agent_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "file_path": file_path,
                "file_type": file_type,
                "test_issues": [],
                "coverage_analysis": {},
                "quality_analysis": {},
                "test_generation_suggestions": [],
                "performance_testing_analysis": {},
                "automation_analysis": {},
                "framework_analysis": {},
                "test_metrics": {},
                "recommendations": [],
                "summary": {}
            }
            
            # 1. Test Coverage Analysis
            coverage_analysis = await self._analyze_test_coverage(content, file_path)
            results["coverage_analysis"] = coverage_analysis
            results["test_issues"].extend(coverage_analysis.get("issues", []))
            
            # 2. Test Quality Analysis
            quality_analysis = await self._analyze_test_quality(content, file_path)
            results["quality_analysis"] = quality_analysis
            results["test_issues"].extend(quality_analysis.get("issues", []))
            
            # 3. Test Framework Analysis
            framework_analysis = await self._analyze_test_frameworks(content, file_path)
            results["framework_analysis"] = framework_analysis
            results["test_issues"].extend(framework_analysis.get("issues", []))
            
            # 4. Performance Testing Analysis
            performance_analysis = await self._analyze_performance_testing(content, file_path)
            results["performance_testing_analysis"] = performance_analysis
            results["test_issues"].extend(performance_analysis.get("issues", []))
            
            # 5. Test Automation Analysis
            automation_analysis = await self._analyze_test_automation(content, file_path)
            results["automation_analysis"] = automation_analysis
            results["test_issues"].extend(automation_analysis.get("issues", []))
            
            # 6. Generate Test Suggestions
            test_suggestions = await self._generate_test_suggestions(content, file_path)
            results["test_generation_suggestions"] = test_suggestions
            
            # 7. Calculate Test Metrics
            test_metrics = await self._calculate_test_metrics(content, results["test_issues"])
            results["test_metrics"] = test_metrics
            
            # 8. Generate Recommendations
            recommendations = await self._generate_testing_recommendations(results["test_issues"], test_metrics)
            results["recommendations"] = recommendations
            
            # 9. Generate Summary
            results["summary"] = self._generate_testing_summary(results)
            
            self.logger.info(f"Testing analysis completed. Found {len(results['test_issues'])} issues")
            
            return {
                "success": True,
                "data": results,
                "meta": {
                    "analysis_time": (datetime.now(timezone.utc) - datetime.fromisoformat(results["timestamp"])).total_seconds(),
                    "issues_found": len(results["test_issues"]),
                    "test_coverage_score": coverage_analysis.get("coverage_score", 0),
                    "test_quality_score": quality_analysis.get("quality_score", 0),
                    "automation_score": automation_analysis.get("automation_score", 0)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Testing analysis failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "data": None
            }
    
    async def _analyze_test_coverage(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze test coverage and identify gaps."""
        issues = []
        coverage_data = {
            "is_test_file": False,
            "test_methods": [],
            "coverage_gaps": [],
            "coverage_score": 0,
            "issues": issues,
            "recommendations": []
        }
        
        try:
            # Check if this is a test file
            is_test_file = any(
                re.search(pattern, file_path, re.IGNORECASE) 
                for pattern in self.TEST_PATTERNS['unit_test_files']
            )
            coverage_data["is_test_file"] = is_test_file
            
            if is_test_file:
                # Analyze test methods
                test_methods = []
                for pattern in self.TEST_PATTERNS['test_methods']:
                    matches = re.finditer(pattern, content, re.MULTILINE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        test_methods.append({
                            "name": match.group(0),
                            "line": line_num,
                            "type": "unit_test"
                        })
                
                coverage_data["test_methods"] = test_methods
                
                # Check for missing assertions
                for test_method in test_methods:
                    method_start = test_method["line"]
                    # Find method end (simplified)
                    method_content = self._extract_method_content(content, method_start)
                    
                    assertion_count = sum(
                        len(re.findall(pattern, method_content, re.IGNORECASE))
                        for pattern in self.TEST_PATTERNS['assertions']
                    )
                    
                    if assertion_count == 0:
                        issue = TestIssue(
                            issue_id=f"TEST_NO_ASSERTIONS_{hashlib.md5(f'{file_path}:{method_start}'.encode()).hexdigest()[:8]}",
                            severity="HIGH",
                            category="test_quality",
                            title="Test Method Without Assertions",
                            description=f"Test method '{test_method['name']}' has no assertions",
                            file_path=file_path,
                            line_number=method_start,
                            code_snippet=method_content.split('\n')[0] if method_content else "",
                            impact="QUALITY",
                            confidence=0.9,
                            remediation="Add appropriate assertions to validate test expectations",
                            test_type="UNIT",
                            automation_potential="HIGH"
                        )
                        issues.append(issue)
                
                # Calculate coverage score based on test quality
                coverage_data["coverage_score"] = self._calculate_test_file_score(test_methods, issues)
            
            else:
                # Analyze production code for test coverage gaps
                functions = self._extract_functions(content)
                classes = self._extract_classes(content)
                
                # Simple heuristic: assume missing tests for functions/classes
                # In a real implementation, this would integrate with coverage tools
                if functions or classes:
                    issue = TestIssue(
                        issue_id=f"TEST_COVERAGE_GAP_{hashlib.md5(file_path.encode()).hexdigest()[:8]}",
                        severity="MEDIUM",
                        category="coverage",
                        title="Potential Test Coverage Gap",
                        description=f"File contains {len(functions)} functions and {len(classes)} classes that may need test coverage",
                        file_path=file_path,
                        line_number=1,
                        code_snippet="# Production code without corresponding tests",
                        impact="QUALITY",
                        confidence=0.6,
                        remediation="Create comprehensive test suite for this module",
                        test_type="UNIT",
                        automation_potential="HIGH"
                    )
                    issues.append(issue)
                
                coverage_data["coverage_score"] = 30  # Low score for untested code
            
            # Generate coverage recommendations
            coverage_data["recommendations"] = self._generate_coverage_recommendations(issues)
            
        except Exception as e:
            self.logger.warning(f"Test coverage analysis failed: {str(e)}")
        
        return coverage_data
    
    async def _analyze_test_quality(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze test quality and identify anti-patterns."""
        issues = []
        quality_data = {
            "quality_score": 0,
            "anti_patterns": [],
            "quality_metrics": {},
            "issues": issues,
            "recommendations": []
        }
        
        try:
            # Check for test anti-patterns
            for anti_pattern, pattern in self.TEST_ANTI_PATTERNS.items():
                if anti_pattern == 'too_many_assertions':
                    # Special handling for too many assertions
                    continue
                
                matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    
                    issue = TestIssue(
                        issue_id=f"TEST_ANTI_PATTERN_{anti_pattern.upper()}_{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                        severity=self._get_anti_pattern_severity(anti_pattern),
                        category="test_quality",
                        title=f"Test Anti-Pattern: {anti_pattern.replace('_', ' ').title()}",
                        description=f"Detected {anti_pattern} anti-pattern in test code",
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=content.split('\n')[line_num-1] if line_num <= len(content.split('\n')) else "",
                        impact="QUALITY",
                        confidence=0.8,
                        remediation=self._get_anti_pattern_remediation(anti_pattern),
                        test_type="UNIT",
                        automation_potential="MEDIUM"
                    )
                    issues.append(issue)
                    quality_data["anti_patterns"].append(anti_pattern)
            
            # Analyze test method complexity
            test_methods = re.finditer(r'def\s+test_\w+.*?(?=def|\Z)', content, re.DOTALL)
            for method_match in test_methods:
                method_content = method_match.group(0)
                line_num = content[:method_match.start()].count('\n') + 1
                
                # Count assertions
                assertion_count = sum(
                    len(re.findall(pattern, method_content, re.IGNORECASE))
                    for pattern in self.TEST_PATTERNS['assertions']
                )
                
                # Check for too many assertions (indicates test doing too much)
                if assertion_count > 5:
                    issue = TestIssue(
                        issue_id=f"TEST_TOO_MANY_ASSERTIONS_{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                        severity="MEDIUM",
                        category="test_quality",
                        title="Test Method With Too Many Assertions",
                        description=f"Test method has {assertion_count} assertions (recommended: 1-5)",
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=method_content.split('\n')[0],
                        impact="MAINTAINABILITY",
                        confidence=0.7,
                        remediation="Split test into multiple focused test methods",
                        test_type="UNIT",
                        automation_potential="LOW"
                    )
                    issues.append(issue)
                
                # Check method length
                method_lines = len(method_content.split('\n'))
                if method_lines > 20:
                    issue = TestIssue(
                        issue_id=f"TEST_TOO_LONG_{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                        severity="MEDIUM",
                        category="test_quality",
                        title="Test Method Too Long",
                        description=f"Test method has {method_lines} lines (recommended: <20)",
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=method_content.split('\n')[0],
                        impact="MAINTAINABILITY",
                        confidence=0.8,
                        remediation="Refactor test method to be more concise",
                        test_type="UNIT",
                        automation_potential="LOW"
                    )
                    issues.append(issue)
            
            # Calculate quality score
            quality_data["quality_score"] = self._calculate_quality_score(content, issues)
            
            # Generate quality recommendations
            quality_data["recommendations"] = self._generate_quality_recommendations(issues)
            
        except Exception as e:
            self.logger.warning(f"Test quality analysis failed: {str(e)}")
        
        return quality_data
    
    async def _analyze_test_frameworks(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze test frameworks and their usage."""
        issues = []
        framework_data = {
            "detected_frameworks": [],
            "framework_conflicts": [],
            "framework_score": 0,
            "issues": issues,
            "recommendations": []
        }
        
        try:
            # Detect test frameworks
            detected_frameworks = []
            for framework, patterns in self.TEST_FRAMEWORKS.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        detected_frameworks.append(framework)
                        break
            
            framework_data["detected_frameworks"] = list(set(detected_frameworks))
            
            # Check for framework conflicts
            if len(detected_frameworks) > 1:
                issue = TestIssue(
                    issue_id=f"TEST_FRAMEWORK_CONFLICT_{hashlib.md5(file_path.encode()).hexdigest()[:8]}",
                    severity="MEDIUM",
                    category="framework",
                    title="Multiple Test Frameworks Detected",
                    description=f"Multiple test frameworks detected: {', '.join(detected_frameworks)}",
                    file_path=file_path,
                    line_number=1,
                    code_snippet="# Multiple test frameworks in use",
                    impact="MAINTAINABILITY",
                    confidence=0.8,
                    remediation="Standardize on a single test framework",
                    test_type="UNIT",
                    automation_potential="MEDIUM"
                )
                issues.append(issue)
                framework_data["framework_conflicts"] = detected_frameworks
            
            # Check for missing test framework
            if not detected_frameworks and self._is_likely_test_file(file_path, content):
                issue = TestIssue(
                    issue_id=f"TEST_NO_FRAMEWORK_{hashlib.md5(file_path.encode()).hexdigest()[:8]}",
                    severity="HIGH",
                    category="framework",
                    title="No Test Framework Detected",
                    description="Test file appears to lack a proper test framework",
                    file_path=file_path,
                    line_number=1,
                    code_snippet="# No test framework detected",
                    impact="QUALITY",
                    confidence=0.7,
                    remediation="Adopt a test framework like pytest or unittest",
                    test_type="UNIT",
                    automation_potential="HIGH"
                )
                issues.append(issue)
            
            # Calculate framework score
            framework_data["framework_score"] = self._calculate_framework_score(detected_frameworks, issues)
            
            # Generate framework recommendations
            framework_data["recommendations"] = self._generate_framework_recommendations(detected_frameworks, issues)
            
        except Exception as e:
            self.logger.warning(f"Test framework analysis failed: {str(e)}")
        
        return framework_data
    
    async def _analyze_performance_testing(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze performance testing implementation."""
        issues = []
        performance_data = {
            "has_performance_tests": False,
            "performance_tools": [],
            "performance_score": 0,
            "issues": issues,
            "recommendations": []
        }
        
        try:
            # Check for performance testing tools
            performance_tools = []
            for category, patterns in self.PERFORMANCE_TEST_PATTERNS.items():
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        performance_tools.append(pattern)
            
            performance_data["performance_tools"] = performance_tools
            performance_data["has_performance_tests"] = len(performance_tools) > 0
            
            # Check for missing performance tests in critical files
            if not performance_tools and self._is_performance_critical_file(file_path, content):
                issue = TestIssue(
                    issue_id=f"TEST_NO_PERFORMANCE_{hashlib.md5(file_path.encode()).hexdigest()[:8]}",
                    severity="MEDIUM",
                    category="performance_testing",
                    title="Missing Performance Tests",
                    description="Performance-critical code lacks performance testing",
                    file_path=file_path,
                    line_number=1,
                    code_snippet="# No performance tests detected",
                    impact="PERFORMANCE",
                    confidence=0.6,
                    remediation="Add performance tests using tools like pytest-benchmark",
                    test_type="PERFORMANCE",
                    automation_potential="HIGH"
                )
                issues.append(issue)
            
            # Calculate performance testing score
            performance_data["performance_score"] = self._calculate_performance_score(performance_tools, issues)
            
            # Generate performance testing recommendations
            performance_data["recommendations"] = self._generate_performance_recommendations(performance_tools, issues)
            
        except Exception as e:
            self.logger.warning(f"Performance testing analysis failed: {str(e)}")
        
        return performance_data
    
    async def _analyze_test_automation(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze test automation and CI/CD integration."""
        issues = []
        automation_data = {
            "automation_score": 0,
            "ci_integration": False,
            "automation_tools": [],
            "issues": issues,
            "recommendations": []
        }
        
        try:
            # Check for CI/CD integration patterns
            ci_patterns = [
                r'pytest',
                r'unittest',
                r'coverage',
                r'tox',
                r'github.*actions',
                r'jenkins',
                r'gitlab.*ci'
            ]
            
            automation_tools = []
            for pattern in ci_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    automation_tools.append(pattern)
            
            automation_data["automation_tools"] = automation_tools
            automation_data["ci_integration"] = len(automation_tools) > 0
            
            # Check for manual test indicators
            manual_indicators = [
                r'# TODO.*test',
                r'# FIXME.*test',
                r'manual.*test',
                r'run.*manually'
            ]
            
            for pattern in manual_indicators:
                matches = re.finditer(pattern, content, re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    
                    issue = TestIssue(
                        issue_id=f"TEST_MANUAL_{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                        severity="MEDIUM",
                        category="automation",
                        title="Manual Testing Indicator",
                        description="Code contains indicators of manual testing requirements",
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=content.split('\n')[line_num-1] if line_num <= len(content.split('\n')) else "",
                        impact="RELIABILITY",
                        confidence=0.6,
                        remediation="Automate manual testing processes",
                        test_type="INTEGRATION",
                        automation_potential="HIGH"
                    )
                    issues.append(issue)
            
            # Calculate automation score
            automation_data["automation_score"] = self._calculate_automation_score(automation_tools, issues)
            
            # Generate automation recommendations
            automation_data["recommendations"] = self._generate_automation_recommendations(automation_tools, issues)
            
        except Exception as e:
            self.logger.warning(f"Test automation analysis failed: {str(e)}")
        
        return automation_data
    
    async def _generate_test_suggestions(self, content: str, file_path: str) -> List[Dict[str, Any]]:
        """Generate automated test case suggestions."""
        suggestions = []
        
        try:
            # Extract functions for test generation
            functions = self._extract_functions(content)
            
            for func in functions:
                suggestion = {
                    "function_name": func["name"],
                    "line_number": func["line"],
                    "suggested_tests": [
                        f"test_{func['name']}_with_valid_input",
                        f"test_{func['name']}_with_invalid_input",
                        f"test_{func['name']}_edge_cases"
                    ],
                    "test_template": self._generate_test_template(func),
                    "priority": "HIGH" if self._is_critical_function(func) else "MEDIUM"
                }
                suggestions.append(suggestion)
            
        except Exception as e:
            self.logger.warning(f"Test suggestion generation failed: {str(e)}")
        
        return suggestions
    
    async def _calculate_test_metrics(self, content: str, issues: List[TestIssue]) -> Dict[str, Any]:
        """Calculate comprehensive test metrics."""
        try:
            # Count test methods
            test_method_count = len(re.findall(r'def\s+test_\w+', content))
            
            # Count assertions
            assertion_count = sum(
                len(re.findall(pattern, content, re.IGNORECASE))
                for pattern in self.TEST_PATTERNS['assertions']
            )
            
            # Calculate assertion density
            assertion_density = assertion_count / max(test_method_count, 1)
            
            # Count issues by severity
            critical_issues = len([i for i in issues if i.severity == "CRITICAL"])
            high_issues = len([i for i in issues if i.severity == "HIGH"])
            medium_issues = len([i for i in issues if i.severity == "MEDIUM"])
            
            # Calculate quality score
            quality_score = max(0, 100 - (critical_issues * 25 + high_issues * 15 + medium_issues * 8))
            
            return {
                "test_method_count": test_method_count,
                "assertion_count": assertion_count,
                "assertion_density": assertion_density,
                "quality_score": quality_score,
                "issue_count": len(issues),
                "critical_issues": critical_issues,
                "high_issues": high_issues,
                "medium_issues": medium_issues,
                "coverage_estimation": self._estimate_coverage(content),
                "maintainability_score": self._calculate_maintainability_score(content, issues)
            }
            
        except Exception as e:
            self.logger.warning(f"Test metrics calculation failed: {str(e)}")
            return {}
    
    async def _generate_testing_recommendations(self, issues: List[TestIssue], metrics: Dict[str, Any]) -> List[str]:
        """Generate testing recommendations based on analysis."""
        recommendations = []
        
        try:
            # Coverage recommendations
            if metrics.get("coverage_estimation", 0) < 80:
                recommendations.append("Increase test coverage to at least 80%")
            
            # Quality recommendations
            if metrics.get("assertion_density", 0) < 1.0:
                recommendations.append("Add more assertions to test methods")
            
            # Framework recommendations
            framework_issues = [i for i in issues if i.category == "framework"]
            if framework_issues:
                recommendations.append("Standardize on a single test framework")
            
            # Performance testing recommendations
            performance_issues = [i for i in issues if i.category == "performance_testing"]
            if performance_issues:
                recommendations.append("Add performance tests for critical code paths")
            
            # Automation recommendations
            automation_issues = [i for i in issues if i.category == "automation"]
            if automation_issues:
                recommendations.append("Improve test automation and CI/CD integration")
            
            # General recommendations
            recommendations.extend([
                "Follow the Arrange-Act-Assert pattern in tests",
                "Use descriptive test method names",
                "Keep tests independent and isolated",
                "Use test fixtures for common setup",
                "Implement parameterized tests for multiple scenarios"
            ])
            
        except Exception as e:
            self.logger.warning(f"Testing recommendations generation failed: {str(e)}")
        
        return recommendations
    
    def _generate_testing_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive testing analysis summary."""
        try:
            issues = results.get("test_issues", [])
            metrics = results.get("test_metrics", {})
            
            summary = {
                "total_issues": len(issues),
                "severity_breakdown": {
                    "CRITICAL": len([i for i in issues if i.severity == "CRITICAL"]),
                    "HIGH": len([i for i in issues if i.severity == "HIGH"]),
                    "MEDIUM": len([i for i in issues if i.severity == "MEDIUM"]),
                    "LOW": len([i for i in issues if i.severity == "LOW"])
                },
                "category_breakdown": {},
                "overall_test_score": metrics.get("quality_score", 0),
                "coverage_score": results.get("coverage_analysis", {}).get("coverage_score", 0),
                "automation_score": results.get("automation_analysis", {}).get("automation_score", 0),
                "test_method_count": metrics.get("test_method_count", 0),
                "assertion_density": metrics.get("assertion_density", 0),
                "top_recommendations": results.get("recommendations", [])[:5],
                "critical_issues": [i.title for i in issues if i.severity == "CRITICAL"][:3]
            }
            
            # Calculate category breakdown
            for issue in issues:
                category = issue.category
                summary["category_breakdown"][category] = summary["category_breakdown"].get(category, 0) + 1
            
            return summary
            
        except Exception as e:
            self.logger.warning(f"Testing summary generation failed: {str(e)}")
            return {}
    
    # Helper methods
    def _extract_method_content(self, content: str, start_line: int) -> str:
        """Extract method content starting from a specific line."""
        lines = content.split('\n')
        if start_line > len(lines):
            return ""
        
        # Simple method extraction (would need more sophisticated parsing in production)
        method_lines = []
        indent_level = None
        
        for i, line in enumerate(lines[start_line-1:], start_line-1):
            if indent_level is None and line.strip():
                indent_level = len(line) - len(line.lstrip())
            
            if line.strip() and len(line) - len(line.lstrip()) <= indent_level:
                if i > start_line - 1:  # End of method
                    break
            
            method_lines.append(line)
        
        return '\n'.join(method_lines)
    
    def _extract_functions(self, content: str) -> List[Dict[str, Any]]:
        """Extract function definitions from code."""
        functions = []
        matches = re.finditer(r'def\s+(\w+)\s*\(', content)
        
        for match in matches:
            functions.append({
                "name": match.group(1),
                "line": content[:match.start()].count('\n') + 1,
                "signature": match.group(0)
            })
        
        return functions
    
    def _extract_classes(self, content: str) -> List[Dict[str, Any]]:
        """Extract class definitions from code."""
        classes = []
        matches = re.finditer(r'class\s+(\w+)', content)
        
        for match in matches:
            classes.append({
                "name": match.group(1),
                "line": content[:match.start()].count('\n') + 1
            })
        
        return classes
    
    def _is_likely_test_file(self, file_path: str, content: str) -> bool:
        """Check if file is likely a test file."""
        return (
            any(pattern in file_path.lower() for pattern in ['test', 'spec']) or
            'def test_' in content or
            'class Test' in content
        )
    
    def _is_performance_critical_file(self, file_path: str, content: str) -> bool:
        """Check if file contains performance-critical code."""
        performance_indicators = [
            'algorithm', 'optimization', 'cache', 'performance',
            'speed', 'efficiency', 'benchmark', 'profile'
        ]
        
        return any(
            indicator in file_path.lower() or indicator in content.lower()
            for indicator in performance_indicators
        )
    
    def _is_critical_function(self, func: Dict[str, Any]) -> bool:
        """Check if function is critical and needs priority testing."""
        critical_patterns = ['main', 'process', 'execute', 'run', 'handle', 'validate']
        return any(pattern in func["name"].lower() for pattern in critical_patterns)
    
    def _generate_test_template(self, func: Dict[str, Any]) -> str:
        """Generate a test template for a function."""
        return f"""
def test_{func['name']}_with_valid_input():
    # Arrange
    # TODO: Set up test data
    
    # Act
    result = {func['name']}()  # TODO: Add appropriate parameters
    
    # Assert
    # TODO: Add assertions
    assert result is not None

def test_{func['name']}_with_invalid_input():
    # Arrange
    # TODO: Set up invalid test data
    
    # Act & Assert
    with pytest.raises(Exception):  # TODO: Specify expected exception
        {func['name']}()  # TODO: Add invalid parameters
"""
    
    # Score calculation methods
    def _calculate_test_file_score(self, test_methods: List[Dict], issues: List[TestIssue]) -> float:
        """Calculate score for test files."""
        base_score = 100
        
        # Deduct points for issues
        for issue in issues:
            if issue.severity == "CRITICAL":
                base_score -= 25
            elif issue.severity == "HIGH":
                base_score -= 15
            elif issue.severity == "MEDIUM":
                base_score -= 8
            elif issue.severity == "LOW":
                base_score -= 3
        
        # Bonus for having tests
        if test_methods:
            base_score += min(len(test_methods) * 5, 20)
        
        return max(0, base_score)
    
    def _calculate_quality_score(self, content: str, issues: List[TestIssue]) -> float:
        """Calculate test quality score."""
        return self._calculate_test_file_score([], issues)
    
    def _calculate_framework_score(self, frameworks: List[str], issues: List[TestIssue]) -> float:
        """Calculate framework usage score."""
        base_score = 50
        
        if len(frameworks) == 1:
            base_score += 30  # Good: single framework
        elif len(frameworks) > 1:
            base_score -= 20  # Bad: multiple frameworks
        
        # Deduct for framework-related issues
        framework_issues = [i for i in issues if i.category == "framework"]
        base_score -= len(framework_issues) * 10
        
        return max(0, base_score)
    
    def _calculate_performance_score(self, tools: List[str], issues: List[TestIssue]) -> float:
        """Calculate performance testing score."""
        base_score = 20  # Low base score
        
        if tools:
            base_score += 60  # Good: has performance testing
        
        # Deduct for performance-related issues
        perf_issues = [i for i in issues if i.category == "performance_testing"]
        base_score -= len(perf_issues) * 15
        
        return max(0, base_score)
    
    def _calculate_automation_score(self, tools: List[str], issues: List[TestIssue]) -> float:
        """Calculate test automation score."""
        base_score = 30  # Low base score
        
        if tools:
            base_score += 50  # Good: has automation
        
        # Deduct for automation-related issues
        auto_issues = [i for i in issues if i.category == "automation"]
        base_score -= len(auto_issues) * 10
        
        return max(0, base_score)
    
    def _calculate_maintainability_score(self, content: str, issues: List[TestIssue]) -> float:
        """Calculate test maintainability score."""
        base_score = 80
        
        # Deduct for maintainability issues
        maintainability_issues = [i for i in issues if i.impact == "MAINTAINABILITY"]
        base_score -= len(maintainability_issues) * 10
        
        return max(0, base_score)
    
    def _estimate_coverage(self, content: str) -> float:
        """Estimate test coverage based on content analysis."""
        # Simple heuristic: ratio of test methods to total methods
        test_methods = len(re.findall(r'def\s+test_\w+', content))
        total_methods = len(re.findall(r'def\s+\w+', content))
        
        if total_methods == 0:
            return 0
        
        return min(100, (test_methods / total_methods) * 100)
    
    # Severity and remediation methods
    def _get_anti_pattern_severity(self, anti_pattern: str) -> str:
        severity_map = {
            'no_assertions': 'HIGH',
            'empty_tests': 'HIGH',
            'hardcoded_values': 'MEDIUM',
            'sleep_in_tests': 'HIGH',
            'print_debugging': 'LOW',
            'commented_assertions': 'MEDIUM',
            'test_dependencies': 'HIGH',
            'database_in_unit_tests': 'HIGH',
            'network_in_unit_tests': 'HIGH'
        }
        return severity_map.get(anti_pattern, 'MEDIUM')
    
    def _get_anti_pattern_remediation(self, anti_pattern: str) -> str:
        remediation_map = {
            'no_assertions': 'Add appropriate assertions to validate test expectations',
            'empty_tests': 'Implement test logic or remove empty test methods',
            'hardcoded_values': 'Use test fixtures or parameterized tests',
            'sleep_in_tests': 'Use mocking or proper synchronization instead of sleep',
            'print_debugging': 'Remove print statements and use proper logging',
            'commented_assertions': 'Uncomment assertions or remove if not needed',
            'test_dependencies': 'Make tests independent and isolated',
            'database_in_unit_tests': 'Use mocking for database interactions in unit tests',
            'network_in_unit_tests': 'Use mocking for network calls in unit tests'
        }
        return remediation_map.get(anti_pattern, 'Review and fix the identified anti-pattern')
    
    # Recommendation generation methods
    def _generate_coverage_recommendations(self, issues: List[TestIssue]) -> List[str]:
        return [
            "Increase test coverage to at least 80%",
            "Add tests for edge cases and error conditions",
            "Use coverage tools to identify untested code paths",
            "Implement integration tests for complex workflows"
        ]
    
    def _generate_quality_recommendations(self, issues: List[TestIssue]) -> List[str]:
        return [
            "Follow the Arrange-Act-Assert pattern",
            "Use descriptive test method names",
            "Keep tests focused and independent",
            "Remove test anti-patterns and code smells"
        ]
    
    def _generate_framework_recommendations(self, frameworks: List[str], issues: List[TestIssue]) -> List[str]:
        if not frameworks:
            return ["Adopt a test framework like pytest or unittest"]
        elif len(frameworks) > 1:
            return ["Standardize on a single test framework"]
        else:
            return ["Continue using the current test framework effectively"]
    
    def _generate_performance_recommendations(self, tools: List[str], issues: List[TestIssue]) -> List[str]:
        if not tools:
            return [
                "Add performance tests for critical code paths",
                "Use benchmarking tools like pytest-benchmark",
                "Implement load testing for APIs",
                "Monitor performance regressions in CI/CD"
            ]
        else:
            return ["Expand performance test coverage"]
    
    def _generate_automation_recommendations(self, tools: List[str], issues: List[TestIssue]) -> List[str]:
        return [
            "Integrate tests into CI/CD pipeline",
            "Automate test execution and reporting",
            "Set up automated test result notifications",
            "Implement test parallelization for faster execution"
        ]

