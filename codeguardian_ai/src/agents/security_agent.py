"""
CodeGuardian AI - Security Agent
Enterprise-grade security analysis agent specializing in vulnerability detection,
threat assessment, and security best practices validation.

This agent implements advanced security analysis capabilities including:
- Static code analysis for security vulnerabilities
- Dynamic security testing and validation
- Threat intelligence integration
- Security best practices compliance
- Risk assessment and scoring
"""

import ast
import re
import hashlib
import subprocess
import tempfile
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass
from pathlib import Path

import bandit
from bandit.core import manager as bandit_manager
from bandit.core import config as bandit_config
import semgrep
import safety
import requests

from .base_agent import BaseAgent, AgentCapability, AnalysisTask, TaskStatus
from ..config.enterprise_config import EnterpriseConfig


@dataclass
class SecurityVulnerability:
    """Represents a security vulnerability found in code."""
    vulnerability_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # e.g., "injection", "crypto", "auth"
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    confidence: float = 0.0
    remediation: Optional[str] = None
    references: List[str] = None
    
    def __post_init__(self):
        if self.references is None:
            self.references = []


@dataclass
class ThreatIntelligence:
    """Threat intelligence data for enhanced security analysis."""
    threat_id: str
    threat_type: str
    indicators: List[str]
    severity: str
    description: str
    mitigation: str
    last_updated: datetime


class SecurityAgent(BaseAgent):
    """
    Specialized agent for comprehensive security analysis and threat detection.
    
    This agent provides enterprise-grade security analysis capabilities including
    static analysis, dynamic testing, threat intelligence integration, and
    compliance validation.
    """
    
    # Security pattern definitions
    SECURITY_PATTERNS = {
        'sql_injection': [
            r'execute\s*\(\s*["\'].*%.*["\']',
            r'cursor\.execute\s*\(\s*["\'].*\+.*["\']',
            r'query\s*=\s*["\'].*%.*["\']',
            r'SELECT\s+.*\+.*FROM',
            r'INSERT\s+.*\+.*VALUES',
            r'UPDATE\s+.*SET.*\+',
            r'DELETE\s+.*WHERE.*\+'
        ],
        'xss': [
            r'innerHTML\s*=\s*.*\+',
            r'document\.write\s*\(\s*.*\+',
            r'eval\s*\(\s*.*\+',
            r'setTimeout\s*\(\s*.*\+',
            r'setInterval\s*\(\s*.*\+'
        ],
        'command_injection': [
            r'os\.system\s*\(\s*.*\+',
            r'subprocess\.(call|run|Popen)\s*\(\s*.*\+',
            r'exec\s*\(\s*.*\+',
            r'eval\s*\(\s*.*\+',
            r'shell=True.*\+',
            r'system\s*\(\s*.*\+'
        ],
        'path_traversal': [
            r'open\s*\(\s*.*\+.*\.\.',
            r'file\s*\(\s*.*\+.*\.\.',
            r'\.\.\/.*\+',
            r'\.\.\\.*\+',
            r'os\.path\.join\s*\(\s*.*\+.*\.\.'
        ],
        'hardcoded_secrets': [
            r'password\s*=\s*["\'][^"\']{8,}["\']',
            r'api_key\s*=\s*["\'][^"\']{16,}["\']',
            r'secret\s*=\s*["\'][^"\']{16,}["\']',
            r'token\s*=\s*["\'][^"\']{20,}["\']',
            r'private_key\s*=\s*["\'].*BEGIN.*PRIVATE.*KEY',
            r'aws_secret_access_key\s*=\s*["\'][^"\']{20,}["\']'
        ],
        'crypto_issues': [
            r'md5\s*\(',
            r'sha1\s*\(',
            r'DES\s*\(',
            r'RC4\s*\(',
            r'random\.random\s*\(',
            r'ssl\.PROTOCOL_SSLv[23]',
            r'ssl\.PROTOCOL_TLSv1[^2]'
        ],
        'auth_bypass': [
            r'if\s+.*==\s*["\']admin["\']',
            r'if\s+.*==\s*["\']root["\']',
            r'if\s+.*==\s*["\']password["\']',
            r'auth\s*=\s*False',
            r'authenticated\s*=\s*True',
            r'is_admin\s*=\s*True'
        ]
    }
    
    # CWE mappings for common vulnerabilities
    CWE_MAPPINGS = {
        'sql_injection': 'CWE-89',
        'xss': 'CWE-79',
        'command_injection': 'CWE-78',
        'path_traversal': 'CWE-22',
        'hardcoded_secrets': 'CWE-798',
        'crypto_issues': 'CWE-327',
        'auth_bypass': 'CWE-287'
    }
    
    def __init__(self, agent_id: str, config: EnterpriseConfig, **kwargs):
        """Initialize the Security Agent with specialized capabilities."""
        super().__init__(agent_id, "security", config, **kwargs)
        
        # Initialize security-specific components
        self.threat_intelligence_cache = {}
        self.vulnerability_database = {}
        self.security_rules_engine = None
        
        # Initialize external security tools
        self._initialize_security_tools()
        
        # Load threat intelligence
        self._load_threat_intelligence()
        
        self.logger.info("Security Agent initialized with advanced threat detection capabilities")
    
    def _initialize_capabilities(self) -> None:
        """Initialize security-specific capabilities."""
        capabilities = [
            AgentCapability(
                name="static_security_analysis",
                description="Static code analysis for security vulnerabilities",
                confidence_level=0.95
            ),
            AgentCapability(
                name="dynamic_security_testing",
                description="Dynamic security testing and validation",
                confidence_level=0.85
            ),
            AgentCapability(
                name="threat_intelligence_analysis",
                description="Integration with threat intelligence feeds",
                confidence_level=0.90
            ),
            AgentCapability(
                name="vulnerability_assessment",
                description="Comprehensive vulnerability assessment and scoring",
                confidence_level=0.92
            ),
            AgentCapability(
                name="compliance_validation",
                description="Security compliance and best practices validation",
                confidence_level=0.88
            ),
            AgentCapability(
                name="dependency_security_scan",
                description="Security scanning of dependencies and libraries",
                confidence_level=0.93
            ),
            AgentCapability(
                name="crypto_analysis",
                description="Cryptographic implementation analysis",
                confidence_level=0.87
            ),
            AgentCapability(
                name="auth_security_review",
                description="Authentication and authorization security review",
                confidence_level=0.89
            )
        ]
        
        for capability in capabilities:
            self.add_capability(capability)
    
    def _initialize_security_tools(self) -> None:
        """Initialize external security analysis tools."""
        try:
            # Initialize Bandit for Python security analysis
            self.bandit_config = bandit_config.BanditConfig()
            self.bandit_manager = bandit_manager.BanditManager(
                self.bandit_config,
                'file'
            )
            
            self.logger.info("Security tools initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize security tools: {str(e)}")
    
    def _load_threat_intelligence(self) -> None:
        """Load threat intelligence data from various sources."""
        try:
            # Load from local threat intelligence database
            # In production, this would integrate with threat feeds
            self.threat_intelligence_cache = {
                "malicious_patterns": [
                    "eval(base64_decode(",
                    "system($_GET",
                    "exec($_POST",
                    "shell_exec(",
                    "passthru(",
                ],
                "suspicious_functions": [
                    "exec", "eval", "system", "shell_exec", "passthru",
                    "file_get_contents", "curl_exec", "fopen", "include",
                    "require", "preg_replace"
                ],
                "crypto_weaknesses": [
                    "md5", "sha1", "des", "rc4", "ssl2", "ssl3", "tls1.0"
                ]
            }
            
            self.logger.info("Threat intelligence loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to load threat intelligence: {str(e)}")
    
    async def analyze(self, task: AnalysisTask) -> Dict[str, Any]:
        """
        Perform comprehensive security analysis on the provided code.
        
        Args:
            task: Analysis task containing code and context
            
        Returns:
            Dictionary containing security analysis results
        """
        try:
            code = task.payload.get('code', '')
            language = task.payload.get('language', 'python')
            file_path = task.payload.get('file_path', 'unknown')
            
            if not code:
                raise ValueError("No code provided for security analysis")
            
            self.logger.info(f"Starting security analysis for {file_path}")
            
            # Perform multi-layered security analysis
            results = {
                "analysis_type": "security",
                "agent_id": self.agent_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "file_path": file_path,
                "language": language,
                "vulnerabilities": [],
                "security_score": 0.0,
                "risk_level": "UNKNOWN",
                "recommendations": [],
                "compliance_status": {},
                "threat_intelligence_matches": [],
                "summary": {}
            }
            
            # 1. Static pattern-based analysis
            pattern_vulnerabilities = await self._analyze_security_patterns(code, file_path)
            results["vulnerabilities"].extend(pattern_vulnerabilities)
            
            # 2. AST-based security analysis
            if language.lower() == 'python':
                ast_vulnerabilities = await self._analyze_python_ast(code, file_path)
                results["vulnerabilities"].extend(ast_vulnerabilities)
            
            # 3. Bandit analysis for Python
            if language.lower() == 'python':
                bandit_vulnerabilities = await self._run_bandit_analysis(code, file_path)
                results["vulnerabilities"].extend(bandit_vulnerabilities)
            
            # 4. Dependency security analysis
            dependency_vulnerabilities = await self._analyze_dependencies(code, language)
            results["vulnerabilities"].extend(dependency_vulnerabilities)
            
            # 5. Threat intelligence matching
            threat_matches = await self._match_threat_intelligence(code)
            results["threat_intelligence_matches"] = threat_matches
            
            # 6. Cryptographic analysis
            crypto_issues = await self._analyze_cryptography(code, language)
            results["vulnerabilities"].extend(crypto_issues)
            
            # 7. Authentication and authorization analysis
            auth_issues = await self._analyze_authentication(code, language)
            results["vulnerabilities"].extend(auth_issues)
            
            # Calculate security score and risk level
            results["security_score"] = self._calculate_security_score(results["vulnerabilities"])
            results["risk_level"] = self._determine_risk_level(results["vulnerabilities"])
            
            # Generate recommendations
            results["recommendations"] = self._generate_security_recommendations(results["vulnerabilities"])
            
            # Compliance validation
            results["compliance_status"] = await self._validate_compliance(results["vulnerabilities"])
            
            # Generate summary
            results["summary"] = self._generate_security_summary(results)
            
            self.logger.info(f"Security analysis completed. Found {len(results['vulnerabilities'])} issues")
            
            return {
                "success": True,
                "data": results,
                "meta": {
                    "analysis_time": (datetime.now(timezone.utc) - datetime.fromisoformat(results["timestamp"])).total_seconds(),
                    "vulnerabilities_found": len(results["vulnerabilities"]),
                    "security_score": results["security_score"],
                    "risk_level": results["risk_level"]
                }
            }
            
        except Exception as e:
            self.logger.error(f"Security analysis failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "data": None
            }
    
    async def _analyze_security_patterns(self, code: str, file_path: str) -> List[SecurityVulnerability]:
        """Analyze code using security pattern matching."""
        vulnerabilities = []
        lines = code.split('\n')
        
        for category, patterns in self.SECURITY_PATTERNS.items():
            for pattern in patterns:
                regex = re.compile(pattern, re.IGNORECASE | re.MULTILINE)
                
                for line_num, line in enumerate(lines, 1):
                    matches = regex.finditer(line)
                    
                    for match in matches:
                        vulnerability = SecurityVulnerability(
                            vulnerability_id=f"PATTERN_{category.upper()}_{hashlib.md5(f'{file_path}:{line_num}:{match.group()}'.encode()).hexdigest()[:8]}",
                            severity=self._get_pattern_severity(category),
                            category=category,
                            title=f"Potential {category.replace('_', ' ').title()} Vulnerability",
                            description=f"Pattern matching detected potential {category} vulnerability",
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=line.strip(),
                            cwe_id=self.CWE_MAPPINGS.get(category),
                            confidence=0.7,
                            remediation=self._get_remediation_advice(category)
                        )
                        
                        vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    async def _analyze_python_ast(self, code: str, file_path: str) -> List[SecurityVulnerability]:
        """Perform AST-based security analysis for Python code."""
        vulnerabilities = []
        
        try:
            tree = ast.parse(code)
            
            class SecurityVisitor(ast.NodeVisitor):
                def __init__(self):
                    self.vulnerabilities = []
                
                def visit_Call(self, node):
                    # Check for dangerous function calls
                    if isinstance(node.func, ast.Name):
                        func_name = node.func.id
                        
                        if func_name in ['exec', 'eval']:
                            vuln = SecurityVulnerability(
                                vulnerability_id=f"AST_EXEC_{hashlib.md5(f'{file_path}:{node.lineno}'.encode()).hexdigest()[:8]}",
                                severity="HIGH",
                                category="code_injection",
                                title=f"Dangerous use of {func_name}()",
                                description=f"Use of {func_name}() can lead to code injection vulnerabilities",
                                file_path=file_path,
                                line_number=node.lineno,
                                code_snippet=ast.get_source_segment(code, node) or f"{func_name}(...)",
                                cwe_id="CWE-94",
                                confidence=0.9,
                                remediation=f"Avoid using {func_name}() with user input. Use safer alternatives."
                            )
                            self.vulnerabilities.append(vuln)
                    
                    self.generic_visit(node)
                
                def visit_Import(self, node):
                    # Check for imports of dangerous modules
                    for alias in node.names:
                        if alias.name in ['pickle', 'cPickle', 'marshal']:
                            vuln = SecurityVulnerability(
                                vulnerability_id=f"AST_IMPORT_{hashlib.md5(f'{file_path}:{node.lineno}:{alias.name}'.encode()).hexdigest()[:8]}",
                                severity="MEDIUM",
                                category="deserialization",
                                title=f"Potentially unsafe import: {alias.name}",
                                description=f"Module {alias.name} can be unsafe for deserializing untrusted data",
                                file_path=file_path,
                                line_number=node.lineno,
                                code_snippet=f"import {alias.name}",
                                cwe_id="CWE-502",
                                confidence=0.6,
                                remediation=f"Be cautious when using {alias.name} with untrusted data"
                            )
                            self.vulnerabilities.append(vuln)
                    
                    self.generic_visit(node)
            
            visitor = SecurityVisitor()
            visitor.visit(tree)
            vulnerabilities.extend(visitor.vulnerabilities)
            
        except SyntaxError as e:
            self.logger.warning(f"Could not parse Python code for AST analysis: {str(e)}")
        
        return vulnerabilities
    
    async def _run_bandit_analysis(self, code: str, file_path: str) -> List[SecurityVulnerability]:
        """Run Bandit security analysis on Python code."""
        vulnerabilities = []
        
        try:
            # Create temporary file for Bandit analysis
            with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as temp_file:
                temp_file.write(code)
                temp_file_path = temp_file.name
            
            try:
                # Run Bandit analysis
                self.bandit_manager.discover([temp_file_path])
                self.bandit_manager.run_tests()
                
                # Process Bandit results
                for result in self.bandit_manager.get_issue_list():
                    vulnerability = SecurityVulnerability(
                        vulnerability_id=f"BANDIT_{result.test_id}_{hashlib.md5(f'{file_path}:{result.lineno}'.encode()).hexdigest()[:8]}",
                        severity=result.severity.upper(),
                        category="bandit_" + result.test_id.lower(),
                        title=result.text,
                        description=result.text,
                        file_path=file_path,
                        line_number=result.lineno,
                        code_snippet=result.get_code(),
                        cwe_id=getattr(result, 'cwe_id', None),
                        confidence=self._convert_bandit_confidence(result.confidence),
                        remediation="Review Bandit documentation for specific remediation advice"
                    )
                    vulnerabilities.append(vulnerability)
                    
            finally:
                # Clean up temporary file
                os.unlink(temp_file_path)
                
        except Exception as e:
            self.logger.warning(f"Bandit analysis failed: {str(e)}")
        
        return vulnerabilities
    
    async def _analyze_dependencies(self, code: str, language: str) -> List[SecurityVulnerability]:
        """Analyze dependencies for known security vulnerabilities."""
        vulnerabilities = []
        
        try:
            if language.lower() == 'python':
                # Extract import statements
                imports = re.findall(r'^(?:from\s+(\S+)\s+)?import\s+(\S+)', code, re.MULTILINE)
                packages = set()
                
                for from_pkg, import_pkg in imports:
                    if from_pkg:
                        packages.add(from_pkg.split('.')[0])
                    packages.add(import_pkg.split('.')[0])
                
                # Check against known vulnerable packages (simplified)
                vulnerable_packages = {
                    'pickle': 'Deserialization vulnerability',
                    'yaml': 'Potential code execution via unsafe loading',
                    'requests': 'Check version for known CVEs'
                }
                
                for package in packages:
                    if package in vulnerable_packages:
                        vulnerability = SecurityVulnerability(
                            vulnerability_id=f"DEP_{package.upper()}_{hashlib.md5(package.encode()).hexdigest()[:8]}",
                            severity="MEDIUM",
                            category="dependency_vulnerability",
                            title=f"Potentially vulnerable dependency: {package}",
                            description=vulnerable_packages[package],
                            file_path="dependencies",
                            line_number=0,
                            code_snippet=f"import {package}",
                            confidence=0.5,
                            remediation=f"Review {package} usage and update to latest secure version"
                        )
                        vulnerabilities.append(vulnerability)
                        
        except Exception as e:
            self.logger.warning(f"Dependency analysis failed: {str(e)}")
        
        return vulnerabilities
    
    async def _match_threat_intelligence(self, code: str) -> List[Dict[str, Any]]:
        """Match code against threat intelligence patterns."""
        matches = []
        
        try:
            for pattern in self.threat_intelligence_cache.get("malicious_patterns", []):
                if pattern in code:
                    matches.append({
                        "pattern": pattern,
                        "type": "malicious_pattern",
                        "severity": "HIGH",
                        "description": f"Code contains known malicious pattern: {pattern}"
                    })
            
            for func in self.threat_intelligence_cache.get("suspicious_functions", []):
                if re.search(rf'\b{func}\s*\(', code):
                    matches.append({
                        "pattern": func,
                        "type": "suspicious_function",
                        "severity": "MEDIUM",
                        "description": f"Code uses potentially dangerous function: {func}"
                    })
                    
        except Exception as e:
            self.logger.warning(f"Threat intelligence matching failed: {str(e)}")
        
        return matches
    
    async def _analyze_cryptography(self, code: str, language: str) -> List[SecurityVulnerability]:
        """Analyze cryptographic implementations for security issues."""
        vulnerabilities = []
        
        crypto_patterns = {
            'weak_hash': [r'md5\s*\(', r'sha1\s*\('],
            'weak_cipher': [r'DES\s*\(', r'RC4\s*\(', r'ECB'],
            'weak_random': [r'random\.random\s*\(', r'Math\.random\s*\('],
            'weak_ssl': [r'ssl\.PROTOCOL_SSLv[23]', r'ssl\.PROTOCOL_TLSv1[^2]']
        }
        
        lines = code.split('\n')
        
        for category, patterns in crypto_patterns.items():
            for pattern in patterns:
                regex = re.compile(pattern, re.IGNORECASE)
                
                for line_num, line in enumerate(lines, 1):
                    if regex.search(line):
                        vulnerability = SecurityVulnerability(
                            vulnerability_id=f"CRYPTO_{category.upper()}_{hashlib.md5(f'{line_num}:{line}'.encode()).hexdigest()[:8]}",
                            severity="HIGH" if category in ['weak_cipher', 'weak_ssl'] else "MEDIUM",
                            category="cryptographic_weakness",
                            title=f"Weak cryptographic implementation: {category}",
                            description=f"Use of weak cryptographic algorithm or implementation",
                            file_path="analyzed_code",
                            line_number=line_num,
                            code_snippet=line.strip(),
                            cwe_id="CWE-327",
                            confidence=0.8,
                            remediation="Use strong, modern cryptographic algorithms and implementations"
                        )
                        vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    async def _analyze_authentication(self, code: str, language: str) -> List[SecurityVulnerability]:
        """Analyze authentication and authorization implementations."""
        vulnerabilities = []
        
        auth_patterns = {
            'hardcoded_credentials': [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'api_key\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']'
            ],
            'weak_session': [
                r'session\[.*\]\s*=\s*True',
                r'authenticated\s*=\s*True',
                r'is_admin\s*=\s*True'
            ],
            'auth_bypass': [
                r'if\s+.*==\s*["\']admin["\']',
                r'if\s+.*==\s*["\']password["\']'
            ]
        }
        
        lines = code.split('\n')
        
        for category, patterns in auth_patterns.items():
            for pattern in patterns:
                regex = re.compile(pattern, re.IGNORECASE)
                
                for line_num, line in enumerate(lines, 1):
                    if regex.search(line):
                        vulnerability = SecurityVulnerability(
                            vulnerability_id=f"AUTH_{category.upper()}_{hashlib.md5(f'{line_num}:{line}'.encode()).hexdigest()[:8]}",
                            severity="HIGH" if category == 'auth_bypass' else "MEDIUM",
                            category="authentication_weakness",
                            title=f"Authentication issue: {category}",
                            description=f"Potential authentication or authorization weakness",
                            file_path="analyzed_code",
                            line_number=line_num,
                            code_snippet=line.strip(),
                            cwe_id="CWE-287",
                            confidence=0.7,
                            remediation="Implement secure authentication and authorization mechanisms"
                        )
                        vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _calculate_security_score(self, vulnerabilities: List[SecurityVulnerability]) -> float:
        """Calculate overall security score based on vulnerabilities found."""
        if not vulnerabilities:
            return 100.0
        
        severity_weights = {
            'CRITICAL': 25,
            'HIGH': 15,
            'MEDIUM': 8,
            'LOW': 3,
            'INFO': 1
        }
        
        total_penalty = sum(severity_weights.get(vuln.severity, 5) for vuln in vulnerabilities)
        
        # Base score of 100, subtract penalties
        score = max(0, 100 - total_penalty)
        
        return round(score, 1)
    
    def _determine_risk_level(self, vulnerabilities: List[SecurityVulnerability]) -> str:
        """Determine overall risk level based on vulnerabilities."""
        if not vulnerabilities:
            return "LOW"
        
        severity_counts = {}
        for vuln in vulnerabilities:
            severity_counts[vuln.severity] = severity_counts.get(vuln.severity, 0) + 1
        
        if severity_counts.get('CRITICAL', 0) > 0:
            return "CRITICAL"
        elif severity_counts.get('HIGH', 0) >= 3:
            return "CRITICAL"
        elif severity_counts.get('HIGH', 0) > 0:
            return "HIGH"
        elif severity_counts.get('MEDIUM', 0) >= 5:
            return "HIGH"
        elif severity_counts.get('MEDIUM', 0) > 0:
            return "MEDIUM"
        else:
            return "LOW"
    
    def _generate_security_recommendations(self, vulnerabilities: List[SecurityVulnerability]) -> List[Dict[str, Any]]:
        """Generate security recommendations based on found vulnerabilities."""
        recommendations = []
        
        # Group vulnerabilities by category
        categories = {}
        for vuln in vulnerabilities:
            if vuln.category not in categories:
                categories[vuln.category] = []
            categories[vuln.category].append(vuln)
        
        # Generate recommendations for each category
        for category, vulns in categories.items():
            recommendation = {
                "category": category,
                "priority": self._get_category_priority(category),
                "title": f"Address {category.replace('_', ' ').title()} Issues",
                "description": f"Found {len(vulns)} {category} vulnerabilities",
                "action_items": self._get_category_action_items(category),
                "affected_lines": [vuln.line_number for vuln in vulns]
            }
            recommendations.append(recommendation)
        
        # Sort by priority
        recommendations.sort(key=lambda x: x["priority"])
        
        return recommendations
    
    async def _validate_compliance(self, vulnerabilities: List[SecurityVulnerability]) -> Dict[str, Any]:
        """Validate compliance with security standards."""
        compliance_status = {
            "OWASP_Top_10": self._check_owasp_compliance(vulnerabilities),
            "CWE_Top_25": self._check_cwe_compliance(vulnerabilities),
            "PCI_DSS": self._check_pci_compliance(vulnerabilities),
            "SOC2": self._check_soc2_compliance(vulnerabilities)
        }
        
        return compliance_status
    
    def _generate_security_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive security analysis summary."""
        vulnerabilities = results["vulnerabilities"]
        
        summary = {
            "total_vulnerabilities": len(vulnerabilities),
            "severity_breakdown": {},
            "category_breakdown": {},
            "security_score": results["security_score"],
            "risk_level": results["risk_level"],
            "top_concerns": [],
            "compliance_summary": results.get("compliance_status", {}),
            "remediation_priority": []
        }
        
        # Calculate severity breakdown
        for vuln in vulnerabilities:
            summary["severity_breakdown"][vuln.severity] = summary["severity_breakdown"].get(vuln.severity, 0) + 1
            summary["category_breakdown"][vuln.category] = summary["category_breakdown"].get(vuln.category, 0) + 1
        
        # Identify top concerns
        critical_high = [v for v in vulnerabilities if v.severity in ['CRITICAL', 'HIGH']]
        summary["top_concerns"] = [
            {
                "title": vuln.title,
                "severity": vuln.severity,
                "line": vuln.line_number,
                "category": vuln.category
            }
            for vuln in critical_high[:5]  # Top 5 critical/high issues
        ]
        
        return summary
    
    # Helper methods
    def _get_pattern_severity(self, category: str) -> str:
        """Get severity level for security pattern category."""
        severity_map = {
            'sql_injection': 'HIGH',
            'xss': 'HIGH',
            'command_injection': 'CRITICAL',
            'path_traversal': 'HIGH',
            'hardcoded_secrets': 'HIGH',
            'crypto_issues': 'MEDIUM',
            'auth_bypass': 'CRITICAL'
        }
        return severity_map.get(category, 'MEDIUM')
    
    def _get_remediation_advice(self, category: str) -> str:
        """Get remediation advice for security category."""
        advice_map = {
            'sql_injection': 'Use parameterized queries or prepared statements',
            'xss': 'Sanitize and escape user input, use Content Security Policy',
            'command_injection': 'Avoid executing system commands with user input',
            'path_traversal': 'Validate and sanitize file paths, use allowlists',
            'hardcoded_secrets': 'Use environment variables or secure key management',
            'crypto_issues': 'Use strong, modern cryptographic algorithms',
            'auth_bypass': 'Implement proper authentication and authorization checks'
        }
        return advice_map.get(category, 'Review and fix the identified security issue')
    
    def _convert_bandit_confidence(self, confidence: str) -> float:
        """Convert Bandit confidence level to numeric value."""
        confidence_map = {
            'HIGH': 0.9,
            'MEDIUM': 0.7,
            'LOW': 0.5
        }
        return confidence_map.get(confidence.upper(), 0.5)
    
    def _get_category_priority(self, category: str) -> int:
        """Get priority level for vulnerability category."""
        priority_map = {
            'command_injection': 1,
            'sql_injection': 2,
            'auth_bypass': 3,
            'xss': 4,
            'path_traversal': 5,
            'hardcoded_secrets': 6,
            'crypto_issues': 7
        }
        return priority_map.get(category, 10)
    
    def _get_category_action_items(self, category: str) -> List[str]:
        """Get action items for vulnerability category."""
        action_map = {
            'sql_injection': [
                'Replace string concatenation with parameterized queries',
                'Use ORM frameworks with built-in protection',
                'Validate and sanitize all user inputs'
            ],
            'xss': [
                'Escape user input in HTML output',
                'Use Content Security Policy headers',
                'Validate input on both client and server side'
            ],
            'command_injection': [
                'Avoid system command execution with user input',
                'Use safe APIs instead of shell commands',
                'Implement strict input validation'
            ]
        }
        return action_map.get(category, ['Review and fix identified issues'])
    
    def _check_owasp_compliance(self, vulnerabilities: List[SecurityVulnerability]) -> Dict[str, Any]:
        """Check compliance with OWASP Top 10."""
        owasp_categories = {
            'A01_Broken_Access_Control': ['auth_bypass', 'authentication_weakness'],
            'A02_Cryptographic_Failures': ['crypto_issues', 'cryptographic_weakness'],
            'A03_Injection': ['sql_injection', 'command_injection', 'code_injection'],
            'A04_Insecure_Design': ['hardcoded_secrets'],
            'A05_Security_Misconfiguration': ['weak_ssl', 'weak_cipher']
        }
        
        compliance = {}
        for owasp_cat, vuln_categories in owasp_categories.items():
            violations = [v for v in vulnerabilities if v.category in vuln_categories]
            compliance[owasp_cat] = {
                'compliant': len(violations) == 0,
                'violations': len(violations),
                'severity': 'HIGH' if violations else 'NONE'
            }
        
        return compliance
    
    def _check_cwe_compliance(self, vulnerabilities: List[SecurityVulnerability]) -> Dict[str, Any]:
        """Check compliance with CWE Top 25."""
        cwe_violations = {}
        for vuln in vulnerabilities:
            if vuln.cwe_id:
                if vuln.cwe_id not in cwe_violations:
                    cwe_violations[vuln.cwe_id] = 0
                cwe_violations[vuln.cwe_id] += 1
        
        return {
            'total_cwe_violations': len(cwe_violations),
            'violations_by_cwe': cwe_violations,
            'compliance_score': max(0, 100 - len(cwe_violations) * 5)
        }
    
    def _check_pci_compliance(self, vulnerabilities: List[SecurityVulnerability]) -> Dict[str, Any]:
        """Check PCI DSS compliance relevant issues."""
        pci_relevant = [
            v for v in vulnerabilities 
            if v.category in ['crypto_issues', 'hardcoded_secrets', 'auth_bypass']
        ]
        
        return {
            'compliant': len(pci_relevant) == 0,
            'violations': len(pci_relevant),
            'risk_level': 'HIGH' if pci_relevant else 'LOW'
        }
    
    def _check_soc2_compliance(self, vulnerabilities: List[SecurityVulnerability]) -> Dict[str, Any]:
        """Check SOC 2 compliance relevant issues."""
        soc2_relevant = [
            v for v in vulnerabilities 
            if v.severity in ['CRITICAL', 'HIGH']
        ]
        
        return {
            'compliant': len(soc2_relevant) == 0,
            'violations': len(soc2_relevant),
            'audit_ready': len(soc2_relevant) == 0
        }

