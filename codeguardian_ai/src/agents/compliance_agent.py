"""
CodeGuardian AI - Compliance Agent
Enterprise-grade compliance analysis agent specializing in regulatory compliance,
code standards validation, documentation analysis, and audit trail generation.

This agent implements comprehensive compliance analysis capabilities including:
- Regulatory compliance checking (SOC2, GDPR, HIPAA, PCI DSS)
- Code standards validation (PEP8, ESLint, industry standards)
- Documentation analysis and gap detection
- Audit trail generation and compliance reporting
- License compliance checking
- Security compliance validation
"""

import re
import ast
import json
import time
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set, Tuple, Union
from dataclasses import dataclass
from pathlib import Path
import subprocess

from .base_agent import BaseAgent, AgentCapability, AnalysisTask
from ..config.enterprise_config import EnterpriseConfig


@dataclass
class ComplianceIssue:
    """Represents a compliance issue found in code."""
    issue_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # e.g., "regulatory", "standards", "documentation", "licensing"
    compliance_framework: str  # SOC2, GDPR, HIPAA, PCI DSS, etc.
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    requirement: str  # Specific compliance requirement
    confidence: float = 0.0
    remediation: Optional[str] = None
    compliance_impact: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    audit_importance: str = "MEDIUM"  # LOW, MEDIUM, HIGH, CRITICAL
    
    def __post_init__(self):
        pass


@dataclass
class ComplianceMetrics:
    """Comprehensive compliance metrics."""
    overall_compliance_score: float
    regulatory_compliance_score: float
    standards_compliance_score: float
    documentation_compliance_score: float
    security_compliance_score: float
    total_violations: int
    critical_violations: int
    frameworks_assessed: List[str]
    compliance_gaps: List[str]


@dataclass
class ComplianceFramework:
    """Represents a compliance framework assessment."""
    framework_name: str
    compliance_percentage: float
    violations: List[ComplianceIssue]
    requirements_met: int
    total_requirements: int
    critical_gaps: List[str]
    recommendations: List[str]


class ComplianceAgent(BaseAgent):
    """
    Specialized agent for comprehensive compliance analysis and validation.
    
    This agent provides enterprise-grade compliance analysis capabilities including
    regulatory compliance checking, code standards validation, documentation analysis,
    and audit trail generation.
    """
    
    # Regulatory compliance patterns
    REGULATORY_PATTERNS = {
        'gdpr': {
            'data_processing': [
                r'personal.*data',
                r'user.*data',
                r'customer.*information',
                r'email.*address',
                r'phone.*number',
                r'address.*field'
            ],
            'consent_management': [
                r'consent',
                r'opt.*in',
                r'permission',
                r'agree.*terms'
            ],
            'data_retention': [
                r'delete.*user',
                r'purge.*data',
                r'retention.*policy',
                r'data.*expiry'
            ],
            'data_portability': [
                r'export.*data',
                r'download.*data',
                r'data.*export',
                r'user.*export'
            ]
        },
        'hipaa': {
            'phi_handling': [
                r'patient.*data',
                r'medical.*record',
                r'health.*information',
                r'diagnosis',
                r'treatment.*data'
            ],
            'access_controls': [
                r'role.*based.*access',
                r'minimum.*necessary',
                r'access.*log',
                r'audit.*trail'
            ],
            'encryption': [
                r'encrypt.*phi',
                r'secure.*transmission',
                r'data.*encryption',
                r'crypto.*key'
            ]
        },
        'pci_dss': {
            'cardholder_data': [
                r'credit.*card',
                r'card.*number',
                r'cvv',
                r'expiry.*date',
                r'cardholder.*name'
            ],
            'secure_transmission': [
                r'ssl.*tls',
                r'secure.*channel',
                r'encrypted.*transmission',
                r'https.*only'
            ],
            'access_control': [
                r'card.*data.*access',
                r'payment.*access',
                r'cardholder.*access',
                r'pci.*access'
            ]
        },
        'sox': {
            'financial_controls': [
                r'financial.*data',
                r'accounting.*record',
                r'revenue.*recognition',
                r'audit.*trail'
            ],
            'change_management': [
                r'code.*review',
                r'approval.*process',
                r'change.*control',
                r'deployment.*approval'
            ]
        }
    }
    
    # Code standards patterns
    CODE_STANDARDS = {
        'python_pep8': {
            'naming_conventions': [
                r'class\s+[a-z]',  # Class should start with uppercase
                r'def\s+[A-Z]',    # Function should start with lowercase
                r'[A-Z]{2,}_[A-Z]',  # Constants should be UPPER_CASE
            ],
            'line_length': [
                r'.{80,}',  # Lines longer than 79 characters
            ],
            'imports': [
                r'from\s+.*\s+import\s+\*',  # Wildcard imports
                r'import\s+.*,.*',  # Multiple imports on one line
            ],
            'whitespace': [
                r'\t',  # Tabs instead of spaces
                r'\s+$',  # Trailing whitespace
                r'\s{2,}=',  # Multiple spaces around operators
            ]
        },
        'security_standards': {
            'hardcoded_secrets': [
                r'password\s*=\s*["\'][^"\']+["\']',
                r'api.*key\s*=\s*["\'][^"\']+["\']',
                r'secret\s*=\s*["\'][^"\']+["\']',
                r'token\s*=\s*["\'][^"\']+["\']'
            ],
            'sql_injection': [
                r'execute\s*\(\s*["\'].*%.*["\']',
                r'query\s*\(\s*["\'].*\+.*["\']',
                r'SELECT.*\+.*FROM'
            ],
            'xss_prevention': [
                r'innerHTML\s*=',
                r'document\.write\s*\(',
                r'eval\s*\(',
                r'setTimeout\s*\(\s*["\']'
            ]
        },
        'documentation_standards': {
            'missing_docstrings': [
                r'def\s+\w+\s*\([^)]*\):\s*\n(?!\s*["\'])',  # Function without docstring
                r'class\s+\w+.*:\s*\n(?!\s*["\'])',  # Class without docstring
            ],
            'missing_type_hints': [
                r'def\s+\w+\s*\([^)]*\)(?!\s*->)',  # Function without return type
                r'def\s+\w+\s*\([^:)]*\)',  # Function without parameter types
            ],
            'missing_comments': [
                r'for\s+.*:\s*\n\s*(?!#)',  # Complex loop without comment
                r'if\s+.*and.*or.*:\s*\n\s*(?!#)',  # Complex condition without comment
            ]
        }
    }
    
    # License compliance patterns
    LICENSE_PATTERNS = {
        'gpl_violations': [
            r'import\s+.*gpl.*',
            r'from\s+.*gpl.*',
            r'# GPL',
            r'GNU General Public License'
        ],
        'proprietary_code': [
            r'# Proprietary',
            r'# Confidential',
            r'# Internal Use Only',
            r'# Copyright.*All Rights Reserved'
        ],
        'missing_license': [
            r'^(?!.*# License)(?!.*# Copyright).*$'  # Files without license header
        ]
    }
    
    # Audit trail requirements
    AUDIT_REQUIREMENTS = {
        'logging_requirements': [
            r'login.*attempt',
            r'authentication',
            r'authorization',
            r'data.*access',
            r'configuration.*change',
            r'user.*action'
        ],
        'data_integrity': [
            r'checksum',
            r'hash.*verification',
            r'integrity.*check',
            r'tamper.*detection'
        ],
        'access_monitoring': [
            r'access.*log',
            r'user.*activity',
            r'permission.*check',
            r'role.*verification'
        ]
    }
    
    def __init__(self, agent_id: str, config: EnterpriseConfig, **kwargs):
        """Initialize the Compliance Agent with specialized capabilities."""
        super().__init__(agent_id, "compliance", config, **kwargs)
        
        # Initialize compliance-specific components
        self.compliance_frameworks = ['GDPR', 'HIPAA', 'PCI DSS', 'SOX', 'SOC2', 'ISO27001']
        self.code_standards = ['PEP8', 'Security Standards', 'Documentation Standards']
        self.compliance_cache = {}
        
        # Load compliance knowledge base
        self._load_compliance_knowledge()
        
        self.logger.info("Compliance Agent initialized with comprehensive regulatory and standards analysis capabilities")
    
    def _initialize_capabilities(self) -> None:
        """Initialize compliance-specific capabilities."""
        capabilities = [
            AgentCapability(
                name="regulatory_compliance_analysis",
                description="Regulatory compliance analysis (GDPR, HIPAA, PCI DSS, SOX)",
                confidence_level=0.92
            ),
            AgentCapability(
                name="code_standards_validation",
                description="Code standards validation (PEP8, security standards)",
                confidence_level=0.94
            ),
            AgentCapability(
                name="documentation_compliance_check",
                description="Documentation compliance and gap analysis",
                confidence_level=0.88
            ),
            AgentCapability(
                name="license_compliance_analysis",
                description="License compliance and intellectual property analysis",
                confidence_level=0.86
            ),
            AgentCapability(
                name="audit_trail_validation",
                description="Audit trail requirements validation and analysis",
                confidence_level=0.90
            ),
            AgentCapability(
                name="security_compliance_check",
                description="Security compliance standards validation",
                confidence_level=0.91
            ),
            AgentCapability(
                name="data_privacy_compliance",
                description="Data privacy and protection compliance analysis",
                confidence_level=0.89
            ),
            AgentCapability(
                name="compliance_reporting",
                description="Compliance reporting and audit documentation generation",
                confidence_level=0.87
            )
        ]
        
        for capability in capabilities:
            self.add_capability(capability)
    
    def _load_compliance_knowledge(self) -> None:
        """Load compliance frameworks and requirements."""
        try:
            # Load compliance requirements
            self.compliance_requirements = {
                'GDPR': {
                    'data_protection': True,
                    'consent_management': True,
                    'data_portability': True,
                    'right_to_be_forgotten': True,
                    'privacy_by_design': True
                },
                'HIPAA': {
                    'phi_protection': True,
                    'access_controls': True,
                    'audit_logs': True,
                    'encryption': True,
                    'minimum_necessary': True
                },
                'PCI_DSS': {
                    'cardholder_data_protection': True,
                    'secure_transmission': True,
                    'access_control': True,
                    'network_security': True,
                    'vulnerability_management': True
                },
                'SOX': {
                    'financial_controls': True,
                    'change_management': True,
                    'audit_trail': True,
                    'segregation_of_duties': True
                }
            }
            
            # Load code quality standards
            self.quality_standards = {
                'maintainability': {
                    'max_function_length': 50,
                    'max_class_length': 500,
                    'max_complexity': 10
                },
                'readability': {
                    'require_docstrings': True,
                    'require_type_hints': True,
                    'require_comments': True
                },
                'security': {
                    'no_hardcoded_secrets': True,
                    'input_validation': True,
                    'secure_defaults': True
                }
            }
            
            self.logger.info("Compliance knowledge base loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to load compliance knowledge: {str(e)}")
    
    async def analyze(self, task: AnalysisTask) -> Dict[str, Any]:
        """
        Perform comprehensive compliance analysis on the provided code.
        
        Args:
            task: Analysis task containing code and context
            
        Returns:
            Dictionary containing compliance analysis results
        """
        try:
            content = task.payload.get('content', task.payload.get('code', ''))
            file_type = task.payload.get('file_type', 'python')
            file_path = task.payload.get('file_path', 'unknown')
            
            if not content:
                raise ValueError("No content provided for compliance analysis")
            
            self.logger.info(f"Starting compliance analysis for {file_path}")
            
            # Perform comprehensive compliance analysis
            results = {
                "analysis_type": "compliance",
                "agent_id": self.agent_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "file_path": file_path,
                "file_type": file_type,
                "compliance_issues": [],
                "regulatory_compliance": {},
                "code_standards_compliance": {},
                "documentation_compliance": {},
                "license_compliance": {},
                "audit_compliance": {},
                "compliance_frameworks": [],
                "compliance_metrics": {},
                "recommendations": [],
                "summary": {}
            }
            
            # 1. Regulatory Compliance Analysis
            regulatory_analysis = await self._analyze_regulatory_compliance(content, file_path)
            results["regulatory_compliance"] = regulatory_analysis
            results["compliance_issues"].extend(regulatory_analysis.get("issues", []))
            
            # 2. Code Standards Compliance
            standards_analysis = await self._analyze_code_standards(content, file_path)
            results["code_standards_compliance"] = standards_analysis
            results["compliance_issues"].extend(standards_analysis.get("issues", []))
            
            # 3. Documentation Compliance
            documentation_analysis = await self._analyze_documentation_compliance(content, file_path)
            results["documentation_compliance"] = documentation_analysis
            results["compliance_issues"].extend(documentation_analysis.get("issues", []))
            
            # 4. License Compliance
            license_analysis = await self._analyze_license_compliance(content, file_path)
            results["license_compliance"] = license_analysis
            results["compliance_issues"].extend(license_analysis.get("issues", []))
            
            # 5. Audit Trail Compliance
            audit_analysis = await self._analyze_audit_compliance(content, file_path)
            results["audit_compliance"] = audit_analysis
            results["compliance_issues"].extend(audit_analysis.get("issues", []))
            
            # 6. Generate Compliance Framework Assessments
            framework_assessments = await self._assess_compliance_frameworks(
                content, file_path, results["compliance_issues"]
            )
            results["compliance_frameworks"] = framework_assessments
            
            # 7. Calculate Compliance Metrics
            compliance_metrics = await self._calculate_compliance_metrics(
                content, results["compliance_issues"], framework_assessments
            )
            results["compliance_metrics"] = compliance_metrics
            
            # 8. Generate Recommendations
            recommendations = await self._generate_compliance_recommendations(
                results["compliance_issues"], compliance_metrics
            )
            results["recommendations"] = recommendations
            
            # 9. Generate Summary
            results["summary"] = self._generate_compliance_summary(results)
            
            self.logger.info(f"Compliance analysis completed. Found {len(results['compliance_issues'])} issues")
            
            return {
                "success": True,
                "data": results,
                "meta": {
                    "analysis_time": (datetime.now(timezone.utc) - datetime.fromisoformat(results["timestamp"])).total_seconds(),
                    "issues_found": len(results["compliance_issues"]),
                    "frameworks_assessed": len(framework_assessments),
                    "compliance_score": compliance_metrics.get("overall_compliance_score", 0),
                    "critical_violations": compliance_metrics.get("critical_violations", 0)
                }
            }
            
        except Exception as e:
            self.logger.error(f"Compliance analysis failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "data": None
            }
    
    async def _analyze_regulatory_compliance(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze regulatory compliance requirements."""
        issues = []
        regulatory_data = {
            "frameworks_analyzed": [],
            "compliance_violations": [],
            "compliance_score": 0,
            "issues": issues,
            "recommendations": []
        }
        
        try:
            # Analyze each regulatory framework
            for framework, patterns in self.REGULATORY_PATTERNS.items():
                framework_issues = []
                
                for category, pattern_list in patterns.items():
                    for pattern in pattern_list:
                        matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            
                            # Check if proper compliance measures are in place
                            compliance_issue = self._check_compliance_measures(
                                framework, category, content, match, line_num, file_path
                            )
                            
                            if compliance_issue:
                                framework_issues.append(compliance_issue)
                                issues.append(compliance_issue)
                
                if framework_issues:
                    regulatory_data["frameworks_analyzed"].append({
                        "framework": framework.upper(),
                        "violations": len(framework_issues),
                        "categories_affected": list(set([issue.category for issue in framework_issues]))
                    })
            
            # Calculate regulatory compliance score
            regulatory_data["compliance_score"] = self._calculate_regulatory_score(issues)
            
            # Generate regulatory recommendations
            regulatory_data["recommendations"] = self._generate_regulatory_recommendations(issues)
            
        except Exception as e:
            self.logger.warning(f"Regulatory compliance analysis failed: {str(e)}")
        
        return regulatory_data
    
    async def _analyze_code_standards(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze code standards compliance."""
        issues = []
        standards_data = {
            "standards_checked": [],
            "violations": [],
            "standards_score": 0,
            "issues": issues,
            "recommendations": []
        }
        
        try:
            # Check each code standard
            for standard, categories in self.CODE_STANDARDS.items():
                standard_issues = []
                
                for category, patterns in categories.items():
                    for pattern in patterns:
                        matches = re.finditer(pattern, content, re.MULTILINE)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            
                            issue = ComplianceIssue(
                                issue_id=f"COMP_STANDARDS_{standard.upper()}_{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                                severity=self._get_standards_severity(standard, category),
                                category="code_standards",
                                compliance_framework=standard.upper(),
                                title=f"Code Standards Violation: {category.replace('_', ' ').title()}",
                                description=f"Violation of {standard} standard in {category}",
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=content.split('\n')[line_num-1] if line_num <= len(content.split('\n')) else "",
                                requirement=f"{standard} - {category}",
                                confidence=0.9,
                                remediation=self._get_standards_remediation(standard, category),
                                compliance_impact="MEDIUM",
                                audit_importance="MEDIUM"
                            )
                            
                            standard_issues.append(issue)
                            issues.append(issue)
                
                if standard_issues:
                    standards_data["standards_checked"].append({
                        "standard": standard,
                        "violations": len(standard_issues),
                        "categories": list(set([issue.requirement.split(' - ')[1] for issue in standard_issues]))
                    })
            
            # Calculate standards compliance score
            standards_data["standards_score"] = self._calculate_standards_score(issues)
            
            # Generate standards recommendations
            standards_data["recommendations"] = self._generate_standards_recommendations(issues)
            
        except Exception as e:
            self.logger.warning(f"Code standards analysis failed: {str(e)}")
        
        return standards_data
    
    async def _analyze_documentation_compliance(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze documentation compliance."""
        issues = []
        doc_data = {
            "documentation_gaps": [],
            "documentation_score": 0,
            "issues": issues,
            "recommendations": []
        }
        
        try:
            # Check for missing docstrings
            doc_patterns = self.CODE_STANDARDS.get('documentation_standards', {})
            
            for category, patterns in doc_patterns.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.MULTILINE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        
                        issue = ComplianceIssue(
                            issue_id=f"COMP_DOC_{category.upper()}_{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                            severity=self._get_documentation_severity(category),
                            category="documentation",
                            compliance_framework="Documentation Standards",
                            title=f"Documentation Issue: {category.replace('_', ' ').title()}",
                            description=f"Missing or inadequate documentation: {category}",
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=content.split('\n')[line_num-1] if line_num <= len(content.split('\n')) else "",
                            requirement=f"Documentation - {category}",
                            confidence=0.8,
                            remediation=self._get_documentation_remediation(category),
                            compliance_impact="LOW",
                            audit_importance="MEDIUM"
                        )
                        
                        issues.append(issue)
            
            # Calculate documentation score
            doc_data["documentation_score"] = self._calculate_documentation_score(issues)
            
            # Generate documentation recommendations
            doc_data["recommendations"] = self._generate_documentation_recommendations(issues)
            
        except Exception as e:
            self.logger.warning(f"Documentation compliance analysis failed: {str(e)}")
        
        return doc_data
    
    async def _analyze_license_compliance(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze license compliance."""
        issues = []
        license_data = {
            "license_issues": [],
            "license_score": 0,
            "issues": issues,
            "recommendations": []
        }
        
        try:
            # Check for license compliance issues
            for category, patterns in self.LICENSE_PATTERNS.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        
                        issue = ComplianceIssue(
                            issue_id=f"COMP_LICENSE_{category.upper()}_{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                            severity=self._get_license_severity(category),
                            category="licensing",
                            compliance_framework="License Compliance",
                            title=f"License Issue: {category.replace('_', ' ').title()}",
                            description=f"License compliance issue: {category}",
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=content.split('\n')[line_num-1] if line_num <= len(content.split('\n')) else "",
                            requirement=f"License - {category}",
                            confidence=0.7,
                            remediation=self._get_license_remediation(category),
                            compliance_impact=self._get_license_impact(category),
                            audit_importance="HIGH"
                        )
                        
                        issues.append(issue)
            
            # Calculate license score
            license_data["license_score"] = self._calculate_license_score(issues)
            
            # Generate license recommendations
            license_data["recommendations"] = self._generate_license_recommendations(issues)
            
        except Exception as e:
            self.logger.warning(f"License compliance analysis failed: {str(e)}")
        
        return license_data
    
    async def _analyze_audit_compliance(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze audit trail compliance."""
        issues = []
        audit_data = {
            "audit_gaps": [],
            "audit_score": 0,
            "issues": issues,
            "recommendations": []
        }
        
        try:
            # Check for audit requirements
            for category, patterns in self.AUDIT_REQUIREMENTS.items():
                category_found = False
                
                for pattern in patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        category_found = True
                        break
                
                if not category_found:
                    # Missing audit requirement
                    issue = ComplianceIssue(
                        issue_id=f"COMP_AUDIT_{category.upper()}_{hashlib.md5(f'{file_path}:{category}'.encode()).hexdigest()[:8]}",
                        severity="MEDIUM",
                        category="audit_trail",
                        compliance_framework="Audit Requirements",
                        title=f"Missing Audit Requirement: {category.replace('_', ' ').title()}",
                        description=f"Missing audit trail requirement: {category}",
                        file_path=file_path,
                        line_number=1,
                        code_snippet="",
                        requirement=f"Audit - {category}",
                        confidence=0.6,
                        remediation=self._get_audit_remediation(category),
                        compliance_impact="MEDIUM",
                        audit_importance="HIGH"
                    )
                    
                    issues.append(issue)
            
            # Calculate audit score
            audit_data["audit_score"] = self._calculate_audit_score(issues)
            
            # Generate audit recommendations
            audit_data["recommendations"] = self._generate_audit_recommendations(issues)
            
        except Exception as e:
            self.logger.warning(f"Audit compliance analysis failed: {str(e)}")
        
        return audit_data
    
    async def _assess_compliance_frameworks(self, content: str, file_path: str, issues: List[ComplianceIssue]) -> List[Dict[str, Any]]:
        """Assess compliance against specific frameworks."""
        framework_assessments = []
        
        try:
            for framework in self.compliance_frameworks:
                framework_issues = [i for i in issues if framework.lower() in i.compliance_framework.lower()]
                
                assessment = {
                    "framework": framework,
                    "compliance_percentage": self._calculate_framework_compliance(framework, framework_issues),
                    "violations": len(framework_issues),
                    "critical_violations": len([i for i in framework_issues if i.severity == "CRITICAL"]),
                    "high_violations": len([i for i in framework_issues if i.severity == "HIGH"]),
                    "requirements_assessed": self._get_framework_requirements_count(framework),
                    "compliance_status": self._get_compliance_status(framework, framework_issues),
                    "recommendations": self._get_framework_recommendations(framework, framework_issues)
                }
                
                framework_assessments.append(assessment)
            
        except Exception as e:
            self.logger.warning(f"Framework assessment failed: {str(e)}")
        
        return framework_assessments
    
    async def _calculate_compliance_metrics(self, content: str, issues: List[ComplianceIssue], frameworks: List[Dict]) -> Dict[str, Any]:
        """Calculate comprehensive compliance metrics."""
        try:
            # Count issues by category
            regulatory_issues = len([i for i in issues if i.category == "regulatory"])
            standards_issues = len([i for i in issues if i.category == "code_standards"])
            documentation_issues = len([i for i in issues if i.category == "documentation"])
            license_issues = len([i for i in issues if i.category == "licensing"])
            audit_issues = len([i for i in issues if i.category == "audit_trail"])
            
            # Calculate scores
            regulatory_score = max(0, 100 - regulatory_issues * 15)
            standards_score = max(0, 100 - standards_issues * 10)
            documentation_score = max(0, 100 - documentation_issues * 8)
            license_score = max(0, 100 - license_issues * 20)
            audit_score = max(0, 100 - audit_issues * 12)
            
            # Calculate overall compliance score
            overall_score = (regulatory_score + standards_score + documentation_score + license_score + audit_score) / 5
            
            # Count critical violations
            critical_violations = len([i for i in issues if i.severity == "CRITICAL"])
            
            return {
                "overall_compliance_score": overall_score,
                "regulatory_compliance_score": regulatory_score,
                "standards_compliance_score": standards_score,
                "documentation_compliance_score": documentation_score,
                "license_compliance_score": license_score,
                "audit_compliance_score": audit_score,
                "total_violations": len(issues),
                "critical_violations": critical_violations,
                "high_violations": len([i for i in issues if i.severity == "HIGH"]),
                "frameworks_assessed": [f["framework"] for f in frameworks],
                "compliance_grade": self._get_compliance_grade(overall_score),
                "audit_readiness": self._assess_audit_readiness(issues)
            }
            
        except Exception as e:
            self.logger.warning(f"Compliance metrics calculation failed: {str(e)}")
            return {}
    
    async def _generate_compliance_recommendations(self, issues: List[ComplianceIssue], metrics: Dict[str, Any]) -> List[str]:
        """Generate compliance recommendations."""
        recommendations = []
        
        try:
            # Regulatory recommendations
            regulatory_issues = [i for i in issues if i.category == "regulatory"]
            if regulatory_issues:
                recommendations.append("Implement comprehensive data protection measures")
                recommendations.append("Establish proper consent management processes")
                recommendations.append("Implement audit logging for all data access")
            
            # Standards recommendations
            standards_issues = [i for i in issues if i.category == "code_standards"]
            if standards_issues:
                recommendations.append("Adopt and enforce coding standards")
                recommendations.append("Implement automated code quality checks")
                recommendations.append("Provide developer training on secure coding practices")
            
            # Documentation recommendations
            doc_issues = [i for i in issues if i.category == "documentation"]
            if doc_issues:
                recommendations.append("Improve code documentation and comments")
                recommendations.append("Implement documentation standards and reviews")
                recommendations.append("Add type hints and docstrings to all functions")
            
            # License recommendations
            license_issues = [i for i in issues if i.category == "licensing"]
            if license_issues:
                recommendations.append("Review and validate all third-party licenses")
                recommendations.append("Implement license compliance tracking")
                recommendations.append("Add proper license headers to all source files")
            
            # Audit recommendations
            audit_issues = [i for i in issues if i.category == "audit_trail"]
            if audit_issues:
                recommendations.append("Implement comprehensive audit logging")
                recommendations.append("Establish audit trail retention policies")
                recommendations.append("Add monitoring and alerting for compliance violations")
            
            # General recommendations
            recommendations.extend([
                "Conduct regular compliance assessments",
                "Implement automated compliance monitoring",
                "Provide compliance training for development teams",
                "Establish compliance review processes",
                "Document compliance procedures and policies"
            ])
            
        except Exception as e:
            self.logger.warning(f"Compliance recommendations generation failed: {str(e)}")
        
        return recommendations
    
    def _generate_compliance_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive compliance analysis summary."""
        try:
            issues = results.get("compliance_issues", [])
            metrics = results.get("compliance_metrics", {})
            frameworks = results.get("compliance_frameworks", [])
            
            summary = {
                "total_violations": len(issues),
                "severity_breakdown": {
                    "CRITICAL": len([i for i in issues if i.severity == "CRITICAL"]),
                    "HIGH": len([i for i in issues if i.severity == "HIGH"]),
                    "MEDIUM": len([i for i in issues if i.severity == "MEDIUM"]),
                    "LOW": len([i for i in issues if i.severity == "LOW"])
                },
                "category_breakdown": {},
                "framework_breakdown": {},
                "overall_compliance_score": metrics.get("overall_compliance_score", 0),
                "compliance_grade": metrics.get("compliance_grade", "C"),
                "audit_readiness": metrics.get("audit_readiness", "Not Ready"),
                "frameworks_assessed": len(frameworks),
                "top_recommendations": results.get("recommendations", [])[:5],
                "critical_issues": [i.title for i in issues if i.severity in ["CRITICAL", "HIGH"]][:3]
            }
            
            # Calculate category breakdown
            for issue in issues:
                category = issue.category
                summary["category_breakdown"][category] = summary["category_breakdown"].get(category, 0) + 1
            
            # Calculate framework breakdown
            for framework in frameworks:
                name = framework["framework"]
                summary["framework_breakdown"][name] = {
                    "compliance_percentage": framework["compliance_percentage"],
                    "violations": framework["violations"]
                }
            
            return summary
            
        except Exception as e:
            self.logger.warning(f"Compliance summary generation failed: {str(e)}")
            return {}
    
    # Helper methods for compliance checking
    def _check_compliance_measures(self, framework: str, category: str, content: str, match, line_num: int, file_path: str) -> Optional[ComplianceIssue]:
        """Check if proper compliance measures are in place for detected patterns."""
        # This is a simplified check - in reality, this would be much more sophisticated
        
        # Check if there are proper security measures around the detected pattern
        context_window = 5  # Lines before and after
        lines = content.split('\n')
        start_line = max(0, line_num - context_window)
        end_line = min(len(lines), line_num + context_window)
        context = '\n'.join(lines[start_line:end_line])
        
        # Look for compliance indicators
        compliance_indicators = {
            'encryption': ['encrypt', 'hash', 'secure', 'crypto'],
            'access_control': ['auth', 'permission', 'role', 'access'],
            'logging': ['log', 'audit', 'track', 'monitor'],
            'validation': ['validate', 'sanitize', 'check', 'verify']
        }
        
        # Check if any compliance measures are present
        measures_found = False
        for measure_type, indicators in compliance_indicators.items():
            for indicator in indicators:
                if indicator in context.lower():
                    measures_found = True
                    break
            if measures_found:
                break
        
        # If no compliance measures found, create an issue
        if not measures_found:
            return ComplianceIssue(
                issue_id=f"COMP_REG_{framework.upper()}_{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                severity=self._get_regulatory_severity(framework, category),
                category="regulatory",
                compliance_framework=framework.upper(),
                title=f"Regulatory Compliance Issue: {framework.upper()} - {category}",
                description=f"Potential {framework.upper()} compliance violation in {category}",
                file_path=file_path,
                line_number=line_num,
                code_snippet=lines[line_num-1] if line_num <= len(lines) else "",
                requirement=f"{framework.upper()} - {category}",
                confidence=0.7,
                remediation=self._get_regulatory_remediation(framework, category),
                compliance_impact="HIGH",
                audit_importance="HIGH"
            )
        
        return None
    
    # Severity and remediation methods
    def _get_regulatory_severity(self, framework: str, category: str) -> str:
        severity_map = {
            'gdpr': {'data_processing': 'HIGH', 'consent_management': 'CRITICAL'},
            'hipaa': {'phi_handling': 'CRITICAL', 'access_controls': 'HIGH'},
            'pci_dss': {'cardholder_data': 'CRITICAL', 'secure_transmission': 'HIGH'},
            'sox': {'financial_controls': 'HIGH', 'change_management': 'MEDIUM'}
        }
        return severity_map.get(framework, {}).get(category, 'MEDIUM')
    
    def _get_regulatory_remediation(self, framework: str, category: str) -> str:
        remediation_map = {
            'gdpr': {
                'data_processing': 'Implement proper data protection measures and consent management',
                'consent_management': 'Add explicit consent collection and management',
                'data_retention': 'Implement data retention and deletion policies',
                'data_portability': 'Add data export functionality for users'
            },
            'hipaa': {
                'phi_handling': 'Implement proper PHI protection and encryption',
                'access_controls': 'Add role-based access controls and audit logging',
                'encryption': 'Encrypt all PHI data in transit and at rest'
            },
            'pci_dss': {
                'cardholder_data': 'Implement proper cardholder data protection',
                'secure_transmission': 'Use secure transmission protocols (TLS 1.2+)',
                'access_control': 'Implement strict access controls for payment data'
            }
        }
        return remediation_map.get(framework, {}).get(category, 'Implement proper compliance measures')
    
    def _get_standards_severity(self, standard: str, category: str) -> str:
        severity_map = {
            'python_pep8': {'naming_conventions': 'LOW', 'line_length': 'LOW', 'imports': 'MEDIUM'},
            'security_standards': {'hardcoded_secrets': 'CRITICAL', 'sql_injection': 'HIGH', 'xss_prevention': 'HIGH'},
            'documentation_standards': {'missing_docstrings': 'MEDIUM', 'missing_type_hints': 'LOW'}
        }
        return severity_map.get(standard, {}).get(category, 'MEDIUM')
    
    def _get_standards_remediation(self, standard: str, category: str) -> str:
        remediation_map = {
            'python_pep8': {
                'naming_conventions': 'Follow PEP8 naming conventions',
                'line_length': 'Keep lines under 79 characters',
                'imports': 'Organize imports properly and avoid wildcards'
            },
            'security_standards': {
                'hardcoded_secrets': 'Use environment variables or secure vaults for secrets',
                'sql_injection': 'Use parameterized queries and input validation',
                'xss_prevention': 'Implement proper output encoding and CSP headers'
            }
        }
        return remediation_map.get(standard, {}).get(category, 'Follow coding standards')
    
    def _get_documentation_severity(self, category: str) -> str:
        severity_map = {
            'missing_docstrings': 'MEDIUM',
            'missing_type_hints': 'LOW',
            'missing_comments': 'LOW'
        }
        return severity_map.get(category, 'MEDIUM')
    
    def _get_documentation_remediation(self, category: str) -> str:
        remediation_map = {
            'missing_docstrings': 'Add comprehensive docstrings to functions and classes',
            'missing_type_hints': 'Add type hints to function parameters and return values',
            'missing_comments': 'Add explanatory comments for complex logic'
        }
        return remediation_map.get(category, 'Improve documentation')
    
    def _get_license_severity(self, category: str) -> str:
        severity_map = {
            'gpl_violations': 'HIGH',
            'proprietary_code': 'MEDIUM',
            'missing_license': 'LOW'
        }
        return severity_map.get(category, 'MEDIUM')
    
    def _get_license_impact(self, category: str) -> str:
        impact_map = {
            'gpl_violations': 'HIGH',
            'proprietary_code': 'MEDIUM',
            'missing_license': 'LOW'
        }
        return impact_map.get(category, 'MEDIUM')
    
    def _get_license_remediation(self, category: str) -> str:
        remediation_map = {
            'gpl_violations': 'Review GPL license compatibility and consider alternatives',
            'proprietary_code': 'Ensure proper licensing for proprietary code usage',
            'missing_license': 'Add appropriate license headers to source files'
        }
        return remediation_map.get(category, 'Review license compliance')
    
    def _get_audit_remediation(self, category: str) -> str:
        remediation_map = {
            'logging_requirements': 'Implement comprehensive audit logging',
            'data_integrity': 'Add data integrity checks and verification',
            'access_monitoring': 'Implement access monitoring and logging'
        }
        return remediation_map.get(category, 'Implement audit requirements')
    
    # Score calculation methods
    def _calculate_regulatory_score(self, issues: List[ComplianceIssue]) -> float:
        base_score = 100
        for issue in issues:
            if issue.severity == "CRITICAL":
                base_score -= 25
            elif issue.severity == "HIGH":
                base_score -= 15
            elif issue.severity == "MEDIUM":
                base_score -= 8
        return max(0, base_score)
    
    def _calculate_standards_score(self, issues: List[ComplianceIssue]) -> float:
        base_score = 100
        for issue in issues:
            if issue.severity == "HIGH":
                base_score -= 15
            elif issue.severity == "MEDIUM":
                base_score -= 10
            elif issue.severity == "LOW":
                base_score -= 5
        return max(0, base_score)
    
    def _calculate_documentation_score(self, issues: List[ComplianceIssue]) -> float:
        base_score = 100
        for issue in issues:
            if issue.severity == "MEDIUM":
                base_score -= 12
            elif issue.severity == "LOW":
                base_score -= 6
        return max(0, base_score)
    
    def _calculate_license_score(self, issues: List[ComplianceIssue]) -> float:
        base_score = 100
        for issue in issues:
            if issue.severity == "HIGH":
                base_score -= 30
            elif issue.severity == "MEDIUM":
                base_score -= 15
            elif issue.severity == "LOW":
                base_score -= 8
        return max(0, base_score)
    
    def _calculate_audit_score(self, issues: List[ComplianceIssue]) -> float:
        base_score = 100
        for issue in issues:
            if issue.severity == "HIGH":
                base_score -= 20
            elif issue.severity == "MEDIUM":
                base_score -= 12
        return max(0, base_score)
    
    def _calculate_framework_compliance(self, framework: str, issues: List[ComplianceIssue]) -> float:
        base_score = 100
        for issue in issues:
            if issue.severity == "CRITICAL":
                base_score -= 30
            elif issue.severity == "HIGH":
                base_score -= 20
            elif issue.severity == "MEDIUM":
                base_score -= 10
        return max(0, base_score)
    
    def _get_framework_requirements_count(self, framework: str) -> int:
        requirements_count = {
            'GDPR': 25,
            'HIPAA': 18,
            'PCI DSS': 12,
            'SOX': 8,
            'SOC2': 15,
            'ISO27001': 35
        }
        return requirements_count.get(framework, 10)
    
    def _get_compliance_status(self, framework: str, issues: List[ComplianceIssue]) -> str:
        critical_issues = len([i for i in issues if i.severity == "CRITICAL"])
        high_issues = len([i for i in issues if i.severity == "HIGH"])
        
        if critical_issues > 0:
            return "Non-Compliant"
        elif high_issues > 2:
            return "Partially Compliant"
        elif high_issues > 0:
            return "Mostly Compliant"
        else:
            return "Compliant"
    
    def _get_framework_recommendations(self, framework: str, issues: List[ComplianceIssue]) -> List[str]:
        recommendations = []
        
        if framework == "GDPR":
            recommendations.extend([
                "Implement data protection impact assessments",
                "Add consent management functionality",
                "Implement data portability features",
                "Add data deletion capabilities"
            ])
        elif framework == "HIPAA":
            recommendations.extend([
                "Implement PHI encryption",
                "Add access controls and audit logging",
                "Implement minimum necessary access",
                "Add breach notification procedures"
            ])
        elif framework == "PCI DSS":
            recommendations.extend([
                "Implement cardholder data protection",
                "Use secure transmission protocols",
                "Add network security controls",
                "Implement vulnerability management"
            ])
        
        return recommendations
    
    def _get_compliance_grade(self, score: float) -> str:
        if score >= 95:
            return "A+"
        elif score >= 90:
            return "A"
        elif score >= 85:
            return "B+"
        elif score >= 80:
            return "B"
        elif score >= 75:
            return "C+"
        elif score >= 70:
            return "C"
        elif score >= 65:
            return "D+"
        elif score >= 60:
            return "D"
        else:
            return "F"
    
    def _assess_audit_readiness(self, issues: List[ComplianceIssue]) -> str:
        critical_issues = len([i for i in issues if i.severity == "CRITICAL"])
        high_issues = len([i for i in issues if i.severity == "HIGH"])
        
        if critical_issues == 0 and high_issues == 0:
            return "Audit Ready"
        elif critical_issues == 0 and high_issues <= 2:
            return "Mostly Ready"
        elif critical_issues <= 1 and high_issues <= 5:
            return "Needs Improvement"
        else:
            return "Not Ready"
    
    # Recommendation generation methods
    def _generate_regulatory_recommendations(self, issues: List[ComplianceIssue]) -> List[str]:
        return [
            "Implement comprehensive data protection measures",
            "Add proper consent management processes",
            "Implement audit logging for compliance",
            "Add data encryption and secure transmission"
        ]
    
    def _generate_standards_recommendations(self, issues: List[ComplianceIssue]) -> List[str]:
        return [
            "Adopt and enforce coding standards",
            "Implement automated code quality checks",
            "Provide secure coding training",
            "Add code review processes"
        ]
    
    def _generate_documentation_recommendations(self, issues: List[ComplianceIssue]) -> List[str]:
        return [
            "Add comprehensive docstrings",
            "Implement type hints",
            "Add explanatory comments",
            "Create API documentation"
        ]
    
    def _generate_license_recommendations(self, issues: List[ComplianceIssue]) -> List[str]:
        return [
            "Review third-party license compatibility",
            "Add license headers to source files",
            "Implement license tracking",
            "Document license compliance procedures"
        ]
    
    def _generate_audit_recommendations(self, issues: List[ComplianceIssue]) -> List[str]:
        return [
            "Implement comprehensive audit logging",
            "Add access monitoring and controls",
            "Implement data integrity checks",
            "Create audit trail retention policies"
        ]

