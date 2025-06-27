"""
CodeGuardian AI - DevOps Agent
Enterprise-grade DevOps analysis agent specializing in CI/CD pipeline optimization,
infrastructure as code review, container security, and deployment best practices.

This agent implements advanced DevOps analysis capabilities including:
- CI/CD pipeline analysis and optimization
- Infrastructure as Code (IaC) security and best practices
- Container and Docker security analysis
- Deployment strategy assessment
- Monitoring and observability recommendations
- Cloud architecture review
"""

import re
import yaml
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
class DevOpsIssue:
    """Represents a DevOps issue found in configuration or code."""
    issue_id: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str  # e.g., "cicd", "security", "performance", "reliability"
    title: str
    description: str
    file_path: str
    line_number: int
    code_snippet: str
    impact: str  # SECURITY, PERFORMANCE, RELIABILITY, MAINTAINABILITY
    confidence: float = 0.0
    remediation: Optional[str] = None
    automation_potential: str = "NONE"  # HIGH, MEDIUM, LOW, NONE
    compliance_impact: List[str] = None
    
    def __post_init__(self):
        if self.compliance_impact is None:
            self.compliance_impact = []


@dataclass
class InfrastructureMetrics:
    """Infrastructure and deployment metrics."""
    deployment_frequency: str
    lead_time_for_changes: str
    mean_time_to_recovery: str
    change_failure_rate: float
    availability_percentage: float
    scalability_score: float
    security_score: float
    cost_optimization_score: float


@dataclass
class CICDPipeline:
    """Represents a CI/CD pipeline configuration."""
    pipeline_name: str
    pipeline_type: str  # GITHUB_ACTIONS, JENKINS, GITLAB_CI, AZURE_DEVOPS
    stages: List[str]
    security_checks: List[str]
    quality_gates: List[str]
    deployment_strategy: str
    automation_level: float
    security_score: float
    efficiency_score: float
    reliability_score: float


class DevOpsAgent(BaseAgent):
    """
    Specialized agent for comprehensive DevOps analysis and optimization.
    
    This agent provides enterprise-grade DevOps analysis capabilities including
    CI/CD optimization, infrastructure security, container analysis, and
    deployment best practices validation.
    """
    
    # CI/CD Security patterns
    CICD_SECURITY_PATTERNS = {
        'hardcoded_secrets': [
            r'password\s*[:=]\s*["\'][^"\']{8,}["\']',
            r'api_key\s*[:=]\s*["\'][^"\']{16,}["\']',
            r'secret\s*[:=]\s*["\'][^"\']{16,}["\']',
            r'token\s*[:=]\s*["\'][^"\']{20,}["\']',
            r'AWS_SECRET_ACCESS_KEY\s*[:=]\s*["\'][^"\']{20,}["\']'
        ],
        'insecure_protocols': [
            r'http://(?!localhost|127\.0\.0\.1)',
            r'ftp://',
            r'telnet://',
            r'--insecure',
            r'verify\s*[:=]\s*false'
        ],
        'privilege_escalation': [
            r'sudo\s+(?!-u)',
            r'--privileged',
            r'securityContext:\s*\n\s*privileged:\s*true',
            r'runAsRoot:\s*true'
        ],
        'missing_security_scans': [
            r'docker\s+build.*(?!--security-opt)',
            r'npm\s+install.*(?!--audit)',
            r'pip\s+install.*(?!--trusted-host)'
        ]
    }
    
    # Docker security best practices
    DOCKER_SECURITY_PATTERNS = {
        'root_user': [
            r'USER\s+root',
            r'USER\s+0',
            r'(?<!USER\s)RUN\s+(?!.*--user)'
        ],
        'latest_tags': [
            r'FROM\s+[^:\s]+(?::latest)?$',
            r'image:\s*[^:\s]+(?::latest)?$'
        ],
        'secrets_in_dockerfile': [
            r'ENV\s+.*(?:PASSWORD|SECRET|KEY|TOKEN)\s*=',
            r'ARG\s+.*(?:PASSWORD|SECRET|KEY|TOKEN)',
            r'COPY\s+.*\.(?:key|pem|p12|pfx)'
        ],
        'unnecessary_packages': [
            r'apt-get\s+install.*(?:curl|wget|ssh|telnet)',
            r'yum\s+install.*(?:curl|wget|ssh|telnet)',
            r'apk\s+add.*(?:curl|wget|ssh|telnet)'
        ]
    }
    
    # Infrastructure as Code patterns
    IAC_PATTERNS = {
        'terraform': {
            'security_groups_open': [
                r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]',
                r'from_port\s*=\s*0.*to_port\s*=\s*65535'
            ],
            'unencrypted_storage': [
                r'encrypted\s*=\s*false',
                r'(?<!server_side_)encryption\s*=\s*""'
            ],
            'missing_versioning': [
                r'versioning\s*\{\s*enabled\s*=\s*false'
            ]
        },
        'kubernetes': {
            'privileged_containers': [
                r'privileged:\s*true',
                r'allowPrivilegeEscalation:\s*true'
            ],
            'no_resource_limits': [
                r'containers:\s*\n(?:(?!\s*resources:).)*$'
            ],
            'default_namespace': [
                r'namespace:\s*default',
                r'(?<!namespace:\s)apiVersion:'
            ]
        }
    }
    
    # Monitoring and observability patterns
    OBSERVABILITY_PATTERNS = {
        'missing_logging': [
            r'(?<!log\.|logger\.|logging\.)',
            r'print\s*\(',
            r'console\.log\s*\('
        ],
        'missing_metrics': [
            r'(?<!metrics\.|prometheus\.)',
            r'(?<!counter\.|gauge\.|histogram\.)'
        ],
        'missing_health_checks': [
            r'(?<!health|readiness|liveness)',
            r'(?<!/health|/ready|/alive)'
        ]
    }
    
    def __init__(self, agent_id: str, config: EnterpriseConfig, **kwargs):
        """Initialize the DevOps Agent with specialized capabilities."""
        super().__init__(agent_id, "devops", config, **kwargs)
        
        # Initialize DevOps-specific components
        self.pipeline_templates = {}
        self.infrastructure_patterns = {}
        self.security_benchmarks = {}
        
        # Load DevOps knowledge base
        self._load_devops_knowledge()
        
        self.logger.info("DevOps Agent initialized with advanced CI/CD and infrastructure analysis capabilities")
    
    def _initialize_capabilities(self) -> None:
        """Initialize DevOps-specific capabilities."""
        capabilities = [
            AgentCapability(
                name="cicd_pipeline_analysis",
                description="CI/CD pipeline security and optimization analysis",
                confidence_level=0.93
            ),
            AgentCapability(
                name="infrastructure_as_code_review",
                description="Infrastructure as Code security and best practices review",
                confidence_level=0.91
            ),
            AgentCapability(
                name="container_security_analysis",
                description="Docker and container security analysis",
                confidence_level=0.89
            ),
            AgentCapability(
                name="deployment_strategy_assessment",
                description="Deployment strategy and reliability assessment",
                confidence_level=0.87
            ),
            AgentCapability(
                name="cloud_architecture_review",
                description="Cloud architecture security and optimization review",
                confidence_level=0.85
            ),
            AgentCapability(
                name="monitoring_observability_analysis",
                description="Monitoring and observability implementation analysis",
                confidence_level=0.88
            ),
            AgentCapability(
                name="automation_optimization",
                description="DevOps automation and workflow optimization",
                confidence_level=0.90
            ),
            AgentCapability(
                name="compliance_validation",
                description="DevOps compliance and governance validation",
                confidence_level=0.86
            )
        ]
        
        for capability in capabilities:
            self.add_capability(capability)
    
    def _load_devops_knowledge(self) -> None:
        """Load DevOps patterns and best practices knowledge base."""
        try:
            # Load CI/CD pipeline templates
            self.pipeline_templates = {
                'security_pipeline': {
                    'stages': ['build', 'security_scan', 'test', 'deploy'],
                    'required_checks': ['sast', 'dast', 'dependency_scan', 'container_scan'],
                    'quality_gates': ['coverage_threshold', 'security_threshold', 'performance_threshold']
                },
                'production_pipeline': {
                    'stages': ['build', 'test', 'security', 'staging', 'production'],
                    'required_checks': ['unit_tests', 'integration_tests', 'security_tests', 'performance_tests'],
                    'deployment_strategies': ['blue_green', 'canary', 'rolling']
                }
            }
            
            # Load security benchmarks
            self.security_benchmarks = {
                'cis_docker': {
                    'user_namespaces': True,
                    'readonly_root_filesystem': True,
                    'no_privileged_containers': True,
                    'resource_limits': True
                },
                'cis_kubernetes': {
                    'rbac_enabled': True,
                    'network_policies': True,
                    'pod_security_policies': True,
                    'secrets_encryption': True
                }
            }
            
            self.logger.info("DevOps knowledge base loaded successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to load DevOps knowledge: {str(e)}")
    
    async def analyze(self, task: AnalysisTask) -> Dict[str, Any]:
        """
        Perform comprehensive DevOps analysis on the provided configuration or code.
        
        Args:
            task: Analysis task containing configuration/code and context
            
        Returns:
            Dictionary containing DevOps analysis results
        """
        try:
            content = task.payload.get('content', task.payload.get('code', ''))
            file_type = task.payload.get('file_type', 'unknown')
            file_path = task.payload.get('file_path', 'unknown')
            
            if not content:
                raise ValueError("No content provided for DevOps analysis")
            
            self.logger.info(f"Starting DevOps analysis for {file_path}")
            
            # Perform comprehensive DevOps analysis
            results = {
                "analysis_type": "devops",
                "agent_id": self.agent_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "file_path": file_path,
                "file_type": file_type,
                "devops_issues": [],
                "pipeline_analysis": {},
                "infrastructure_analysis": {},
                "container_analysis": {},
                "security_analysis": {},
                "observability_analysis": {},
                "automation_recommendations": [],
                "compliance_status": {},
                "summary": {}
            }
            
            # Determine analysis type based on file type/content
            analysis_type = self._determine_analysis_type(content, file_type, file_path)
            
            # 1. CI/CD Pipeline Analysis
            if analysis_type in ['cicd', 'yaml', 'yml']:
                pipeline_analysis = await self._analyze_cicd_pipeline(content, file_path)
                results["pipeline_analysis"] = pipeline_analysis
                results["devops_issues"].extend(pipeline_analysis.get("issues", []))
            
            # 2. Infrastructure as Code Analysis
            if analysis_type in ['terraform', 'iac', 'tf']:
                iac_analysis = await self._analyze_infrastructure_as_code(content, file_path)
                results["infrastructure_analysis"] = iac_analysis
                results["devops_issues"].extend(iac_analysis.get("issues", []))
            
            # 3. Container/Docker Analysis
            if analysis_type in ['dockerfile', 'docker', 'container']:
                container_analysis = await self._analyze_container_configuration(content, file_path)
                results["container_analysis"] = container_analysis
                results["devops_issues"].extend(container_analysis.get("issues", []))
            
            # 4. Kubernetes Analysis
            if analysis_type in ['kubernetes', 'k8s', 'yaml', 'yml']:
                k8s_analysis = await self._analyze_kubernetes_configuration(content, file_path)
                results["infrastructure_analysis"].update(k8s_analysis)
                results["devops_issues"].extend(k8s_analysis.get("issues", []))
            
            # 5. Security Analysis
            security_analysis = await self._analyze_devops_security(content, file_path, analysis_type)
            results["security_analysis"] = security_analysis
            results["devops_issues"].extend(security_analysis.get("issues", []))
            
            # 6. Observability Analysis
            observability_analysis = await self._analyze_observability(content, file_path)
            results["observability_analysis"] = observability_analysis
            results["devops_issues"].extend(observability_analysis.get("issues", []))
            
            # 7. Generate automation recommendations
            automation_recs = await self._generate_automation_recommendations(results["devops_issues"], analysis_type)
            results["automation_recommendations"] = automation_recs
            
            # 8. Compliance validation
            compliance_status = await self._validate_devops_compliance(results["devops_issues"], analysis_type)
            results["compliance_status"] = compliance_status
            
            # 9. Generate comprehensive summary
            results["summary"] = self._generate_devops_summary(results)
            
            self.logger.info(f"DevOps analysis completed. Found {len(results['devops_issues'])} issues")
            
            return {
                "success": True,
                "data": results,
                "meta": {
                    "analysis_time": (datetime.now(timezone.utc) - datetime.fromisoformat(results["timestamp"])).total_seconds(),
                    "issues_found": len(results["devops_issues"]),
                    "analysis_type": analysis_type,
                    "security_score": security_analysis.get("security_score", 0),
                    "automation_potential": len([r for r in automation_recs if r.get("priority") == "HIGH"])
                }
            }
            
        except Exception as e:
            self.logger.error(f"DevOps analysis failed: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "data": None
            }
    
    def _determine_analysis_type(self, content: str, file_type: str, file_path: str) -> str:
        """Determine the type of DevOps analysis needed."""
        file_path_lower = file_path.lower()
        
        # Check file extensions and names
        if file_path_lower.endswith('.tf') or 'terraform' in file_path_lower:
            return 'terraform'
        elif file_path_lower.endswith('dockerfile') or 'dockerfile' in file_path_lower:
            return 'dockerfile'
        elif any(name in file_path_lower for name in ['.github/workflows', 'jenkins', 'gitlab-ci', 'azure-pipelines']):
            return 'cicd'
        elif any(name in file_path_lower for name in ['deployment', 'service', 'configmap', 'secret']) and file_path_lower.endswith(('.yaml', '.yml')):
            return 'kubernetes'
        elif file_path_lower.endswith(('.yaml', '.yml')):
            return 'yaml'
        
        # Check content patterns
        if 'resource "aws_' in content or 'provider "aws"' in content:
            return 'terraform'
        elif 'FROM ' in content and ('RUN ' in content or 'COPY ' in content):
            return 'dockerfile'
        elif 'apiVersion:' in content and 'kind:' in content:
            return 'kubernetes'
        elif any(key in content for key in ['on:', 'jobs:', 'steps:', 'runs-on:']):
            return 'cicd'
        
        return 'general'
    
    async def _analyze_cicd_pipeline(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze CI/CD pipeline configuration."""
        issues = []
        pipeline_data = {
            "pipeline_type": "unknown",
            "stages": [],
            "security_checks": [],
            "quality_gates": [],
            "issues": issues,
            "recommendations": [],
            "security_score": 0,
            "efficiency_score": 0
        }
        
        try:
            # Detect pipeline type
            if '.github/workflows' in file_path:
                pipeline_data["pipeline_type"] = "github_actions"
            elif 'jenkins' in file_path.lower():
                pipeline_data["pipeline_type"] = "jenkins"
            elif 'gitlab' in file_path.lower():
                pipeline_data["pipeline_type"] = "gitlab_ci"
            elif 'azure' in file_path.lower():
                pipeline_data["pipeline_type"] = "azure_devops"
            
            # Parse YAML content
            try:
                if content.strip().startswith('{'):
                    config = json.loads(content)
                else:
                    config = yaml.safe_load(content)
            except:
                config = {}
            
            # Analyze security patterns
            for category, patterns in self.CICD_SECURITY_PATTERNS.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        
                        issue = DevOpsIssue(
                            issue_id=f"CICD_{category.upper()}_{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                            severity=self._get_cicd_issue_severity(category),
                            category="cicd_security",
                            title=f"CI/CD Security Issue: {category.replace('_', ' ').title()}",
                            description=f"Detected {category} in CI/CD pipeline",
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=content.split('\n')[line_num-1] if line_num <= len(content.split('\n')) else "",
                            impact="SECURITY",
                            confidence=0.8,
                            remediation=self._get_cicd_remediation(category),
                            automation_potential="HIGH"
                        )
                        issues.append(issue)
            
            # Check for missing security scans
            security_tools = ['bandit', 'safety', 'semgrep', 'snyk', 'trivy', 'clair']
            found_security_tools = [tool for tool in security_tools if tool in content.lower()]
            
            if not found_security_tools:
                issue = DevOpsIssue(
                    issue_id=f"CICD_MISSING_SECURITY_{hashlib.md5(file_path.encode()).hexdigest()[:8]}",
                    severity="HIGH",
                    category="missing_security_scan",
                    title="Missing Security Scanning",
                    description="CI/CD pipeline lacks security scanning tools",
                    file_path=file_path,
                    line_number=1,
                    code_snippet="# No security scanning detected",
                    impact="SECURITY",
                    confidence=0.9,
                    remediation="Add security scanning tools like Bandit, Safety, or Snyk",
                    automation_potential="HIGH"
                )
                issues.append(issue)
            
            # Calculate scores
            pipeline_data["security_score"] = self._calculate_pipeline_security_score(content, issues)
            pipeline_data["efficiency_score"] = self._calculate_pipeline_efficiency_score(content)
            
            # Generate recommendations
            pipeline_data["recommendations"] = self._generate_pipeline_recommendations(issues, config)
            
        except Exception as e:
            self.logger.warning(f"CI/CD pipeline analysis failed: {str(e)}")
        
        return pipeline_data
    
    async def _analyze_infrastructure_as_code(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze Infrastructure as Code configuration."""
        issues = []
        iac_data = {
            "iac_type": "terraform",
            "resources": [],
            "security_issues": [],
            "compliance_issues": [],
            "issues": issues,
            "recommendations": [],
            "security_score": 0
        }
        
        try:
            # Analyze Terraform patterns
            if 'terraform' in file_path.lower() or '.tf' in file_path:
                for category, patterns in self.IAC_PATTERNS['terraform'].items():
                    for pattern in patterns:
                        matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                        for match in matches:
                            line_num = content[:match.start()].count('\n') + 1
                            
                            issue = DevOpsIssue(
                                issue_id=f"IAC_TF_{category.upper()}_{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                                severity=self._get_iac_issue_severity(category),
                                category="iac_security",
                                title=f"Terraform Security Issue: {category.replace('_', ' ').title()}",
                                description=f"Detected {category} in Terraform configuration",
                                file_path=file_path,
                                line_number=line_num,
                                code_snippet=content.split('\n')[line_num-1] if line_num <= len(content.split('\n')) else "",
                                impact="SECURITY",
                                confidence=0.85,
                                remediation=self._get_iac_remediation(category),
                                automation_potential="MEDIUM"
                            )
                            issues.append(issue)
            
            # Extract resource information
            resource_matches = re.finditer(r'resource\s+"([^"]+)"\s+"([^"]+)"', content)
            for match in resource_matches:
                iac_data["resources"].append({
                    "type": match.group(1),
                    "name": match.group(2),
                    "line": content[:match.start()].count('\n') + 1
                })
            
            # Calculate security score
            iac_data["security_score"] = self._calculate_iac_security_score(content, issues)
            
            # Generate recommendations
            iac_data["recommendations"] = self._generate_iac_recommendations(issues)
            
        except Exception as e:
            self.logger.warning(f"Infrastructure as Code analysis failed: {str(e)}")
        
        return iac_data
    
    async def _analyze_container_configuration(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze Docker/container configuration."""
        issues = []
        container_data = {
            "container_type": "docker",
            "base_image": "",
            "security_issues": [],
            "optimization_issues": [],
            "issues": issues,
            "recommendations": [],
            "security_score": 0
        }
        
        try:
            # Extract base image
            base_image_match = re.search(r'FROM\s+([^\s]+)', content)
            if base_image_match:
                container_data["base_image"] = base_image_match.group(1)
            
            # Analyze Docker security patterns
            for category, patterns in self.DOCKER_SECURITY_PATTERNS.items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        
                        issue = DevOpsIssue(
                            issue_id=f"DOCKER_{category.upper()}_{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                            severity=self._get_docker_issue_severity(category),
                            category="container_security",
                            title=f"Docker Security Issue: {category.replace('_', ' ').title()}",
                            description=f"Detected {category} in Docker configuration",
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=content.split('\n')[line_num-1] if line_num <= len(content.split('\n')) else "",
                            impact="SECURITY",
                            confidence=0.9,
                            remediation=self._get_docker_remediation(category),
                            automation_potential="HIGH"
                        )
                        issues.append(issue)
            
            # Check for multi-stage builds
            if content.count('FROM ') == 1:
                issue = DevOpsIssue(
                    issue_id=f"DOCKER_SINGLE_STAGE_{hashlib.md5(file_path.encode()).hexdigest()[:8]}",
                    severity="MEDIUM",
                    category="optimization",
                    title="Single-stage Docker build",
                    description="Consider using multi-stage builds for smaller, more secure images",
                    file_path=file_path,
                    line_number=1,
                    code_snippet="FROM ...",
                    impact="PERFORMANCE",
                    confidence=0.6,
                    remediation="Implement multi-stage Docker builds",
                    automation_potential="MEDIUM"
                )
                issues.append(issue)
            
            # Calculate security score
            container_data["security_score"] = self._calculate_container_security_score(content, issues)
            
            # Generate recommendations
            container_data["recommendations"] = self._generate_container_recommendations(issues)
            
        except Exception as e:
            self.logger.warning(f"Container analysis failed: {str(e)}")
        
        return container_data
    
    async def _analyze_kubernetes_configuration(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze Kubernetes configuration."""
        issues = []
        k8s_data = {
            "resources": [],
            "security_issues": [],
            "issues": issues,
            "recommendations": [],
            "security_score": 0
        }
        
        try:
            # Parse YAML content
            try:
                configs = list(yaml.safe_load_all(content))
            except:
                configs = []
            
            # Analyze Kubernetes security patterns
            for category, patterns in self.IAC_PATTERNS['kubernetes'].items():
                for pattern in patterns:
                    matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                    for match in matches:
                        line_num = content[:match.start()].count('\n') + 1
                        
                        issue = DevOpsIssue(
                            issue_id=f"K8S_{category.upper()}_{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                            severity=self._get_k8s_issue_severity(category),
                            category="kubernetes_security",
                            title=f"Kubernetes Security Issue: {category.replace('_', ' ').title()}",
                            description=f"Detected {category} in Kubernetes configuration",
                            file_path=file_path,
                            line_number=line_num,
                            code_snippet=content.split('\n')[line_num-1] if line_num <= len(content.split('\n')) else "",
                            impact="SECURITY",
                            confidence=0.85,
                            remediation=self._get_k8s_remediation(category),
                            automation_potential="HIGH"
                        )
                        issues.append(issue)
            
            # Extract resource information
            for config in configs:
                if isinstance(config, dict) and 'kind' in config:
                    k8s_data["resources"].append({
                        "kind": config.get("kind"),
                        "name": config.get("metadata", {}).get("name", "unknown"),
                        "namespace": config.get("metadata", {}).get("namespace", "default")
                    })
            
            # Calculate security score
            k8s_data["security_score"] = self._calculate_k8s_security_score(content, issues)
            
            # Generate recommendations
            k8s_data["recommendations"] = self._generate_k8s_recommendations(issues)
            
        except Exception as e:
            self.logger.warning(f"Kubernetes analysis failed: {str(e)}")
        
        return k8s_data
    
    async def _analyze_devops_security(self, content: str, file_path: str, analysis_type: str) -> Dict[str, Any]:
        """Analyze DevOps security across all configuration types."""
        issues = []
        security_data = {
            "security_score": 0,
            "vulnerabilities": [],
            "compliance_issues": [],
            "issues": issues,
            "recommendations": []
        }
        
        try:
            # Check for hardcoded secrets across all file types
            secret_patterns = [
                r'password\s*[:=]\s*["\'][^"\']{8,}["\']',
                r'api_key\s*[:=]\s*["\'][^"\']{16,}["\']',
                r'secret\s*[:=]\s*["\'][^"\']{16,}["\']',
                r'token\s*[:=]\s*["\'][^"\']{20,}["\']',
                r'private_key\s*[:=]\s*["\'].*BEGIN.*PRIVATE.*KEY'
            ]
            
            for pattern in secret_patterns:
                matches = re.finditer(pattern, content, re.MULTILINE | re.IGNORECASE)
                for match in matches:
                    line_num = content[:match.start()].count('\n') + 1
                    
                    issue = DevOpsIssue(
                        issue_id=f"SEC_HARDCODED_{hashlib.md5(f'{file_path}:{line_num}'.encode()).hexdigest()[:8]}",
                        severity="CRITICAL",
                        category="hardcoded_secrets",
                        title="Hardcoded Secret Detected",
                        description="Hardcoded secrets found in configuration",
                        file_path=file_path,
                        line_number=line_num,
                        code_snippet=content.split('\n')[line_num-1] if line_num <= len(content.split('\n')) else "",
                        impact="SECURITY",
                        confidence=0.95,
                        remediation="Use environment variables or secret management systems",
                        automation_potential="HIGH",
                        compliance_impact=["SOC2", "PCI_DSS", "GDPR"]
                    )
                    issues.append(issue)
            
            # Calculate overall security score
            security_data["security_score"] = self._calculate_overall_security_score(issues)
            
            # Generate security recommendations
            security_data["recommendations"] = self._generate_security_recommendations(issues)
            
        except Exception as e:
            self.logger.warning(f"DevOps security analysis failed: {str(e)}")
        
        return security_data
    
    async def _analyze_observability(self, content: str, file_path: str) -> Dict[str, Any]:
        """Analyze observability and monitoring configuration."""
        issues = []
        observability_data = {
            "logging_score": 0,
            "monitoring_score": 0,
            "alerting_score": 0,
            "issues": issues,
            "recommendations": []
        }
        
        try:
            # Check for logging implementation
            logging_patterns = ['log', 'logger', 'logging', 'syslog', 'fluentd', 'logstash']
            has_logging = any(pattern in content.lower() for pattern in logging_patterns)
            
            if not has_logging:
                issue = DevOpsIssue(
                    issue_id=f"OBS_MISSING_LOGGING_{hashlib.md5(file_path.encode()).hexdigest()[:8]}",
                    severity="MEDIUM",
                    category="missing_observability",
                    title="Missing Logging Configuration",
                    description="No logging configuration detected",
                    file_path=file_path,
                    line_number=1,
                    code_snippet="# No logging detected",
                    impact="RELIABILITY",
                    confidence=0.7,
                    remediation="Implement structured logging with appropriate log levels",
                    automation_potential="HIGH"
                )
                issues.append(issue)
            
            # Check for monitoring implementation
            monitoring_patterns = ['prometheus', 'grafana', 'datadog', 'newrelic', 'metrics', 'monitoring']
            has_monitoring = any(pattern in content.lower() for pattern in monitoring_patterns)
            
            if not has_monitoring:
                issue = DevOpsIssue(
                    issue_id=f"OBS_MISSING_MONITORING_{hashlib.md5(file_path.encode()).hexdigest()[:8]}",
                    severity="MEDIUM",
                    category="missing_observability",
                    title="Missing Monitoring Configuration",
                    description="No monitoring configuration detected",
                    file_path=file_path,
                    line_number=1,
                    code_snippet="# No monitoring detected",
                    impact="RELIABILITY",
                    confidence=0.7,
                    remediation="Implement monitoring with Prometheus, Grafana, or similar tools",
                    automation_potential="HIGH"
                )
                issues.append(issue)
            
            # Calculate observability scores
            observability_data["logging_score"] = 80 if has_logging else 20
            observability_data["monitoring_score"] = 80 if has_monitoring else 20
            observability_data["alerting_score"] = 60  # Default score
            
            # Generate recommendations
            observability_data["recommendations"] = self._generate_observability_recommendations(issues)
            
        except Exception as e:
            self.logger.warning(f"Observability analysis failed: {str(e)}")
        
        return observability_data
    
    async def _generate_automation_recommendations(self, issues: List[DevOpsIssue], analysis_type: str) -> List[Dict[str, Any]]:
        """Generate automation recommendations based on found issues."""
        recommendations = []
        
        try:
            # Group issues by automation potential
            high_automation = [i for i in issues if i.automation_potential == "HIGH"]
            medium_automation = [i for i in issues if i.automation_potential == "MEDIUM"]
            
            if high_automation:
                recommendations.append({
                    "category": "high_automation_potential",
                    "priority": "HIGH",
                    "title": "High Automation Potential Issues",
                    "description": f"Found {len(high_automation)} issues that can be automated",
                    "automation_tools": self._suggest_automation_tools(high_automation),
                    "estimated_effort": "2-4 hours",
                    "impact": "Significant reduction in manual effort and human error"
                })
            
            if medium_automation:
                recommendations.append({
                    "category": "medium_automation_potential",
                    "priority": "MEDIUM",
                    "title": "Medium Automation Potential Issues",
                    "description": f"Found {len(medium_automation)} issues that can be partially automated",
                    "automation_tools": self._suggest_automation_tools(medium_automation),
                    "estimated_effort": "4-8 hours",
                    "impact": "Moderate reduction in manual effort"
                })
            
            # Add general automation recommendations
            if analysis_type == "cicd":
                recommendations.append({
                    "category": "cicd_automation",
                    "priority": "HIGH",
                    "title": "CI/CD Pipeline Automation",
                    "description": "Enhance CI/CD pipeline with automated security and quality checks",
                    "automation_tools": ["GitHub Actions", "Jenkins", "GitLab CI", "Azure DevOps"],
                    "estimated_effort": "8-16 hours",
                    "impact": "Automated security scanning and quality gates"
                })
            
        except Exception as e:
            self.logger.warning(f"Automation recommendations generation failed: {str(e)}")
        
        return recommendations
    
    async def _validate_devops_compliance(self, issues: List[DevOpsIssue], analysis_type: str) -> Dict[str, Any]:
        """Validate DevOps compliance with various standards."""
        compliance_status = {
            "overall_compliance_score": 0,
            "compliance_frameworks": {},
            "violations": [],
            "recommendations": []
        }
        
        try:
            # Check compliance violations
            compliance_violations = [i for i in issues if i.compliance_impact]
            
            # Analyze compliance by framework
            frameworks = ["SOC2", "PCI_DSS", "GDPR", "HIPAA", "ISO27001"]
            
            for framework in frameworks:
                framework_violations = [
                    i for i in compliance_violations 
                    if framework in i.compliance_impact
                ]
                
                compliance_status["compliance_frameworks"][framework] = {
                    "compliant": len(framework_violations) == 0,
                    "violations": len(framework_violations),
                    "risk_level": self._assess_compliance_risk(framework_violations)
                }
            
            # Calculate overall compliance score
            total_violations = len(compliance_violations)
            total_issues = len(issues)
            
            if total_issues > 0:
                compliance_status["overall_compliance_score"] = max(0, 100 - (total_violations / total_issues) * 100)
            else:
                compliance_status["overall_compliance_score"] = 100
            
            # Generate compliance recommendations
            compliance_status["recommendations"] = self._generate_compliance_recommendations(compliance_violations)
            
        except Exception as e:
            self.logger.warning(f"Compliance validation failed: {str(e)}")
        
        return compliance_status
    
    def _generate_devops_summary(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive DevOps analysis summary."""
        try:
            issues = results.get("devops_issues", [])
            
            summary = {
                "total_issues": len(issues),
                "severity_breakdown": {
                    "CRITICAL": len([i for i in issues if i.severity == "CRITICAL"]),
                    "HIGH": len([i for i in issues if i.severity == "HIGH"]),
                    "MEDIUM": len([i for i in issues if i.severity == "MEDIUM"]),
                    "LOW": len([i for i in issues if i.severity == "LOW"])
                },
                "category_breakdown": {},
                "security_score": results.get("security_analysis", {}).get("security_score", 0),
                "automation_potential": len([i for i in issues if i.automation_potential == "HIGH"]),
                "compliance_score": results.get("compliance_status", {}).get("overall_compliance_score", 0),
                "top_recommendations": [],
                "critical_issues": [i.title for i in issues if i.severity == "CRITICAL"][:5]
            }
            
            # Calculate category breakdown
            for issue in issues:
                category = issue.category
                summary["category_breakdown"][category] = summary["category_breakdown"].get(category, 0) + 1
            
            # Generate top recommendations
            summary["top_recommendations"] = [
                "Implement automated security scanning in CI/CD pipeline",
                "Remove hardcoded secrets and use secret management",
                "Add comprehensive monitoring and alerting",
                "Implement infrastructure as code best practices",
                "Enhance container security configurations"
            ]
            
            return summary
            
        except Exception as e:
            self.logger.warning(f"DevOps summary generation failed: {str(e)}")
            return {}
    
    # Helper methods for severity and remediation
    def _get_cicd_issue_severity(self, category: str) -> str:
        severity_map = {
            'hardcoded_secrets': 'CRITICAL',
            'insecure_protocols': 'HIGH',
            'privilege_escalation': 'HIGH',
            'missing_security_scans': 'HIGH'
        }
        return severity_map.get(category, 'MEDIUM')
    
    def _get_cicd_remediation(self, category: str) -> str:
        remediation_map = {
            'hardcoded_secrets': 'Use environment variables or secret management systems like HashiCorp Vault',
            'insecure_protocols': 'Use HTTPS/TLS for all communications',
            'privilege_escalation': 'Run containers with non-root users and minimal privileges',
            'missing_security_scans': 'Add security scanning tools like Bandit, Safety, or Snyk to pipeline'
        }
        return remediation_map.get(category, 'Review and fix the identified issue')
    
    def _get_iac_issue_severity(self, category: str) -> str:
        severity_map = {
            'security_groups_open': 'CRITICAL',
            'unencrypted_storage': 'HIGH',
            'missing_versioning': 'MEDIUM'
        }
        return severity_map.get(category, 'MEDIUM')
    
    def _get_iac_remediation(self, category: str) -> str:
        remediation_map = {
            'security_groups_open': 'Restrict security group rules to specific IP ranges',
            'unencrypted_storage': 'Enable encryption for all storage resources',
            'missing_versioning': 'Enable versioning for storage buckets'
        }
        return remediation_map.get(category, 'Review and fix the identified issue')
    
    def _get_docker_issue_severity(self, category: str) -> str:
        severity_map = {
            'root_user': 'HIGH',
            'latest_tags': 'MEDIUM',
            'secrets_in_dockerfile': 'CRITICAL',
            'unnecessary_packages': 'MEDIUM'
        }
        return severity_map.get(category, 'MEDIUM')
    
    def _get_docker_remediation(self, category: str) -> str:
        remediation_map = {
            'root_user': 'Create and use a non-root user in Docker containers',
            'latest_tags': 'Use specific version tags instead of latest',
            'secrets_in_dockerfile': 'Use Docker secrets or environment variables',
            'unnecessary_packages': 'Remove unnecessary packages to reduce attack surface'
        }
        return remediation_map.get(category, 'Review and fix the identified issue')
    
    def _get_k8s_issue_severity(self, category: str) -> str:
        severity_map = {
            'privileged_containers': 'CRITICAL',
            'no_resource_limits': 'HIGH',
            'default_namespace': 'MEDIUM'
        }
        return severity_map.get(category, 'MEDIUM')
    
    def _get_k8s_remediation(self, category: str) -> str:
        remediation_map = {
            'privileged_containers': 'Disable privileged containers and privilege escalation',
            'no_resource_limits': 'Set resource limits and requests for all containers',
            'default_namespace': 'Use specific namespaces instead of default'
        }
        return remediation_map.get(category, 'Review and fix the identified issue')
    
    # Score calculation methods
    def _calculate_pipeline_security_score(self, content: str, issues: List[DevOpsIssue]) -> float:
        base_score = 100
        for issue in issues:
            if issue.severity == "CRITICAL":
                base_score -= 25
            elif issue.severity == "HIGH":
                base_score -= 15
            elif issue.severity == "MEDIUM":
                base_score -= 8
            elif issue.severity == "LOW":
                base_score -= 3
        return max(0, base_score)
    
    def _calculate_pipeline_efficiency_score(self, content: str) -> float:
        # Simplified efficiency calculation
        return 75.0  # Default score
    
    def _calculate_iac_security_score(self, content: str, issues: List[DevOpsIssue]) -> float:
        return self._calculate_pipeline_security_score(content, issues)
    
    def _calculate_container_security_score(self, content: str, issues: List[DevOpsIssue]) -> float:
        return self._calculate_pipeline_security_score(content, issues)
    
    def _calculate_k8s_security_score(self, content: str, issues: List[DevOpsIssue]) -> float:
        return self._calculate_pipeline_security_score(content, issues)
    
    def _calculate_overall_security_score(self, issues: List[DevOpsIssue]) -> float:
        if not issues:
            return 100.0
        
        base_score = 100
        for issue in issues:
            if issue.severity == "CRITICAL":
                base_score -= 20
            elif issue.severity == "HIGH":
                base_score -= 12
            elif issue.severity == "MEDIUM":
                base_score -= 6
            elif issue.severity == "LOW":
                base_score -= 2
        
        return max(0, base_score)
    
    # Recommendation generation methods
    def _generate_pipeline_recommendations(self, issues: List[DevOpsIssue], config: Dict) -> List[str]:
        return [
            "Add automated security scanning to pipeline",
            "Implement quality gates with coverage thresholds",
            "Use secret management for sensitive data",
            "Add deployment approval processes"
        ]
    
    def _generate_iac_recommendations(self, issues: List[DevOpsIssue]) -> List[str]:
        return [
            "Enable encryption for all storage resources",
            "Implement least privilege access policies",
            "Use specific security group rules",
            "Enable logging and monitoring"
        ]
    
    def _generate_container_recommendations(self, issues: List[DevOpsIssue]) -> List[str]:
        return [
            "Use non-root users in containers",
            "Implement multi-stage builds",
            "Use specific image tags",
            "Remove unnecessary packages"
        ]
    
    def _generate_k8s_recommendations(self, issues: List[DevOpsIssue]) -> List[str]:
        return [
            "Implement Pod Security Policies",
            "Set resource limits and requests",
            "Use specific namespaces",
            "Enable RBAC"
        ]
    
    def _generate_security_recommendations(self, issues: List[DevOpsIssue]) -> List[str]:
        return [
            "Implement secret management system",
            "Add security scanning to CI/CD pipeline",
            "Enable encryption in transit and at rest",
            "Implement least privilege access"
        ]
    
    def _generate_observability_recommendations(self, issues: List[DevOpsIssue]) -> List[str]:
        return [
            "Implement structured logging",
            "Add monitoring and alerting",
            "Set up distributed tracing",
            "Create operational dashboards"
        ]
    
    def _generate_compliance_recommendations(self, violations: List[DevOpsIssue]) -> List[str]:
        return [
            "Address critical security violations",
            "Implement audit logging",
            "Add compliance monitoring",
            "Regular compliance assessments"
        ]
    
    def _suggest_automation_tools(self, issues: List[DevOpsIssue]) -> List[str]:
        tools = set()
        for issue in issues:
            if issue.category == "cicd_security":
                tools.update(["GitHub Actions", "Jenkins", "GitLab CI"])
            elif issue.category == "container_security":
                tools.update(["Trivy", "Clair", "Snyk"])
            elif issue.category == "iac_security":
                tools.update(["Terraform", "Checkov", "tfsec"])
        
        return list(tools)
    
    def _assess_compliance_risk(self, violations: List[DevOpsIssue]) -> str:
        if not violations:
            return "LOW"
        
        critical_count = len([v for v in violations if v.severity == "CRITICAL"])
        high_count = len([v for v in violations if v.severity == "HIGH"])
        
        if critical_count > 0:
            return "CRITICAL"
        elif high_count > 2:
            return "HIGH"
        elif high_count > 0:
            return "MEDIUM"
        else:
            return "LOW"

