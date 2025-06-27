"""
CodeGuardian AI - Enhanced Security Analysis Engine
Advanced security vulnerability detection with AST validation integration
"""

import re
import time
import hashlib
from typing import List, Dict, Any, Set
from dataclasses import dataclass, field
from enum import Enum

# Import the new AST validator
from src.engines.ast_validator import ASTValidator, SecurityLevel, ASTValidationResult

class VulnerabilityType(Enum):
    COMMAND_INJECTION = "command_injection"
    CODE_INJECTION = "code_injection"
    PATH_TRAVERSAL = "path_traversal"
    HARDCODED_CREDENTIALS = "hardcoded_credentials"
    WEAK_CRYPTOGRAPHY = "weak_cryptography"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    SQL_INJECTION = "sql_injection"
    XSS = "cross_site_scripting"
    UNSAFE_REFLECTION = "unsafe_reflection"
    INFORMATION_DISCLOSURE = "information_disclosure"
    DENIAL_OF_SERVICE = "denial_of_service"
    BUFFER_OVERFLOW = "buffer_overflow"

@dataclass
class Vulnerability:
    type: VulnerabilityType
    severity: str  # "critical", "high", "medium", "low"
    line_number: int
    description: str
    code_snippet: str
    proof_of_concept: str
    mitigation: str
    confidence: float = 1.0
    cwe_id: str = ""
    cvss_score: float = 0.0

@dataclass
class SecurityAnalysisResult:
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    analysis_time: float = 0.0
    code_hash: str = ""
    language: str = "python"
    ast_validation_result: ASTValidationResult = None
    
    @property
    def total_vulnerabilities(self) -> int:
        return len(self.vulnerabilities)
    
    @property
    def critical_count(self) -> int:
        return len([v for v in self.vulnerabilities if v.severity == "critical"])
    
    @property
    def high_count(self) -> int:
        return len([v for v in self.vulnerabilities if v.severity == "high"])
    
    @property
    def medium_count(self) -> int:
        return len([v for v in self.vulnerabilities if v.severity == "medium"])
    
    @property
    def low_count(self) -> int:
        return len([v for v in self.vulnerabilities if v.severity == "low"])
    
    @property
    def max_severity(self) -> str:
        if self.critical_count > 0:
            return "critical"
        elif self.high_count > 0:
            return "high"
        elif self.medium_count > 0:
            return "medium"
        elif self.low_count > 0:
            return "low"
        return "none"
    
    def to_dict(self) -> Dict[str, Any]:
        result = {
            'vulnerabilities': [
                {
                    'type': v.type.value,
                    'severity': v.severity,
                    'line_number': v.line_number,
                    'description': v.description,
                    'code_snippet': v.code_snippet,
                    'proof_of_concept': v.proof_of_concept,
                    'mitigation': v.mitigation,
                    'confidence': v.confidence,
                    'cwe_id': v.cwe_id,
                    'cvss_score': v.cvss_score
                }
                for v in self.vulnerabilities
            ],
            'summary': {
                'total_vulnerabilities': self.total_vulnerabilities,
                'critical_count': self.critical_count,
                'high_count': self.high_count,
                'medium_count': self.medium_count,
                'low_count': self.low_count,
                'max_severity': self.max_severity
            },
            'analysis_time': self.analysis_time,
            'code_hash': self.code_hash,
            'language': self.language
        }
        
        # Include AST validation results if available
        if self.ast_validation_result:
            result['ast_validation'] = self.ast_validation_result.to_dict()
        
        return result

class SecurityAnalysisEngine:
    """Enhanced security analysis engine with AST validation"""
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.MODERATE):
        self.ast_validator = ASTValidator(security_level)
        self._setup_patterns()
    
    def _setup_patterns(self):
        """Setup regex patterns for legacy detection (fallback)"""
        self.vulnerability_patterns = {
            VulnerabilityType.COMMAND_INJECTION: [
                (r'os\.system\s*\(', "critical", "CWE-78", 9.8),
                (r'subprocess\.(call|run|Popen)', "critical", "CWE-78", 9.8),
                (r'commands\.(getoutput|getstatusoutput)', "high", "CWE-78", 8.8),
                (r'eval\s*\(', "critical", "CWE-95", 9.8),
                (r'exec\s*\(', "critical", "CWE-95", 9.8),
            ],
            VulnerabilityType.CODE_INJECTION: [
                (r'compile\s*\(', "high", "CWE-95", 8.8),
                (r'__import__\s*\(', "high", "CWE-95", 8.8),
                (r'importlib\.import_module', "medium", "CWE-95", 6.1),
            ],
            VulnerabilityType.PATH_TRAVERSAL: [
                (r'open\s*\([^)]*\.\./.*\)', "high", "CWE-22", 7.5),
                (r'file\s*\([^)]*\.\./.*\)', "high", "CWE-22", 7.5),
                (r'\.\./', "medium", "CWE-22", 5.3),
            ],
            VulnerabilityType.HARDCODED_CREDENTIALS: [
                (r'password\s*=\s*["\'][^"\']+["\']', "high", "CWE-798", 7.5),
                (r'passwd\s*=\s*["\'][^"\']+["\']', "high", "CWE-798", 7.5),
                (r'secret\s*=\s*["\'][^"\']+["\']', "medium", "CWE-798", 6.1),
                (r'api_key\s*=\s*["\'][^"\']+["\']', "medium", "CWE-798", 6.1),
                (r'token\s*=\s*["\'][^"\']+["\']', "medium", "CWE-798", 6.1),
            ],
            VulnerabilityType.WEAK_CRYPTOGRAPHY: [
                (r'hashlib\.md5\s*\(', "medium", "CWE-327", 5.3),
                (r'hashlib\.sha1\s*\(', "medium", "CWE-327", 5.3),
                (r'random\.random\s*\(', "low", "CWE-338", 3.1),
            ],
            VulnerabilityType.INSECURE_DESERIALIZATION: [
                (r'pickle\.loads?\s*\(', "critical", "CWE-502", 9.8),
                (r'marshal\.loads?\s*\(', "critical", "CWE-502", 9.8),
                (r'yaml\.load\s*\(', "high", "CWE-502", 8.8),
            ],
            VulnerabilityType.SQL_INJECTION: [
                (r'execute\s*\([^)]*%[^)]*\)', "critical", "CWE-89", 9.8),
                (r'cursor\.execute\s*\([^)]*\+[^)]*\)', "critical", "CWE-89", 9.8),
                (r'SELECT.*\+.*FROM', "high", "CWE-89", 8.8),
            ],
            VulnerabilityType.UNSAFE_REFLECTION: [
                (r'getattr\s*\(', "medium", "CWE-470", 6.1),
                (r'setattr\s*\(', "medium", "CWE-470", 6.1),
                (r'hasattr\s*\(', "low", "CWE-470", 3.1),
                (r'vars\s*\(', "medium", "CWE-470", 6.1),
                (r'globals\s*\(', "high", "CWE-470", 7.5),
                (r'locals\s*\(', "medium", "CWE-470", 6.1),
            ]
        }
    
    def analyze(self, code: str, language: str = "python") -> SecurityAnalysisResult:
        """Perform comprehensive security analysis"""
        start_time = time.time()
        
        # Generate code hash for caching/tracking
        code_hash = hashlib.sha256(code.encode()).hexdigest()[:16]
        
        # Initialize result
        result = SecurityAnalysisResult(
            code_hash=code_hash,
            language=language
        )
        
        # Step 1: AST-based validation (primary method)
        ast_result = self.ast_validator.validate_code(code, language)
        result.ast_validation_result = ast_result
        
        # Convert AST violations to vulnerabilities
        for violation in ast_result.violations:
            vulnerability = self._ast_violation_to_vulnerability(violation)
            if vulnerability:
                result.vulnerabilities.append(vulnerability)
        
        # Step 2: Legacy regex-based analysis (fallback/supplementary)
        if language.lower() == "python":
            regex_vulnerabilities = self._regex_based_analysis(code)
            
            # Merge regex results, avoiding duplicates
            for vuln in regex_vulnerabilities:
                if not self._is_duplicate_vulnerability(vuln, result.vulnerabilities):
                    result.vulnerabilities.append(vuln)
        
        # Step 3: Advanced pattern analysis
        advanced_vulnerabilities = self._advanced_pattern_analysis(code)
        for vuln in advanced_vulnerabilities:
            if not self._is_duplicate_vulnerability(vuln, result.vulnerabilities):
                result.vulnerabilities.append(vuln)
        
        result.analysis_time = time.time() - start_time
        return result
    
    def _ast_violation_to_vulnerability(self, violation) -> Vulnerability:
        """Convert AST violation to vulnerability"""
        # Map AST violation types to vulnerability types
        type_mapping = {
            'forbidden_import': VulnerabilityType.CODE_INJECTION,
            'forbidden_builtin': VulnerabilityType.CODE_INJECTION,
            'forbidden_function': VulnerabilityType.CODE_INJECTION,
            'exec_eval_usage': VulnerabilityType.CODE_INJECTION,
            'subprocess_usage': VulnerabilityType.COMMAND_INJECTION,
            'reflection_usage': VulnerabilityType.UNSAFE_REFLECTION,
            'dynamic_code': VulnerabilityType.CODE_INJECTION,
            'encoding_manipulation': VulnerabilityType.CODE_INJECTION,
            'obfuscation_attempt': VulnerabilityType.CODE_INJECTION,
        }
        
        vuln_type = type_mapping.get(violation.violation_type.value, VulnerabilityType.CODE_INJECTION)
        
        # Map severity to CVSS score
        cvss_mapping = {
            'critical': 9.8,
            'high': 7.5,
            'medium': 5.3,
            'low': 3.1
        }
        
        return Vulnerability(
            type=vuln_type,
            severity=violation.severity,
            line_number=violation.line_number,
            description=violation.description,
            code_snippet=violation.code_snippet,
            proof_of_concept=f"AST analysis detected: {violation.description}",
            mitigation=violation.suggestion,
            confidence=violation.confidence,
            cwe_id=self._get_cwe_for_type(vuln_type),
            cvss_score=cvss_mapping.get(violation.severity, 0.0)
        )
    
    def _regex_based_analysis(self, code: str) -> List[Vulnerability]:
        """Legacy regex-based analysis for additional coverage"""
        vulnerabilities = []
        lines = code.split('\n')
        
        for vuln_type, patterns in self.vulnerability_patterns.items():
            for pattern, severity, cwe_id, cvss_score in patterns:
                for line_num, line in enumerate(lines, 1):
                    matches = re.finditer(pattern, line, re.IGNORECASE)
                    for match in matches:
                        vulnerability = Vulnerability(
                            type=vuln_type,
                            severity=severity,
                            line_number=line_num,
                            description=self._get_description_for_pattern(vuln_type, pattern),
                            code_snippet=line.strip(),
                            proof_of_concept=self._generate_poc(vuln_type, match.group()),
                            mitigation=self._get_mitigation_for_type(vuln_type),
                            confidence=0.8,  # Lower confidence for regex-based detection
                            cwe_id=cwe_id,
                            cvss_score=cvss_score
                        )
                        vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _advanced_pattern_analysis(self, code: str) -> List[Vulnerability]:
        """Advanced pattern analysis for sophisticated attacks"""
        vulnerabilities = []
        
        # Check for base64 encoded content
        base64_pattern = r'[A-Za-z0-9+/]{20,}={0,2}'
        matches = re.finditer(base64_pattern, code)
        for match in matches:
            try:
                import base64
                decoded = base64.b64decode(match.group())
                if b'import' in decoded or b'exec' in decoded or b'eval' in decoded:
                    vulnerabilities.append(Vulnerability(
                        type=VulnerabilityType.CODE_INJECTION,
                        severity="high",
                        line_number=code[:match.start()].count('\n') + 1,
                        description="Suspicious base64 encoded content detected",
                        code_snippet=match.group()[:50] + "...",
                        proof_of_concept=f"Base64 content may contain: {decoded[:50]}",
                        mitigation="Avoid encoding executable code in base64",
                        confidence=0.7,
                        cwe_id="CWE-95",
                        cvss_score=7.5
                    ))
            except:
                pass
        
        # Check for URL patterns that might indicate data exfiltration
        url_pattern = r'https?://[^\s<>"\']+|ftp://[^\s<>"\']+|file://[^\s<>"\']+'
        matches = re.finditer(url_pattern, code)
        for match in matches:
            vulnerabilities.append(Vulnerability(
                type=VulnerabilityType.INFORMATION_DISCLOSURE,
                severity="medium",
                line_number=code[:match.start()].count('\n') + 1,
                description="External URL detected - potential data exfiltration",
                code_snippet=match.group(),
                proof_of_concept=f"Code contains URL: {match.group()}",
                mitigation="Review external connections for data leakage",
                confidence=0.5,
                cwe_id="CWE-200",
                cvss_score=5.3
            ))
        
        return vulnerabilities
    
    def _is_duplicate_vulnerability(self, new_vuln: Vulnerability, existing_vulns: List[Vulnerability]) -> bool:
        """Check if vulnerability is duplicate"""
        for existing in existing_vulns:
            if (existing.type == new_vuln.type and 
                existing.line_number == new_vuln.line_number and
                existing.severity == new_vuln.severity):
                return True
        return False
    
    def _get_description_for_pattern(self, vuln_type: VulnerabilityType, pattern: str) -> str:
        """Get description for vulnerability pattern"""
        descriptions = {
            VulnerabilityType.COMMAND_INJECTION: "Command injection vulnerability detected",
            VulnerabilityType.CODE_INJECTION: "Code injection vulnerability detected",
            VulnerabilityType.PATH_TRAVERSAL: "Path traversal vulnerability detected",
            VulnerabilityType.HARDCODED_CREDENTIALS: "Hardcoded credentials detected",
            VulnerabilityType.WEAK_CRYPTOGRAPHY: "Weak cryptographic algorithm detected",
            VulnerabilityType.INSECURE_DESERIALIZATION: "Insecure deserialization detected",
            VulnerabilityType.SQL_INJECTION: "SQL injection vulnerability detected",
            VulnerabilityType.UNSAFE_REFLECTION: "Unsafe reflection usage detected"
        }
        return descriptions.get(vuln_type, "Security vulnerability detected")
    
    def _generate_poc(self, vuln_type: VulnerabilityType, matched_text: str) -> str:
        """Generate proof of concept for vulnerability"""
        pocs = {
            VulnerabilityType.COMMAND_INJECTION: f"Attacker could execute: {matched_text}('malicious_command')",
            VulnerabilityType.CODE_INJECTION: f"Attacker could inject: {matched_text}('__import__(\"os\").system(\"rm -rf /\")')",
            VulnerabilityType.PATH_TRAVERSAL: f"Attacker could access: {matched_text}('../../../etc/passwd')",
            VulnerabilityType.HARDCODED_CREDENTIALS: f"Credentials exposed: {matched_text}",
            VulnerabilityType.WEAK_CRYPTOGRAPHY: f"Weak algorithm: {matched_text} - easily crackable",
            VulnerabilityType.INSECURE_DESERIALIZATION: f"Malicious payload: {matched_text}(malicious_data)",
            VulnerabilityType.SQL_INJECTION: f"SQL injection: {matched_text} with malicious input",
            VulnerabilityType.UNSAFE_REFLECTION: f"Reflection abuse: {matched_text}(obj, 'dangerous_method')"
        }
        return pocs.get(vuln_type, f"Vulnerability in: {matched_text}")
    
    def _get_mitigation_for_type(self, vuln_type: VulnerabilityType) -> str:
        """Get mitigation advice for vulnerability type"""
        mitigations = {
            VulnerabilityType.COMMAND_INJECTION: "Use subprocess with shell=False and validate inputs",
            VulnerabilityType.CODE_INJECTION: "Avoid eval/exec, use safe alternatives like ast.literal_eval",
            VulnerabilityType.PATH_TRAVERSAL: "Validate file paths and use os.path.join() safely",
            VulnerabilityType.HARDCODED_CREDENTIALS: "Use environment variables or secure credential storage",
            VulnerabilityType.WEAK_CRYPTOGRAPHY: "Use strong algorithms like SHA-256 or bcrypt",
            VulnerabilityType.INSECURE_DESERIALIZATION: "Use safe serialization formats like JSON",
            VulnerabilityType.SQL_INJECTION: "Use parameterized queries or ORM",
            VulnerabilityType.UNSAFE_REFLECTION: "Avoid dynamic attribute access, use explicit methods"
        }
        return mitigations.get(vuln_type, "Review and secure the code")
    
    def _get_cwe_for_type(self, vuln_type: VulnerabilityType) -> str:
        """Get CWE ID for vulnerability type"""
        cwe_mapping = {
            VulnerabilityType.COMMAND_INJECTION: "CWE-78",
            VulnerabilityType.CODE_INJECTION: "CWE-95",
            VulnerabilityType.PATH_TRAVERSAL: "CWE-22",
            VulnerabilityType.HARDCODED_CREDENTIALS: "CWE-798",
            VulnerabilityType.WEAK_CRYPTOGRAPHY: "CWE-327",
            VulnerabilityType.INSECURE_DESERIALIZATION: "CWE-502",
            VulnerabilityType.SQL_INJECTION: "CWE-89",
            VulnerabilityType.UNSAFE_REFLECTION: "CWE-470"
        }
        return cwe_mapping.get(vuln_type, "CWE-0")

# Example usage
if __name__ == "__main__":
    engine = SecurityAnalysisEngine(SecurityLevel.MODERATE)
    
    # Test with dangerous code
    dangerous_code = """
import os
import subprocess

password = "admin123"
api_key = "secret_key_12345"

def dangerous_function(user_input):
    # Command injection
    os.system(f"ls {user_input}")
    
    # Code injection
    eval(user_input)
    exec(user_input)
    
    # Path traversal
    with open(f"../../../{user_input}", 'r') as f:
        content = f.read()
    
    # SQL injection
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)
    
    return content

result = dangerous_function("test")
    """
    
    result = engine.analyze(dangerous_code)
    print(f"Analysis completed in {result.analysis_time:.3f}s")
    print(f"Found {result.total_vulnerabilities} vulnerabilities:")
    print(f"  Critical: {result.critical_count}")
    print(f"  High: {result.high_count}")
    print(f"  Medium: {result.medium_count}")
    print(f"  Low: {result.low_count}")
    
    for vuln in result.vulnerabilities[:5]:  # Show first 5
        print(f"\n{vuln.severity.upper()}: {vuln.description}")
        print(f"  Line {vuln.line_number}: {vuln.code_snippet}")
        print(f"  Mitigation: {vuln.mitigation}")

