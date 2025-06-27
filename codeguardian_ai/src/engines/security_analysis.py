"""
CodeGuardian AI - Security Analysis Engine
Advanced vulnerability detection with proof-of-concept generation
"""

import re
import ast
import json
import uuid
import hashlib
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
from enum import Enum

class VulnerabilityType(Enum):
    """Types of vulnerabilities that can be detected"""
    SQL_INJECTION = "sql_injection"
    XSS = "cross_site_scripting"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    WEAK_CRYPTOGRAPHY = "weak_cryptography"
    HARDCODED_SECRETS = "hardcoded_secrets"
    UNSAFE_EVAL = "unsafe_eval"
    BUFFER_OVERFLOW = "buffer_overflow"
    RACE_CONDITION = "race_condition"

class SeverityLevel(Enum):
    """Severity levels for vulnerabilities"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

@dataclass
class Vulnerability:
    """Represents a detected vulnerability"""
    id: str
    type: VulnerabilityType
    severity: SeverityLevel
    title: str
    description: str
    line_number: int
    code_snippet: str
    cwe_id: Optional[str] = None
    cvss_score: Optional[float] = None
    proof_of_concept: Optional[str] = None
    mitigation: Optional[str] = None
    references: Optional[List[str]] = None
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()
        if self.id is None:
            self.id = str(uuid.uuid4())
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['type'] = self.type.value
        result['severity'] = self.severity.value
        return result

@dataclass
class SecurityAnalysisResult:
    """Result of security analysis"""
    analysis_id: str
    code: str
    language: str
    vulnerabilities: List[Vulnerability]
    total_vulnerabilities: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    analysis_time: float
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()
        
        # Calculate counts
        self.total_vulnerabilities = len(self.vulnerabilities)
        self.critical_count = sum(1 for v in self.vulnerabilities if v.severity == SeverityLevel.CRITICAL)
        self.high_count = sum(1 for v in self.vulnerabilities if v.severity == SeverityLevel.HIGH)
        self.medium_count = sum(1 for v in self.vulnerabilities if v.severity == SeverityLevel.MEDIUM)
        self.low_count = sum(1 for v in self.vulnerabilities if v.severity == SeverityLevel.LOW)
    
    def to_dict(self) -> Dict[str, Any]:
        result = asdict(self)
        result['vulnerabilities'] = [v.to_dict() for v in self.vulnerabilities]
        return result

class PythonSecurityAnalyzer:
    """Security analyzer for Python code"""
    
    def __init__(self):
        self.patterns = self._load_vulnerability_patterns()
    
    def _load_vulnerability_patterns(self) -> Dict[VulnerabilityType, List[Dict]]:
        """Load vulnerability detection patterns"""
        return {
            VulnerabilityType.SQL_INJECTION: [
                {
                    'pattern': r'execute\s*\(\s*["\'].*%.*["\']',
                    'description': 'SQL query with string formatting - potential SQL injection',
                    'severity': SeverityLevel.HIGH,
                    'cwe_id': 'CWE-89',
                    'mitigation': 'Use parameterized queries or prepared statements'
                },
                {
                    'pattern': r'cursor\.execute\s*\(\s*f["\']',
                    'description': 'SQL query with f-string - potential SQL injection',
                    'severity': SeverityLevel.HIGH,
                    'cwe_id': 'CWE-89',
                    'mitigation': 'Use parameterized queries instead of f-strings'
                }
            ],
            VulnerabilityType.COMMAND_INJECTION: [
                {
                    'pattern': r'os\.system\s*\(\s*.*\+',
                    'description': 'Command execution with concatenated input - potential command injection',
                    'severity': SeverityLevel.CRITICAL,
                    'cwe_id': 'CWE-78',
                    'mitigation': 'Use subprocess with shell=False and validate inputs'
                },
                {
                    'pattern': r'subprocess\.(call|run|Popen).*shell\s*=\s*True',
                    'description': 'Subprocess call with shell=True - potential command injection',
                    'severity': SeverityLevel.HIGH,
                    'cwe_id': 'CWE-78',
                    'mitigation': 'Use shell=False and pass arguments as list'
                }
            ],
            VulnerabilityType.UNSAFE_EVAL: [
                {
                    'pattern': r'eval\s*\(',
                    'description': 'Use of eval() function - code injection risk',
                    'severity': SeverityLevel.CRITICAL,
                    'cwe_id': 'CWE-95',
                    'mitigation': 'Avoid eval(). Use ast.literal_eval() for safe evaluation'
                },
                {
                    'pattern': r'exec\s*\(',
                    'description': 'Use of exec() function - code injection risk',
                    'severity': SeverityLevel.CRITICAL,
                    'cwe_id': 'CWE-95',
                    'mitigation': 'Avoid exec(). Redesign to avoid dynamic code execution'
                }
            ],
            VulnerabilityType.HARDCODED_SECRETS: [
                {
                    'pattern': r'password\s*=\s*["\'][^"\']{8,}["\']',
                    'description': 'Hardcoded password detected',
                    'severity': SeverityLevel.HIGH,
                    'cwe_id': 'CWE-798',
                    'mitigation': 'Use environment variables or secure credential storage'
                },
                {
                    'pattern': r'api_key\s*=\s*["\'][A-Za-z0-9]{20,}["\']',
                    'description': 'Hardcoded API key detected',
                    'severity': SeverityLevel.HIGH,
                    'cwe_id': 'CWE-798',
                    'mitigation': 'Use environment variables or secure credential storage'
                }
            ],
            VulnerabilityType.WEAK_CRYPTOGRAPHY: [
                {
                    'pattern': r'hashlib\.md5\s*\(',
                    'description': 'Use of weak MD5 hash algorithm',
                    'severity': SeverityLevel.MEDIUM,
                    'cwe_id': 'CWE-327',
                    'mitigation': 'Use SHA-256 or stronger hash algorithms'
                },
                {
                    'pattern': r'hashlib\.sha1\s*\(',
                    'description': 'Use of weak SHA-1 hash algorithm',
                    'severity': SeverityLevel.MEDIUM,
                    'cwe_id': 'CWE-327',
                    'mitigation': 'Use SHA-256 or stronger hash algorithms'
                }
            ],
            VulnerabilityType.PATH_TRAVERSAL: [
                {
                    'pattern': r'open\s*\(\s*.*\+.*["\']\.\./',
                    'description': 'File path with directory traversal pattern',
                    'severity': SeverityLevel.HIGH,
                    'cwe_id': 'CWE-22',
                    'mitigation': 'Validate and sanitize file paths, use os.path.join()'
                }
            ]
        }
    
    def analyze(self, code: str) -> List[Vulnerability]:
        """Analyze Python code for security vulnerabilities"""
        vulnerabilities = []
        lines = code.split('\n')
        
        for vuln_type, patterns in self.patterns.items():
            for pattern_info in patterns:
                pattern = pattern_info['pattern']
                
                for line_num, line in enumerate(lines, 1):
                    if re.search(pattern, line, re.IGNORECASE):
                        vulnerability = Vulnerability(
                            id=str(uuid.uuid4()),
                            type=vuln_type,
                            severity=pattern_info['severity'],
                            title=f"{vuln_type.value.replace('_', ' ').title()} Detected",
                            description=pattern_info['description'],
                            line_number=line_num,
                            code_snippet=line.strip(),
                            cwe_id=pattern_info.get('cwe_id'),
                            mitigation=pattern_info.get('mitigation'),
                            proof_of_concept=self._generate_poc(vuln_type, line.strip())
                        )
                        vulnerabilities.append(vulnerability)
        
        return vulnerabilities
    
    def _generate_poc(self, vuln_type: VulnerabilityType, code_snippet: str) -> str:
        """Generate proof-of-concept for vulnerability"""
        poc_templates = {
            VulnerabilityType.SQL_INJECTION: """
# Proof of Concept - SQL Injection
# Vulnerable code: {code}
# Attack vector:
malicious_input = "'; DROP TABLE users; --"
# This input could be used to execute arbitrary SQL commands
""",
            VulnerabilityType.COMMAND_INJECTION: """
# Proof of Concept - Command Injection  
# Vulnerable code: {code}
# Attack vector:
malicious_input = "; cat /etc/passwd"
# This input could be used to execute arbitrary system commands
""",
            VulnerabilityType.UNSAFE_EVAL: """
# Proof of Concept - Code Injection via eval()
# Vulnerable code: {code}
# Attack vector:
malicious_input = "__import__('os').system('rm -rf /')"
# This input could be used to execute arbitrary Python code
""",
            VulnerabilityType.HARDCODED_SECRETS: """
# Proof of Concept - Hardcoded Secret Exposure
# Vulnerable code: {code}
# Risk: Secret is visible in source code and version control
# Attackers can extract credentials from:
# - Source code repositories
# - Compiled binaries
# - Memory dumps
""",
            VulnerabilityType.WEAK_CRYPTOGRAPHY: """
# Proof of Concept - Weak Cryptography
# Vulnerable code: {code}
# Risk: Hash can be cracked using:
# - Rainbow tables
# - Brute force attacks
# - Collision attacks
""",
            VulnerabilityType.PATH_TRAVERSAL: """
# Proof of Concept - Path Traversal
# Vulnerable code: {code}
# Attack vector:
malicious_path = "../../../etc/passwd"
# This could be used to access files outside intended directory
"""
        }
        
        template = poc_templates.get(vuln_type, "# No specific PoC available for this vulnerability type")
        return template.format(code=code_snippet)

class SecurityAnalysisEngine:
    """Main engine for security analysis"""
    
    def __init__(self):
        self.python_analyzer = PythonSecurityAnalyzer()
    
    def analyze(self, code: str, language: str = "python") -> SecurityAnalysisResult:
        """Analyze code for security vulnerabilities"""
        import time
        start_time = time.time()
        
        analysis_id = str(uuid.uuid4())
        
        if language.lower() != "python":
            return SecurityAnalysisResult(
                analysis_id=analysis_id,
                code=code,
                language=language,
                vulnerabilities=[],
                total_vulnerabilities=0,
                critical_count=0,
                high_count=0,
                medium_count=0,
                low_count=0,
                analysis_time=time.time() - start_time
            )
        
        vulnerabilities = self.python_analyzer.analyze(code)
        analysis_time = time.time() - start_time
        
        return SecurityAnalysisResult(
            analysis_id=analysis_id,
            code=code,
            language=language,
            vulnerabilities=vulnerabilities,
            total_vulnerabilities=len(vulnerabilities),
            critical_count=0,  # Will be calculated in __post_init__
            high_count=0,
            medium_count=0,
            low_count=0,
            analysis_time=analysis_time
        )

# Example usage and testing
if __name__ == "__main__":
    # Test the security analysis engine
    engine = SecurityAnalysisEngine()
    
    # Test vulnerable code
    vulnerable_code = """
import os
import hashlib

def login(username, password):
    # Hardcoded password - vulnerability!
    admin_password = "admin123"
    
    # Weak hash algorithm - vulnerability!
    password_hash = hashlib.md5(password.encode()).hexdigest()
    
    if username == "admin" and password == admin_password:
        return True
    return False

def execute_command(user_input):
    # Command injection vulnerability!
    os.system("echo " + user_input)

def search_database(query):
    # SQL injection vulnerability!
    sql = f"SELECT * FROM users WHERE name = '{query}'"
    cursor.execute(sql)
    
def process_data(data):
    # Code injection vulnerability!
    result = eval(data)
    return result
"""
    
    result = engine.analyze(vulnerable_code)
    print("=== Security Analysis Result ===")
    print(json.dumps(result.to_dict(), indent=2))
    
    print(f"\n=== Summary ===")
    print(f"Total vulnerabilities found: {result.total_vulnerabilities}")
    print(f"Critical: {result.critical_count}")
    print(f"High: {result.high_count}")
    print(f"Medium: {result.medium_count}")
    print(f"Low: {result.low_count}")
    print(f"Analysis time: {result.analysis_time:.3f} seconds")

