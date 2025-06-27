"""
CodeGuardian AI - Advanced AST Validation System
Enterprise-grade Abstract Syntax Tree analysis for robust code validation
Replaces regex-based validation with proper parsing and semantic analysis
"""

import ast
import sys
import types
import inspect
import builtins
from typing import Dict, List, Set, Any, Optional, Tuple, Union
from dataclasses import dataclass, field
from enum import Enum
import re
import keyword

class SecurityLevel(Enum):
    """Security levels for AST validation"""
    PERMISSIVE = "permissive"      # Allow most operations
    MODERATE = "moderate"          # Block dangerous operations
    STRICT = "strict"              # Block potentially dangerous operations
    PARANOID = "paranoid"          # Block almost everything except basic operations

class ViolationType(Enum):
    """Types of security violations"""
    FORBIDDEN_IMPORT = "forbidden_import"
    FORBIDDEN_BUILTIN = "forbidden_builtin"
    FORBIDDEN_ATTRIBUTE = "forbidden_attribute"
    FORBIDDEN_FUNCTION = "forbidden_function"
    EXEC_EVAL_USAGE = "exec_eval_usage"
    FILE_SYSTEM_ACCESS = "file_system_access"
    NETWORK_ACCESS = "network_access"
    SUBPROCESS_USAGE = "subprocess_usage"
    REFLECTION_USAGE = "reflection_usage"
    DYNAMIC_CODE = "dynamic_code"
    INFINITE_LOOP = "infinite_loop"
    EXCESSIVE_COMPLEXITY = "excessive_complexity"
    OBFUSCATION_ATTEMPT = "obfuscation_attempt"
    ENCODING_MANIPULATION = "encoding_manipulation"
    MEMORY_EXHAUSTION = "memory_exhaustion"

@dataclass
class SecurityViolation:
    """Represents a security violation found in code"""
    violation_type: ViolationType
    severity: str  # "critical", "high", "medium", "low"
    line_number: int
    column_number: int
    node_type: str
    description: str
    code_snippet: str
    suggestion: str
    confidence: float = 1.0  # 0.0 to 1.0

@dataclass
class ComplexityMetrics:
    """Code complexity metrics"""
    cyclomatic_complexity: int = 0
    cognitive_complexity: int = 0
    nesting_depth: int = 0
    function_count: int = 0
    class_count: int = 0
    import_count: int = 0
    line_count: int = 0
    halstead_difficulty: float = 0.0

@dataclass
class ASTValidationResult:
    """Result of AST validation"""
    is_valid: bool
    violations: List[SecurityViolation] = field(default_factory=list)
    complexity_metrics: ComplexityMetrics = field(default_factory=ComplexityMetrics)
    allowed_imports: Set[str] = field(default_factory=set)
    forbidden_patterns: List[str] = field(default_factory=list)
    execution_time: float = 0.0
    
    @property
    def critical_violations(self) -> List[SecurityViolation]:
        return [v for v in self.violations if v.severity == "critical"]
    
    @property
    def high_violations(self) -> List[SecurityViolation]:
        return [v for v in self.violations if v.severity == "high"]
    
    @property
    def has_critical_issues(self) -> bool:
        return len(self.critical_violations) > 0
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            'is_valid': self.is_valid,
            'violations': [
                {
                    'type': v.violation_type.value,
                    'severity': v.severity,
                    'line': v.line_number,
                    'column': v.column_number,
                    'node_type': v.node_type,
                    'description': v.description,
                    'code_snippet': v.code_snippet,
                    'suggestion': v.suggestion,
                    'confidence': v.confidence
                }
                for v in self.violations
            ],
            'complexity_metrics': {
                'cyclomatic_complexity': self.complexity_metrics.cyclomatic_complexity,
                'cognitive_complexity': self.complexity_metrics.cognitive_complexity,
                'nesting_depth': self.complexity_metrics.nesting_depth,
                'function_count': self.complexity_metrics.function_count,
                'class_count': self.complexity_metrics.class_count,
                'import_count': self.complexity_metrics.import_count,
                'line_count': self.complexity_metrics.line_count,
                'halstead_difficulty': self.complexity_metrics.halstead_difficulty
            },
            'summary': {
                'total_violations': len(self.violations),
                'critical_count': len(self.critical_violations),
                'high_count': len(self.high_violations),
                'has_critical_issues': self.has_critical_issues,
                'execution_time': self.execution_time
            }
        }

class SecurityConfig:
    """Configuration for security validation"""
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.MODERATE):
        self.security_level = security_level
        self._setup_rules()
    
    def _setup_rules(self):
        """Setup security rules based on security level"""
        
        # Base forbidden imports (always blocked)
        self.forbidden_imports = {
            'os', 'sys', 'subprocess', 'shutil', 'glob', 'tempfile',
            'socket', 'urllib', 'requests', 'http', 'ftplib', 'smtplib',
            'pickle', 'marshal', 'shelve', 'dbm', 'sqlite3',
            'ctypes', 'multiprocessing', 'threading', 'asyncio',
            'importlib', '__builtin__', '__builtins__', 'builtins'
        }
        
        # Base forbidden builtins (always blocked)
        self.forbidden_builtins = {
            'eval', 'exec', 'compile', '__import__', 'open', 'file',
            'input', 'raw_input', 'reload', 'vars', 'locals', 'globals',
            'dir', 'getattr', 'setattr', 'delattr', 'hasattr'
        }
        
        # Base forbidden attributes
        self.forbidden_attributes = {
            '__class__', '__bases__', '__subclasses__', '__mro__',
            '__globals__', '__code__', '__func__', '__self__',
            'func_globals', 'func_code', 'gi_frame', 'gi_code'
        }
        
        # Adjust rules based on security level
        if self.security_level == SecurityLevel.PERMISSIVE:
            # Remove some restrictions for permissive mode
            self.forbidden_imports.discard('json')
            self.forbidden_imports.discard('re')
            self.forbidden_imports.discard('datetime')
            
        elif self.security_level == SecurityLevel.STRICT:
            # Add more restrictions for strict mode
            self.forbidden_imports.update({
                'json', 're', 'datetime', 'random', 'hashlib',
                'base64', 'binascii', 'codecs', 'encodings'
            })
            self.forbidden_builtins.update({
                'type', 'isinstance', 'issubclass', 'callable'
            })
            
        elif self.security_level == SecurityLevel.PARANOID:
            # Maximum restrictions for paranoid mode
            self.forbidden_imports.update({
                'json', 're', 'datetime', 'random', 'hashlib',
                'base64', 'binascii', 'codecs', 'encodings',
                'collections', 'itertools', 'functools', 'operator'
            })
            self.forbidden_builtins.update({
                'type', 'isinstance', 'issubclass', 'callable',
                'map', 'filter', 'reduce', 'zip', 'enumerate'
            })
        
        # Complexity limits based on security level
        self.max_cyclomatic_complexity = {
            SecurityLevel.PERMISSIVE: 20,
            SecurityLevel.MODERATE: 15,
            SecurityLevel.STRICT: 10,
            SecurityLevel.PARANOID: 5
        }[self.security_level]
        
        self.max_nesting_depth = {
            SecurityLevel.PERMISSIVE: 8,
            SecurityLevel.MODERATE: 6,
            SecurityLevel.STRICT: 4,
            SecurityLevel.PARANOID: 3
        }[self.security_level]
        
        self.max_function_count = {
            SecurityLevel.PERMISSIVE: 50,
            SecurityLevel.MODERATE: 30,
            SecurityLevel.STRICT: 20,
            SecurityLevel.PARANOID: 10
        }[self.security_level]

class ASTSecurityAnalyzer(ast.NodeVisitor):
    """Advanced AST analyzer for security validation"""
    
    def __init__(self, config: SecurityConfig, source_code: str):
        self.config = config
        self.source_code = source_code
        self.source_lines = source_code.splitlines()
        self.violations: List[SecurityViolation] = []
        self.complexity_metrics = ComplexityMetrics()
        
        # Analysis state
        self.current_nesting_depth = 0
        self.max_nesting_depth = 0
        self.function_definitions = []
        self.class_definitions = []
        self.imports = set()
        self.function_calls = []
        self.attribute_accesses = []
        
        # Obfuscation detection
        self.suspicious_patterns = []
        self.encoding_attempts = []
        
    def analyze(self, tree: ast.AST) -> ASTValidationResult:
        """Perform complete AST analysis"""
        import time
        start_time = time.time()
        
        try:
            # Visit all nodes
            self.visit(tree)
            
            # Calculate final metrics
            self._calculate_complexity_metrics()
            
            # Detect obfuscation patterns
            self._detect_obfuscation()
            
            # Check for infinite loops
            self._check_infinite_loops(tree)
            
            execution_time = time.time() - start_time
            
            # Determine if code is valid
            is_valid = not any(v.severity in ['critical', 'high'] for v in self.violations)
            
            return ASTValidationResult(
                is_valid=is_valid,
                violations=self.violations,
                complexity_metrics=self.complexity_metrics,
                execution_time=execution_time
            )
            
        except Exception as e:
            # If AST analysis fails, it's likely malformed or malicious code
            self._add_violation(
                ViolationType.OBFUSCATION_ATTEMPT,
                "critical",
                1, 0, "unknown",
                f"Failed to parse code: {str(e)}",
                "Code appears to be malformed or obfuscated",
                "Ensure code is valid Python syntax"
            )
            
            return ASTValidationResult(
                is_valid=False,
                violations=self.violations,
                execution_time=time.time() - start_time
            )
    
    def visit_Import(self, node: ast.Import):
        """Handle import statements"""
        for alias in node.names:
            module_name = alias.name
            self.imports.add(module_name)
            self.complexity_metrics.import_count += 1
            
            if module_name in self.config.forbidden_imports:
                self._add_violation(
                    ViolationType.FORBIDDEN_IMPORT,
                    "critical",
                    node.lineno, node.col_offset,
                    "Import",
                    f"Forbidden import: {module_name}",
                    self._get_code_snippet(node.lineno),
                    f"Remove import of {module_name} or use an allowed alternative"
                )
        
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Handle from ... import statements"""
        module_name = node.module or ""
        self.imports.add(module_name)
        self.complexity_metrics.import_count += 1
        
        if module_name in self.config.forbidden_imports:
            self._add_violation(
                ViolationType.FORBIDDEN_IMPORT,
                "critical",
                node.lineno, node.col_offset,
                "ImportFrom",
                f"Forbidden import from: {module_name}",
                self._get_code_snippet(node.lineno),
                f"Remove import from {module_name}"
            )
        
        # Check for specific dangerous imports
        for alias in node.names:
            name = alias.name
            if name in self.config.forbidden_builtins:
                self._add_violation(
                    ViolationType.FORBIDDEN_BUILTIN,
                    "critical",
                    node.lineno, node.col_offset,
                    "ImportFrom",
                    f"Forbidden builtin import: {name}",
                    self._get_code_snippet(node.lineno),
                    f"Remove import of {name}"
                )
        
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call):
        """Handle function calls"""
        self.function_calls.append(node)
        
        # Check for forbidden builtin functions
        if isinstance(node.func, ast.Name):
            func_name = node.func.id
            if func_name in self.config.forbidden_builtins:
                severity = "critical" if func_name in ['eval', 'exec', 'compile'] else "high"
                self._add_violation(
                    ViolationType.FORBIDDEN_BUILTIN,
                    severity,
                    node.lineno, node.col_offset,
                    "Call",
                    f"Forbidden builtin function: {func_name}",
                    self._get_code_snippet(node.lineno),
                    f"Remove call to {func_name} or use a safe alternative"
                )
        
        # Check for attribute-based dangerous calls
        elif isinstance(node.func, ast.Attribute):
            attr_name = node.func.attr
            if attr_name in ['eval', 'exec', 'compile', 'open']:
                self._add_violation(
                    ViolationType.FORBIDDEN_FUNCTION,
                    "critical",
                    node.lineno, node.col_offset,
                    "Call",
                    f"Forbidden function call: {attr_name}",
                    self._get_code_snippet(node.lineno),
                    f"Remove call to {attr_name}"
                )
        
        self.generic_visit(node)
    
    def visit_Attribute(self, node: ast.Attribute):
        """Handle attribute access"""
        self.attribute_accesses.append(node)
        
        attr_name = node.attr
        if attr_name in self.config.forbidden_attributes:
            self._add_violation(
                ViolationType.FORBIDDEN_ATTRIBUTE,
                "high",
                node.lineno, node.col_offset,
                "Attribute",
                f"Forbidden attribute access: {attr_name}",
                self._get_code_snippet(node.lineno),
                f"Remove access to {attr_name}"
            )
        
        # Check for reflection patterns
        if attr_name in ['__class__', '__bases__', '__subclasses__']:
            self._add_violation(
                ViolationType.REFLECTION_USAGE,
                "medium",
                node.lineno, node.col_offset,
                "Attribute",
                f"Reflection usage detected: {attr_name}",
                self._get_code_snippet(node.lineno),
                "Avoid using reflection for security reasons"
            )
        
        self.generic_visit(node)
    
    def visit_FunctionDef(self, node: ast.FunctionDef):
        """Handle function definitions"""
        self.function_definitions.append(node)
        self.complexity_metrics.function_count += 1
        
        # Increase nesting depth
        self.current_nesting_depth += 1
        self.max_nesting_depth = max(self.max_nesting_depth, self.current_nesting_depth)
        
        # Check for suspicious function names
        if self._is_suspicious_name(node.name):
            self._add_violation(
                ViolationType.OBFUSCATION_ATTEMPT,
                "medium",
                node.lineno, node.col_offset,
                "FunctionDef",
                f"Suspicious function name: {node.name}",
                self._get_code_snippet(node.lineno),
                "Use descriptive function names"
            )
        
        self.generic_visit(node)
        
        # Decrease nesting depth
        self.current_nesting_depth -= 1
    
    def visit_ClassDef(self, node: ast.ClassDef):
        """Handle class definitions"""
        self.class_definitions.append(node)
        self.complexity_metrics.class_count += 1
        
        # Increase nesting depth
        self.current_nesting_depth += 1
        self.max_nesting_depth = max(self.max_nesting_depth, self.current_nesting_depth)
        
        self.generic_visit(node)
        
        # Decrease nesting depth
        self.current_nesting_depth -= 1
    
    def visit_If(self, node: ast.If):
        """Handle if statements"""
        self.current_nesting_depth += 1
        self.max_nesting_depth = max(self.max_nesting_depth, self.current_nesting_depth)
        
        self.generic_visit(node)
        
        self.current_nesting_depth -= 1
    
    def visit_For(self, node: ast.For):
        """Handle for loops"""
        self.current_nesting_depth += 1
        self.max_nesting_depth = max(self.max_nesting_depth, self.current_nesting_depth)
        
        self.generic_visit(node)
        
        self.current_nesting_depth -= 1
    
    def visit_While(self, node: ast.While):
        """Handle while loops"""
        self.current_nesting_depth += 1
        self.max_nesting_depth = max(self.max_nesting_depth, self.current_nesting_depth)
        
        # Check for potential infinite loops
        if isinstance(node.test, ast.Constant) and node.test.value is True:
            self._add_violation(
                ViolationType.INFINITE_LOOP,
                "high",
                node.lineno, node.col_offset,
                "While",
                "Potential infinite loop detected: while True",
                self._get_code_snippet(node.lineno),
                "Add proper exit condition to avoid infinite loop"
            )
        
        self.generic_visit(node)
        
        self.current_nesting_depth -= 1
    
    def visit_Try(self, node: ast.Try):
        """Handle try statements"""
        self.current_nesting_depth += 1
        self.max_nesting_depth = max(self.max_nesting_depth, self.current_nesting_depth)
        
        self.generic_visit(node)
        
        self.current_nesting_depth -= 1
    
    def visit_With(self, node: ast.With):
        """Handle with statements"""
        self.current_nesting_depth += 1
        self.max_nesting_depth = max(self.max_nesting_depth, self.current_nesting_depth)
        
        self.generic_visit(node)
        
        self.current_nesting_depth -= 1
    
    def visit_Str(self, node: ast.Str):
        """Handle string literals (Python < 3.8)"""
        self._check_string_content(node.s, node.lineno, node.col_offset)
        self.generic_visit(node)
    
    def visit_Constant(self, node: ast.Constant):
        """Handle constants (Python >= 3.8)"""
        if isinstance(node.value, str):
            self._check_string_content(node.value, node.lineno, node.col_offset)
        self.generic_visit(node)
    
    def _check_string_content(self, content: str, lineno: int, col_offset: int):
        """Check string content for suspicious patterns"""
        # Check for encoding attempts
        encoding_patterns = [
            r'\\x[0-9a-fA-F]{2}',  # Hex encoding
            r'\\u[0-9a-fA-F]{4}',  # Unicode encoding
            r'\\[0-7]{3}',         # Octal encoding
            r'base64',
            r'decode\(',
            r'encode\(',
        ]
        
        for pattern in encoding_patterns:
            if re.search(pattern, content):
                self._add_violation(
                    ViolationType.ENCODING_MANIPULATION,
                    "medium",
                    lineno, col_offset,
                    "String",
                    f"Potential encoding manipulation detected: {pattern}",
                    self._get_code_snippet(lineno),
                    "Avoid encoded strings that could hide malicious code"
                )
                break
        
        # Check for suspicious keywords in strings
        suspicious_keywords = ['eval', 'exec', 'import', '__import__', 'compile']
        for keyword in suspicious_keywords:
            if keyword in content.lower():
                self._add_violation(
                    ViolationType.DYNAMIC_CODE,
                    "high",
                    lineno, col_offset,
                    "String",
                    f"Suspicious keyword in string: {keyword}",
                    self._get_code_snippet(lineno),
                    f"Remove {keyword} from string content"
                )
    
    def _calculate_complexity_metrics(self):
        """Calculate complexity metrics"""
        self.complexity_metrics.nesting_depth = self.max_nesting_depth
        self.complexity_metrics.line_count = len(self.source_lines)
        
        # Calculate cyclomatic complexity (simplified)
        decision_points = 0
        for line in self.source_lines:
            stripped = line.strip()
            if any(keyword in stripped for keyword in ['if ', 'elif ', 'while ', 'for ', 'except ', 'and ', 'or ']):
                decision_points += 1
        
        self.complexity_metrics.cyclomatic_complexity = decision_points + 1
        
        # Check complexity limits
        if self.complexity_metrics.cyclomatic_complexity > self.config.max_cyclomatic_complexity:
            self._add_violation(
                ViolationType.EXCESSIVE_COMPLEXITY,
                "medium",
                1, 0,
                "Module",
                f"Cyclomatic complexity too high: {self.complexity_metrics.cyclomatic_complexity}",
                "Code is too complex",
                f"Reduce complexity to below {self.config.max_cyclomatic_complexity}"
            )
        
        if self.complexity_metrics.nesting_depth > self.config.max_nesting_depth:
            self._add_violation(
                ViolationType.EXCESSIVE_COMPLEXITY,
                "medium",
                1, 0,
                "Module",
                f"Nesting depth too high: {self.complexity_metrics.nesting_depth}",
                "Code nesting is too deep",
                f"Reduce nesting depth to below {self.config.max_nesting_depth}"
            )
        
        if self.complexity_metrics.function_count > self.config.max_function_count:
            self._add_violation(
                ViolationType.EXCESSIVE_COMPLEXITY,
                "low",
                1, 0,
                "Module",
                f"Too many functions: {self.complexity_metrics.function_count}",
                "Too many functions in module",
                f"Reduce function count to below {self.config.max_function_count}"
            )
    
    def _detect_obfuscation(self):
        """Detect obfuscation patterns"""
        # Check for suspicious variable names
        suspicious_names = []
        for line_num, line in enumerate(self.source_lines, 1):
            # Look for variables with suspicious names
            import re
            var_pattern = r'\b([a-zA-Z_][a-zA-Z0-9_]*)\s*='
            matches = re.findall(var_pattern, line)
            for match in matches:
                if self._is_suspicious_name(match):
                    suspicious_names.append((match, line_num))
        
        if len(suspicious_names) > 3:
            self._add_violation(
                ViolationType.OBFUSCATION_ATTEMPT,
                "medium",
                1, 0,
                "Module",
                f"Multiple suspicious variable names detected: {[name for name, _ in suspicious_names[:3]]}",
                "Code may be obfuscated",
                "Use descriptive variable names"
            )
    
    def _check_infinite_loops(self, tree: ast.AST):
        """Check for potential infinite loops"""
        # This is a simplified check - a full implementation would need more sophisticated analysis
        pass
    
    def _is_suspicious_name(self, name: str) -> bool:
        """Check if a name is suspicious (potential obfuscation)"""
        if len(name) == 1 and name not in ['i', 'j', 'k', 'x', 'y', 'z']:
            return True
        
        # Check for random-looking names
        if len(name) > 10 and not any(c in name.lower() for c in 'aeiou'):
            return True
        
        # Check for hex-like names
        if len(name) > 6 and all(c in '0123456789abcdefABCDEF_' for c in name):
            return True
        
        return False
    
    def _add_violation(self, violation_type: ViolationType, severity: str,
                      line: int, column: int, node_type: str,
                      description: str, code_snippet: str, suggestion: str,
                      confidence: float = 1.0):
        """Add a security violation"""
        violation = SecurityViolation(
            violation_type=violation_type,
            severity=severity,
            line_number=line,
            column_number=column,
            node_type=node_type,
            description=description,
            code_snippet=code_snippet,
            suggestion=suggestion,
            confidence=confidence
        )
        self.violations.append(violation)
    
    def _get_code_snippet(self, line_number: int, context: int = 0) -> str:
        """Get code snippet around the specified line"""
        if not self.source_lines:
            return ""
        
        start = max(0, line_number - 1 - context)
        end = min(len(self.source_lines), line_number + context)
        
        if start == end:
            return ""
        
        return self.source_lines[line_number - 1] if line_number <= len(self.source_lines) else ""

class ASTValidator:
    """Main AST validation class"""
    
    def __init__(self, security_level: SecurityLevel = SecurityLevel.MODERATE):
        self.config = SecurityConfig(security_level)
    
    def validate_code(self, source_code: str, language: str = "python") -> ASTValidationResult:
        """Validate source code using AST analysis"""
        if language.lower() != "python":
            # For now, only Python is supported
            return ASTValidationResult(
                is_valid=False,
                violations=[
                    SecurityViolation(
                        violation_type=ViolationType.FORBIDDEN_IMPORT,
                        severity="critical",
                        line_number=1,
                        column_number=0,
                        node_type="Module",
                        description=f"Unsupported language: {language}",
                        code_snippet="",
                        suggestion="Use Python code only"
                    )
                ]
            )
        
        try:
            # Parse the code into an AST
            tree = ast.parse(source_code)
            
            # Create analyzer and perform analysis
            analyzer = ASTSecurityAnalyzer(self.config, source_code)
            result = analyzer.analyze(tree)
            
            return result
            
        except SyntaxError as e:
            return ASTValidationResult(
                is_valid=False,
                violations=[
                    SecurityViolation(
                        violation_type=ViolationType.OBFUSCATION_ATTEMPT,
                        severity="critical",
                        line_number=e.lineno or 1,
                        column_number=e.offset or 0,
                        node_type="SyntaxError",
                        description=f"Syntax error: {str(e)}",
                        code_snippet=e.text or "",
                        suggestion="Fix syntax errors in the code"
                    )
                ]
            )
        
        except Exception as e:
            return ASTValidationResult(
                is_valid=False,
                violations=[
                    SecurityViolation(
                        violation_type=ViolationType.OBFUSCATION_ATTEMPT,
                        severity="critical",
                        line_number=1,
                        column_number=0,
                        node_type="ParseError",
                        description=f"Failed to parse code: {str(e)}",
                        code_snippet="",
                        suggestion="Ensure code is valid Python"
                    )
                ]
            )
    
    def set_security_level(self, level: SecurityLevel):
        """Update security level"""
        self.config = SecurityConfig(level)

# Example usage and testing
if __name__ == "__main__":
    # Test the AST validator
    validator = ASTValidator(SecurityLevel.MODERATE)
    
    # Test cases
    test_codes = [
        # Safe code
        """
def calculate_sum(a, b):
    return a + b

result = calculate_sum(5, 3)
print(f"Result: {result}")
        """,
        
        # Dangerous code
        """
import os
import subprocess

def dangerous_function():
    os.system("rm -rf /")
    eval("print('hello')")
    exec("import sys")
    
dangerous_function()
        """,
        
        # Obfuscated code
        """
_ = lambda __: __.join(chr(ord(_) - 1) for _ in 'jnqpsu!pt')
__(__)
        """,
        
        # Complex code
        """
def complex_function(x):
    if x > 0:
        if x > 10:
            if x > 100:
                if x > 1000:
                    if x > 10000:
                        return "very large"
                    return "large"
                return "medium"
            return "small"
        return "tiny"
    return "negative"
        """
    ]
    
    for i, code in enumerate(test_codes, 1):
        print(f"\n=== Test Case {i} ===")
        result = validator.validate_code(code)
        print(f"Valid: {result.is_valid}")
        print(f"Violations: {len(result.violations)}")
        for violation in result.violations:
            print(f"  - {violation.severity.upper()}: {violation.description}")
        print(f"Complexity: {result.complexity_metrics.cyclomatic_complexity}")

