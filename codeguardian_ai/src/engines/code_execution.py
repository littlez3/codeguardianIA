"""
CodeGuardian AI - Code Execution Engine
Secure sandbox for code execution with resource limits and structured logging
"""

import os
import sys
import json
import time
import uuid
import tempfile
import subprocess
import threading
import resource
import signal
from datetime import datetime
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, asdict
from pathlib import Path

@dataclass
class ExecutionResult:
    """Structured result from code execution"""
    execution_id: str
    language: str
    code: str
    stdout: str
    stderr: str
    exit_code: int
    execution_time: float
    memory_used: int
    success: bool
    error_message: Optional[str] = None
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)

@dataclass
class ExecutionLimits:
    """Resource limits for code execution"""
    timeout_seconds: int = 10
    max_memory_mb: int = 128
    max_disk_mb: int = 50
    max_output_size: int = 10000  # characters
    allowed_imports: Optional[List[str]] = None

class SecurityValidator:
    """Validates code for security issues before execution"""
    
    DANGEROUS_PATTERNS = [
        'import os',
        'import sys', 
        'import subprocess',
        'import socket',
        'import urllib',
        'import requests',
        'import http',
        'open(',
        'file(',
        'exec(',
        'eval(',
        '__import__',
        'compile(',
        'globals(',
        'locals(',
        'vars(',
        'dir(',
        'getattr(',
        'setattr(',
        'delattr(',
        'hasattr(',
    ]
    
    ALLOWED_IMPORTS = [
        'math', 'random', 'datetime', 'json', 'collections',
        'itertools', 'functools', 'operator', 're', 'string',
        'decimal', 'fractions', 'statistics', 'hashlib',
        'base64', 'binascii', 'struct', 'codecs'
    ]
    
    @classmethod
    def validate_python_code(cls, code: str) -> tuple[bool, str]:
        """Validate Python code for security issues"""
        code_lower = code.lower()
        
        # Check for dangerous patterns
        for pattern in cls.DANGEROUS_PATTERNS:
            if pattern in code_lower:
                return False, f"Dangerous pattern detected: {pattern}"
        
        # Check for file operations
        if any(op in code_lower for op in ['open(', 'file(', 'with open']):
            return False, "File operations not allowed"
        
        # Check for network operations
        if any(net in code_lower for net in ['socket', 'urllib', 'requests', 'http']):
            return False, "Network operations not allowed"
        
        # Check for system operations
        if any(sys_op in code_lower for sys_op in ['os.', 'sys.', 'subprocess']):
            return False, "System operations not allowed"
        
        return True, "Code validation passed"

class CodeSandbox:
    """Secure sandbox for code execution"""
    
    def __init__(self, limits: ExecutionLimits = None):
        self.limits = limits or ExecutionLimits()
        self.temp_dir = tempfile.mkdtemp(prefix="codeguardian_")
        
    def __del__(self):
        """Cleanup temporary directory"""
        try:
            import shutil
            shutil.rmtree(self.temp_dir, ignore_errors=True)
        except:
            pass
    
    def _set_resource_limits(self):
        """Set resource limits for the execution process"""
        # Memory limit
        memory_limit = self.limits.max_memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (memory_limit, memory_limit))
        
        # CPU time limit
        resource.setrlimit(resource.RLIMIT_CPU, (self.limits.timeout_seconds, self.limits.timeout_seconds))
        
        # File size limit
        file_limit = self.limits.max_disk_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (file_limit, file_limit))
        
        # Number of processes limit
        resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
    
    def execute_python(self, code: str) -> ExecutionResult:
        """Execute Python code in sandbox"""
        execution_id = str(uuid.uuid4())
        
        # Validate code security
        is_safe, validation_message = SecurityValidator.validate_python_code(code)
        if not is_safe:
            return ExecutionResult(
                execution_id=execution_id,
                language="python",
                code=code,
                stdout="",
                stderr="",
                exit_code=-1,
                execution_time=0.0,
                memory_used=0,
                success=False,
                error_message=f"Security validation failed: {validation_message}"
            )
        
        # Create temporary file for code
        code_file = os.path.join(self.temp_dir, f"{execution_id}.py")
        
        try:
            with open(code_file, 'w') as f:
                f.write(code)
            
            start_time = time.time()
            
            # Execute code with resource limits
            process = subprocess.Popen(
                [sys.executable, code_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                cwd=self.temp_dir,
                preexec_fn=self._set_resource_limits
            )
            
            try:
                stdout, stderr = process.communicate(timeout=self.limits.timeout_seconds)
                exit_code = process.returncode
                execution_time = time.time() - start_time
                
                # Truncate output if too long
                if len(stdout) > self.limits.max_output_size:
                    stdout = stdout[:self.limits.max_output_size] + "\n... (output truncated)"
                
                if len(stderr) > self.limits.max_output_size:
                    stderr = stderr[:self.limits.max_output_size] + "\n... (error output truncated)"
                
                success = exit_code == 0 and not stderr.strip()
                error_message = stderr.strip() if stderr.strip() else None
                
                return ExecutionResult(
                    execution_id=execution_id,
                    language="python",
                    code=code,
                    stdout=stdout,
                    stderr=stderr,
                    exit_code=exit_code,
                    execution_time=execution_time,
                    memory_used=0,  # TODO: Implement memory tracking
                    success=success,
                    error_message=error_message
                )
                
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
                return ExecutionResult(
                    execution_id=execution_id,
                    language="python",
                    code=code,
                    stdout="",
                    stderr="",
                    exit_code=-1,
                    execution_time=self.limits.timeout_seconds,
                    memory_used=0,
                    success=False,
                    error_message=f"Execution timeout after {self.limits.timeout_seconds} seconds"
                )
                
        except Exception as e:
            return ExecutionResult(
                execution_id=execution_id,
                language="python",
                code=code,
                stdout="",
                stderr="",
                exit_code=-1,
                execution_time=0.0,
                memory_used=0,
                success=False,
                error_message=f"Execution error: {str(e)}"
            )
        
        finally:
            # Cleanup
            try:
                os.remove(code_file)
            except:
                pass

class ExecutionLogger:
    """Structured logging for code executions"""
    
    def __init__(self, log_file: str = None):
        self.log_file = log_file or os.path.join(os.getcwd(), "execution_logs.jsonl")
        
    def log_execution(self, result: ExecutionResult):
        """Log execution result to structured log file"""
        log_entry = {
            "timestamp": datetime.utcnow().isoformat(),
            "execution_id": result.execution_id,
            "language": result.language,
            "success": result.success,
            "execution_time": result.execution_time,
            "exit_code": result.exit_code,
            "error_message": result.error_message,
            "code_length": len(result.code),
            "stdout_length": len(result.stdout),
            "stderr_length": len(result.stderr)
        }
        
        try:
            with open(self.log_file, 'a') as f:
                f.write(json.dumps(log_entry) + '\n')
        except Exception as e:
            print(f"Failed to log execution: {e}")

class CodeExecutionEngine:
    """Main engine for secure code execution"""
    
    def __init__(self, limits: ExecutionLimits = None, log_file: str = None):
        self.limits = limits or ExecutionLimits()
        self.logger = ExecutionLogger(log_file)
        
    def execute(self, code: str, language: str = "python") -> ExecutionResult:
        """Execute code in specified language"""
        if language.lower() != "python":
            return ExecutionResult(
                execution_id=str(uuid.uuid4()),
                language=language,
                code=code,
                stdout="",
                stderr="",
                exit_code=-1,
                execution_time=0.0,
                memory_used=0,
                success=False,
                error_message=f"Language '{language}' not supported yet"
            )
        
        sandbox = CodeSandbox(self.limits)
        result = sandbox.execute_python(code)
        
        # Log the execution
        self.logger.log_execution(result)
        
        return result

# Example usage and testing
if __name__ == "__main__":
    # Test the execution engine
    engine = CodeExecutionEngine()
    
    # Test successful execution
    test_code = """
print("Hello, CodeGuardian!")
result = 2 + 2
print(f"2 + 2 = {result}")
"""
    
    result = engine.execute(test_code)
    print("=== Test Execution Result ===")
    print(json.dumps(result.to_dict(), indent=2))
    
    # Test security validation
    dangerous_code = """
import os
os.system("ls -la")
"""
    
    result = engine.execute(dangerous_code)
    print("\n=== Security Test Result ===")
    print(json.dumps(result.to_dict(), indent=2))

