"""
ECDAT Cryptographic Agility & Buffer Hazard Auditor:
Statically audits source code for fixed-size byte buffer allocations adjacent to crypto operations
that would cause silent buffer overflows, memory corruption, or serialization crashes when
upgrading to larger Post-Quantum primitives (e.g. ML-DSA-65's 3,309-byte signatures).
"""

import ast
from typing import List, Optional
from pydantic import BaseModel, Field

CRYPTO_BUFFER_KEYWORDS = {"sig", "signature", "key", "buf", "buffer", "ciphertext", "cipher", "secret", "digest", "token", "mac", "cert", "hash"}

class BufferHazard(BaseModel):
    variable_name: str = Field(..., description="Name of the fixed buffer variable")
    allocated_bytes: int = Field(..., description="Currently allocated size in bytes")
    required_bytes_pqc: int = Field(..., description="Size required by target PQC primitive")
    line_number: int = Field(0, description="Line number of buffer allocation")
    file_path: str = Field("source", description="File path where hazard was detected")
    severity: str = Field("CRITICAL", description="CRITICAL, HIGH, or MEDIUM")
    message: str = Field(..., description="Actionable warning message")

class BufferAllocationVisitor(ast.NodeVisitor):
    def __init__(self, target_pqc_bytes: int = 3309, file_path: str = "source"):
        self.target_pqc_bytes = target_pqc_bytes
        self.file_path = file_path
        self.hazards: List[BufferHazard] = []

    def _extract_constant_int(self, node: ast.AST) -> Optional[int]:
        """Extracts integer value from Constant or Num node."""
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        return None

    def visit_Assign(self, node: ast.Assign):
        # 1. Detect: buf = bytearray(64) or buf = bytes(64)
        if isinstance(node.value, ast.Call):
            if isinstance(node.value.func, ast.Name) and node.value.func.id in ("bytearray", "bytes"):
                if node.value.args:
                    size = self._extract_constant_int(node.value.args[0])
                    if size is not None and size < self.target_pqc_bytes:
                        for target in node.targets:
                            if isinstance(target, ast.Name):
                                name_lower = target.id.lower()
                                if any(kw in name_lower for kw in CRYPTO_BUFFER_KEYWORDS):
                                    self._flag_hazard(target.id, size, node.lineno)

        # 2. Detect: buf = b"\x00" * 64 or [0] * 64
        elif isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.Mult):
            size = None
            is_buffer_pattern = False

            # Check: Left is b"..." or [...] and Right is int
            if isinstance(node.value.left, ast.Constant) and isinstance(node.value.left.value, (bytes, bytearray)):
                is_buffer_pattern = True
                size = self._extract_constant_int(node.value.right)
            elif isinstance(node.value.right, ast.Constant) and isinstance(node.value.right.value, (bytes, bytearray)):
                is_buffer_pattern = True
                size = self._extract_constant_int(node.value.left)
            elif isinstance(node.value.left, ast.List):
                is_buffer_pattern = True
                size = self._extract_constant_int(node.value.right)

            if is_buffer_pattern and size is not None and size < self.target_pqc_bytes:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        name_lower = target.id.lower()
                        # Strictly require cryptographic buffer naming to avoid false positives on math/plotting arrays
                        if any(kw in name_lower for kw in CRYPTO_BUFFER_KEYWORDS):
                            self._flag_hazard(target.id, size, node.lineno)

        self.generic_visit(node)

    def _flag_hazard(self, var_name: str, allocated: int, lineno: int):
        severity = "CRITICAL" if allocated <= 256 else "HIGH"
        msg = (
            f"FIXED BUFFER HAZARD: Variable '{var_name}' at line {lineno} allocates a static buffer "
            f"of {allocated} bytes. Target PQC primitive (e.g. ML-DSA-65) requires {self.target_pqc_bytes} bytes. "
            f"Swapping algorithm without expanding buffer causes memory overflow or serialization failure."
        )
        self.hazards.append(BufferHazard(
            variable_name=var_name,
            allocated_bytes=allocated,
            required_bytes_pqc=self.target_pqc_bytes,
            line_number=lineno,
            file_path=self.file_path,
            severity=severity,
            message=msg,
        ))

def audit_python_buffer_allocations(source_code: str, target_pqc_bytes: int = 3309, file_path: str = "source") -> List[BufferHazard]:
    """Parses Python source code and audits for static buffer allocation hazards."""
    try:
        tree = ast.parse(source_code)
    except SyntaxError:
        return []

    visitor = BufferAllocationVisitor(target_pqc_bytes=target_pqc_bytes, file_path=file_path)
    visitor.visit(tree)
    return visitor.hazards

def audit_python_buffer_file(file_path: str, target_pqc_bytes: int = 3309) -> List[BufferHazard]:
    """Reads a Python file from disk and audits for fixed-size buffer hazards."""
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    return audit_python_buffer_allocations(content, target_pqc_bytes=target_pqc_bytes, file_path=file_path)
