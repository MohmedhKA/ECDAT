"""
ECDAT AST Taint & Dataflow Persistence Tracer:
Analyzes Python source code to track cryptographic variables from creation/encryption
to terminal persistence sinks (DB, Disk, S3, Memory), inferring the 4-tier data lifespan X.
"""

import ast
import re
from typing import List, Dict, Optional, Set
from pydantic import BaseModel, Field
from ecdat.models import XTier
from ecdat.x_inference.sink_stubs import match_sink_pattern

CRYPTO_GENERATION_KEYWORDS = {
    "encrypt", "cipher", "generate_private_key", "generate_key",
    "sign", "digest", "hmac", "token", "seal", "derive", "key_exchange"
}

class XInferenceResult(BaseModel):
    target_variable: str = Field(..., description="Name of the cryptographic variable tracked")
    tier: XTier = Field(..., description="Inferred 4-tier data lifespan X")
    confidence: str = Field("LOW", description="HIGH, MEDIUM, or LOW")
    evidence: str = Field(..., description="Technical rationale and matched sink")
    review_required: bool = Field(False, description="Whether human audit review is recommended")
    sink_call: Optional[str] = Field(None, description="The matched persistence sink syntax")
    line_number: int = Field(0, description="Line number of the cryptographic invocation")

class CryptoTaintVisitor(ast.NodeVisitor):
    def __init__(self, source_code: str):
        self.source_lines = source_code.splitlines()
        self.crypto_vars: Dict[str, int] = {}  # var_name -> line_number
        self.results: List[XInferenceResult] = []
        self.analyzed_vars: Set[str] = set()

    def _get_call_name(self, node: ast.AST) -> str:
        """Helper to reconstruct a string representation of an AST call node."""
        if isinstance(node, ast.Name):
            return node.id
        elif isinstance(node, ast.Attribute):
            return f"{self._get_call_name(node.value)}.{node.attr}"
        elif isinstance(node, ast.Call):
            return self._get_call_name(node.func)
        return ""

    def visit_Assign(self, node: ast.Assign):
        # Detect: var = crypto_function(...)
        if isinstance(node.value, ast.Call):
            func_name = self._get_call_name(node.value.func).lower()
            # Tokenize to avoid matching non-crypto substrings like 'signal' or 'design'
            tokens = set(re.split(r"[._\s]+", func_name))
            if any(kw in tokens or kw in func_name.split(".") for kw in CRYPTO_GENERATION_KEYWORDS):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        self.crypto_vars[var_name] = node.lineno

        self.generic_visit(node)

    def visit_Delete(self, node: ast.Delete):
        # Detect: del crypto_var (explicit memory destruction)
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in self.crypto_vars:
                var = target.id
                if var not in self.analyzed_vars:
                    self.results.append(XInferenceResult(
                        target_variable=var,
                        tier=XTier.EPHEMERAL,
                        confidence="HIGH",
                        evidence=f"Explicit variable destruction ('del {var}') at line {node.lineno}.",
                        review_required=False,
                        sink_call=f"del {var}",
                        line_number=self.crypto_vars[var],
                    ))
                    self.analyzed_vars.add(var)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        call_str = self._get_call_name(node.func)

        # Check if any tracked crypto variable is an argument to this call
        passed_crypto_vars = []
        for arg in node.args:
            if isinstance(arg, ast.Name) and arg.id in self.crypto_vars:
                passed_crypto_vars.append(arg.id)
        for kw in node.keywords:
            if isinstance(kw.value, ast.Name) and kw.value.id in self.crypto_vars:
                passed_crypto_vars.append(kw.value.id)

        for var in passed_crypto_vars:
            if var in self.analyzed_vars:
                continue

            # Check if this call matches our pre-annotated persistence sink database
            matched = match_sink_pattern(call_str)
            if matched:
                tier, conf, desc = matched
                self.results.append(XInferenceResult(
                    target_variable=var,
                    tier=tier,
                    confidence=conf,
                    evidence=f"{desc} (Matched sink: '{call_str}' at line {node.lineno}).",
                    review_required=False,
                    sink_call=call_str,
                    line_number=self.crypto_vars[var],
                ))
                self.analyzed_vars.add(var)
            else:
                # Inter-procedural boundary: variable passed into an unanalyzed external function
                # Graceful degradation: flag as HUMAN_REVIEW instead of guessing
                self.results.append(XInferenceResult(
                    target_variable=var,
                    tier=XTier.HUMAN_REVIEW,
                    confidence="LOW",
                    evidence=(
                        f"Taint escaped across module boundary into unanalyzed function '{call_str}' at line {node.lineno}. "
                        "Static persistence sink could not be verified automatically."
                    ),
                    review_required=True,
                    sink_call=call_str,
                    line_number=self.crypto_vars[var],
                ))
                self.analyzed_vars.add(var)

        self.generic_visit(node)

def analyze_python_source(source_code: str, file_path: str = "<memory>") -> List[XInferenceResult]:
    """
    Parses Python source code, performs AST dataflow tracing, and classifies
    all detected cryptographic variables into the 4 persistence tiers.
    """
    try:
        tree = ast.parse(source_code, filename=file_path)
    except SyntaxError as e:
        return [
            XInferenceResult(
                target_variable="syntax_error",
                tier=XTier.HUMAN_REVIEW,
                confidence="LOW",
                evidence=f"SyntaxError parsing {file_path}: {e}",
                review_required=True,
                line_number=getattr(e, "lineno", 0),
            )
        ]

    visitor = CryptoTaintVisitor(source_code)
    visitor.visit(tree)

    # For any crypto variables that never reached any sink call at all:
    # They remained exclusively in local volatile registers/memory
    for var, lineno in visitor.crypto_vars.items():
        if var not in visitor.analyzed_vars:
            visitor.results.append(XInferenceResult(
                target_variable=var,
                tier=XTier.EPHEMERAL,
                confidence="MEDIUM",
                evidence=(
                    f"Variable '{var}' created at line {lineno} does not flow into any persistence sink; "
                    "retained exclusively in volatile memory scope."
                ),
                review_required=False,
                sink_call=None,
                line_number=lineno,
            ))
            visitor.analyzed_vars.add(var)

    return visitor.results

def analyze_python_file(file_path: str) -> List[XInferenceResult]:
    """Reads a Python file from disk and performs AST taint persistence analysis."""
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    return analyze_python_source(content, file_path=file_path)
