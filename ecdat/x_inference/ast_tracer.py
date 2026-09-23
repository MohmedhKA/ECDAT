"""
ECDAT AST Taint & Dataflow Persistence Tracer:
Analyzes Python source code to track cryptographic variables from creation/encryption
to terminal persistence sinks (DB, Disk, S3, Memory), inferring the 4-tier data lifespan X
and the DSIS 4-class functional security intent.
"""

import ast
from typing import List, Dict, Optional, Set, Any
from pydantic import BaseModel, Field
from ecdat.models import XTier, IntentClass, EvidenceLevel, AgilityLevel
from ecdat.x_inference.sink_stubs import match_sink_pattern
from ecdat.intent import classify_intent
from ecdat.agility.cams_detector import detect_cams_agility

# AST Method Call Names indicating cryptographic generation
CRYPTO_GENERATION_KEYWORDS = {
    "encrypt", "cipher", "generate_private_key", "generate_key",
    "generatekeypair", "generate_key_pair", "derivekey", "derive_key",
    "sign", "digest", "hexdigest", "hmac", "token", "token_bytes",
    "urandom", "seal", "derive", "key_exchange", "ecdh", "kem",
    "sha256", "sha384", "sha512", "sha1", "md5", "hashlib", "new"
}

class XInferenceResult(BaseModel):
    target_variable: str = Field(..., description="Name of the cryptographic variable tracked")
    tier: XTier = Field(..., description="Inferred 4-tier data lifespan X")
    confidence: str = Field("LOW", description="HIGH, MEDIUM, or LOW")
    evidence: str = Field(..., description="Technical rationale and matched sink")
    review_required: bool = Field(False, description="Whether human audit review is recommended")
    sink_call: Optional[str] = Field(None, description="The matched persistence sink syntax")
    line_number: int = Field(0, description="Line number of the cryptographic invocation")

    # Master Plan Phase 1 & 2 Extensions: Dual-Sink Semantic Intent, Evidence State & CAMS
    intent_class: IntentClass = Field(IntentClass.CONFIDENTIALITY_ENVELOPE, description="Functional security intent")
    intent_evidence: str = Field("", description="Intent classification rationale")
    evidence_level: EvidenceLevel = Field(EvidenceLevel.E1_STATIC_ARTIFACT, description="E0-E5 evidence state")
    agility_level: AgilityLevel = Field(AgilityLevel.RIGID, description="CAMS agility level (0-3)")
    cams_evidence: str = Field("", description="CAMS agility rationale")

class CryptoTaintVisitor(ast.NodeVisitor):
    def __init__(self, source_code: str):
        self.source_lines = source_code.splitlines()
        self.crypto_vars: Dict[str, int] = {}  # var_name -> line_number
        self.crypto_nodes: Dict[str, Any] = {}  # var_name -> AST node
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

    def _get_context_lines(self, line_no: int, radius: int = 5) -> str:
        start = max(0, line_no - radius - 1)
        end = min(len(self.source_lines), line_no + radius)
        return "\n".join(self.source_lines[start:end])

    def visit_Assign(self, node: ast.Assign):
        # Detect: var = crypto_function(...)
        if isinstance(node.value, ast.Call):
            func_name = self._get_call_name(node.value.func).lower()
            # Tokenize to avoid matching non-crypto substrings like 'signal' or 'design'
            tokens = set(func_name.replace(".", " ").replace("_", " ").split())
            if any(kw in tokens or kw in func_name.split(".") for kw in CRYPTO_GENERATION_KEYWORDS):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        var_name = target.id
                        self.crypto_vars[var_name] = node.lineno
                        self.crypto_nodes[var_name] = node.value

        self.generic_visit(node)

    def visit_Delete(self, node: ast.Delete):
        # Detect: del crypto_var (explicit memory destruction)
        for target in node.targets:
            if isinstance(target, ast.Name) and target.id in self.crypto_vars:
                var = target.id
                if var not in self.analyzed_vars:
                    context_str = self._get_context_lines(node.lineno)
                    intent, intent_desc = classify_intent(var_name=var, sink_call=f"del {var}", context_lines=context_str)
                    var_lineno = self.crypto_vars[var]
                    line_src = self.source_lines[var_lineno - 1] if 0 < var_lineno <= len(self.source_lines) else ""
                    cams_level, cams_desc = detect_cams_agility(
                        source_line=line_src,
                        surrounding_code=context_str,
                        ast_node=self.crypto_nodes.get(var)
                    )
                    self.results.append(XInferenceResult(
                        target_variable=var,
                        tier=XTier.EPHEMERAL,
                        confidence="HIGH",
                        evidence=f"Explicit variable destruction ('del {var}') at line {node.lineno}.",
                        review_required=False,
                        sink_call=f"del {var}",
                        line_number=var_lineno,
                        intent_class=intent,
                        intent_evidence=intent_desc,
                        evidence_level=EvidenceLevel.E2_REACHABLE_PATH,
                        agility_level=cams_level,
                        cams_evidence=cams_desc,
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

            context_str = self._get_context_lines(node.lineno)
            intent, intent_desc = classify_intent(var_name=var, sink_call=call_str, context_lines=context_str)
            var_lineno = self.crypto_vars[var]
            line_src = self.source_lines[var_lineno - 1] if 0 < var_lineno <= len(self.source_lines) else ""
            cams_level, cams_desc = detect_cams_agility(
                source_line=line_src,
                surrounding_code=context_str,
                ast_node=self.crypto_nodes.get(var)
            )

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
                    line_number=var_lineno,
                    intent_class=intent,
                    intent_evidence=intent_desc,
                    evidence_level=EvidenceLevel.E2_REACHABLE_PATH,
                    agility_level=cams_level,
                    cams_evidence=cams_desc,
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
                    line_number=var_lineno,
                    intent_class=intent,
                    intent_evidence=intent_desc,
                    evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                    agility_level=cams_level,
                    cams_evidence=cams_desc,
                ))
                self.analyzed_vars.add(var)

        self.generic_visit(node)

def analyze_python_source(source_code: str, file_path: str = "<memory>") -> List[XInferenceResult]:
    """
    Parses Python source code, performs AST dataflow tracing, and classifies
    all detected cryptographic variables into the 4 persistence tiers and intent classes.
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
                intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
                intent_evidence="Syntax error prevented AST intent analysis.",
                evidence_level=EvidenceLevel.E0_UNCONFIRMED,
            )
        ]

    visitor = CryptoTaintVisitor(source_code)
    visitor.visit(tree)

    # For any crypto variables that never reached any sink call at all:
    # They remained exclusively in local volatile registers/memory
    for var, lineno in visitor.crypto_vars.items():
        if var not in visitor.analyzed_vars:
            context_str = visitor._get_context_lines(lineno)
            intent, intent_desc = classify_intent(var_name=var, sink_call=None, context_lines=context_str)
            line_src = visitor.source_lines[lineno - 1] if 0 < lineno <= len(visitor.source_lines) else ""
            cams_level, cams_desc = detect_cams_agility(
                source_line=line_src,
                surrounding_code=context_str,
                ast_node=visitor.crypto_nodes.get(var)
            )
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
                intent_class=intent,
                intent_evidence=intent_desc,
                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                agility_level=cams_level,
                cams_evidence=cams_desc,
            ))
            visitor.analyzed_vars.add(var)

    return visitor.results

def analyze_python_file(file_path: str) -> List[XInferenceResult]:
    """Reads a Python file from disk and performs AST taint persistence and intent analysis."""
    with open(file_path, "r", encoding="utf-8") as f:
        content = f.read()
    return analyze_python_source(content, file_path=file_path)
