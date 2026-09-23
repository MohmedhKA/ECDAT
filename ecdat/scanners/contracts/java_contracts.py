"""
ECDAT Java Cryptographic Contract Engine (100% Pure AST via ljavalang):
Statically discovers Java cryptographic primitives across standard JCA/JCE Service Provider
Interfaces (CipherSpi, MessageDigestSpi, SignatureSpi, MacSpi, KeyAgreementSpi, KeyGenerator,
KeyPairGenerator, SSLContextSpi) and cryptographic specifications (SecretKeySpec, PBEKeySpec,
PBEParameterSpec, IvParameterSpec, SecureRandom, X509TrustManager, HostnameVerifier).

Implemented with strictly ZERO REGEX pattern matching. All discoveries, backward scope tracing,
argument resolution, reaching definitions, and dead-code pruning are executed via concrete AST node traversal.
"""

from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set, Any
from collections import defaultdict

import javalang
from javalang.tree import (
    CompilationUnit,
    ClassDeclaration,
    InterfaceDeclaration,
    MethodDeclaration,
    ConstructorDeclaration,
    FieldDeclaration,
    LocalVariableDeclaration,
    VariableDeclarator,
    MethodInvocation,
    ClassCreator,
    ArrayCreator,
    ArrayInitializer,
    Literal,
    MemberReference,
    Assignment,
    IfStatement,
    BinaryOperation,
    ReturnStatement,
    StatementExpression,
    Cast,
    ThrowStatement,
)

from ecdat.models import (
    CryptoAsset,
    PrimitiveType,
    XTier,
    EvidenceLevel,
    IntentClass,
    AgilityLevel,
)
from ecdat.rules.signature_db import get_signature_db
from ecdat.scanners.contracts.base import BaseContractEngine

# Known JCA SPI interfaces and contracts
JCA_SPI_CLASSES = {
    "Cipher": {"contract": "CipherSpi", "prim": PrimitiveType.ENCRYPTION},
    "javax.crypto.Cipher": {"contract": "CipherSpi", "prim": PrimitiveType.ENCRYPTION},
    "MessageDigest": {"contract": "MessageDigestSpi", "prim": PrimitiveType.HASH},
    "java.security.MessageDigest": {"contract": "MessageDigestSpi", "prim": PrimitiveType.HASH},
    "Signature": {"contract": "SignatureSpi", "prim": PrimitiveType.SIGNATURE},
    "java.security.Signature": {"contract": "SignatureSpi", "prim": PrimitiveType.SIGNATURE},
    "Mac": {"contract": "MacSpi", "prim": PrimitiveType.HASH},
    "javax.crypto.Mac": {"contract": "MacSpi", "prim": PrimitiveType.HASH},
    "KeyAgreement": {"contract": "KeyAgreementSpi", "prim": PrimitiveType.KEY_EXCHANGE},
    "javax.crypto.KeyAgreement": {"contract": "KeyAgreementSpi", "prim": PrimitiveType.KEY_EXCHANGE},
    "KeyGenerator": {"contract": "KeyGenerator", "prim": PrimitiveType.KEY_EXCHANGE},
    "javax.crypto.KeyGenerator": {"contract": "KeyGenerator", "prim": PrimitiveType.KEY_EXCHANGE},
    "java.security.KeyGenerator": {"contract": "KeyGenerator", "prim": PrimitiveType.KEY_EXCHANGE},
    "KeyPairGenerator": {"contract": "KeyPairGenerator", "prim": PrimitiveType.SIGNATURE},
    "java.security.KeyPairGenerator": {"contract": "KeyPairGenerator", "prim": PrimitiveType.SIGNATURE},
    "SSLContext": {"contract": "SSLContextSpi", "prim": PrimitiveType.KEY_EXCHANGE},
    "javax.net.ssl.SSLContext": {"contract": "SSLContextSpi", "prim": PrimitiveType.KEY_EXCHANGE},
}

DYNAMIC_STRING_METHODS = {
    "replace", "replaceAll", "replaceFirst", "substring",
    "toLowerCase", "toUpperCase", "concat", "trim", "format",
}


class JavaAstHelper:
    """Utility class for pure AST-level type, expression, and cross-file resolution."""

    @staticmethod
    def get_full_type_name(ref_type: Any) -> str:
        if not ref_type or not hasattr(ref_type, "name"):
            return ""
        parts = [ref_type.name]
        cur = ref_type
        while getattr(cur, "sub_type", None):
            cur = cur.sub_type
            parts.append(cur.name)
        return ".".join(parts)

    @staticmethod
    def resolve_ast_expression(
        expr: Any,
        local_scope: Dict[str, Any],
        class_fields: Dict[str, Any],
        tree: Optional[CompilationUnit] = None,
        current_file: Optional[Path] = None,
        maps: Optional[Dict[str, Dict[str, Any]]] = None,
        visited: Optional[Set[str]] = None,
        depth: int = 0,
    ) -> Optional[str]:
        """
        Recursively resolves an AST expression node into a constant string or integer value.
        Detects dynamic PRNG invocations and returns \x27DYNAMIC_RANDOM\x27.
        """
        if expr is None or depth > 10:
            return None

        if visited is None:
            visited = set()
        if maps is None:
            maps = {}

        # 1. Literal values
        if isinstance(expr, Literal):
            val = str(expr.value)
            if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                return val[1:-1]
            return val

        # 2. Variable / Member reference
        if isinstance(expr, MemberReference):
            name = expr.member
            if name in visited:
                return None
            visited.add(name)

            if name in local_scope and local_scope[name] is not None:
                return JavaAstHelper.resolve_ast_expression(
                    local_scope[name], local_scope, class_fields, tree, current_file, maps, visited, depth + 1
                )
            if name in class_fields and class_fields[name] is not None:
                return JavaAstHelper.resolve_ast_expression(
                    class_fields[name], local_scope, class_fields, tree, current_file, maps, visited, depth + 1
                )

            # Check class-level field assignments in tree
            if tree:
                for _, assign in tree.filter(Assignment):
                    if isinstance(assign.expressionl, MemberReference) and assign.expressionl.member == name:
                        res = JavaAstHelper.resolve_ast_expression(
                            assign.value, local_scope, class_fields, tree, current_file, maps, visited, depth + 1
                        )
                        if res:
                            return res
            return None

        # 3. Method Invocations
        if isinstance(expr, MethodInvocation):
            member = expr.member

            if member in DYNAMIC_STRING_METHODS:
                return f"DYNAMIC_UNRESOLVED:{member}"

            if member in ("valueOf", "toString", "parseInt", "parseLong") and expr.arguments:
                return JavaAstHelper.resolve_ast_expression(
                    expr.arguments[0], local_scope, class_fields, tree, current_file, maps, visited, depth + 1
                )

            if member in ("toString", "toCharArray", "getBytes") and expr.qualifier:
                if isinstance(expr.qualifier, str):
                    return JavaAstHelper.resolve_ast_expression(
                        MemberReference(member=expr.qualifier), local_scope, class_fields, tree, current_file, maps, visited, depth + 1
                    )
                return JavaAstHelper.resolve_ast_expression(
                    expr.qualifier, local_scope, class_fields, tree, current_file, maps, visited, depth + 1
                )

            if member == "get" and expr.arguments and expr.qualifier and expr.qualifier in maps:
                k = JavaAstHelper.resolve_ast_expression(
                    expr.arguments[0], local_scope, class_fields, tree, current_file, maps, visited, depth + 1
                )
                if k and k in maps[expr.qualifier]:
                    return str(maps[expr.qualifier][k])

            if member in ("ints", "nextBytes", "generateSeed", "nextInt", "nextLong"):
                return "DYNAMIC_RANDOM"

            return None

        # 4. Cast expression
        if isinstance(expr, Cast):
            return JavaAstHelper.resolve_ast_expression(
                expr.expression, local_scope, class_fields, tree, current_file, maps, visited, depth + 1
            )

        # 5. Class Creator
        if isinstance(expr, ClassCreator):
            t_name = getattr(expr.type, "name", "")
            if t_name in ("String", "java.lang.String", "Integer", "java.lang.Integer") and expr.arguments:
                return JavaAstHelper.resolve_ast_expression(
                    expr.arguments[0], local_scope, class_fields, tree, current_file, maps, visited, depth + 1
                )

        return None

    @staticmethod
    def resolve_param_recursive(
        target_class_name: str,
        method_name: str,
        param_idx: int,
        start_file: Path,
        ast_cache: Dict[Path, CompilationUnit],
        call_depth: int = 0,
    ) -> Optional[str]:
        """
        Recursively resolves method parameters by searching callers within the compilation unit
        and across sibling Java files in the same directory/package.
        """
        if call_depth > 5:
            return None

        files_to_check = [start_file] + list(start_file.parent.glob("*.java"))
        for sf in files_to_check:
            st = ast_cache.get(sf)
            if not st:
                continue

            is_same_file = (sf == start_file)

            sf_locals: Dict[str, Any] = {}
            for _, ldecl in st.filter(LocalVariableDeclaration):
                for d in ldecl.declarators:
                    sf_locals[d.name] = d.initializer

            vars_of_target: Set[str] = set()
            for _, ldecl in st.filter(LocalVariableDeclaration):
                if getattr(ldecl.type, "name", "") == target_class_name:
                    for d in ldecl.declarators:
                        vars_of_target.add(d.name)

            for path, inv in st.filter(MethodInvocation):
                if inv.member == method_name and inv.arguments and len(inv.arguments) > param_idx:
                    qual_ok = False
                    if is_same_file and (not inv.qualifier or inv.qualifier == "this" or inv.qualifier in vars_of_target):
                        qual_ok = True
                    elif not is_same_file and (inv.qualifier in vars_of_target or inv.qualifier == target_class_name):
                        qual_ok = True

                    if qual_ok:
                        arg_node = inv.arguments[param_idx]
                        enclosing_m = next((p for p in reversed(path) if isinstance(p, MethodDeclaration)), None)
                        if enclosing_m:
                            target_ref_name = None
                            if isinstance(arg_node, MemberReference):
                                target_ref_name = arg_node.member
                                init_val = sf_locals.get(target_ref_name)
                                if isinstance(init_val, MemberReference):
                                    target_ref_name = init_val.member

                            if target_ref_name:
                                for p2_idx, p2 in enumerate(enclosing_m.parameters):
                                    if p2.name == target_ref_name:
                                        c_type = getattr(st, "types", [None])[0]
                                        c_name = c_type.name if c_type else ""
                                        rec_val = JavaAstHelper.resolve_param_recursive(
                                            c_name, enclosing_m.name, p2_idx, sf, ast_cache, call_depth + 1
                                        )
                                        if rec_val:
                                            return rec_val

                        v = JavaAstHelper.resolve_ast_expression(arg_node, sf_locals, {}, st, sf)
                        if v:
                            return v
        return None

    @staticmethod
    def evaluate_static_condition(cond: Any, constants: Dict[str, int]) -> Optional[bool]:
        """Evaluates simple boolean or integer binary comparisons statically for dead-code pruning."""
        if cond is None:
            return None

        if isinstance(cond, Literal):
            if cond.value == "true":
                return True
            if cond.value == "false":
                return False

        if isinstance(cond, BinaryOperation):
            left_val = None
            if isinstance(cond.operandl, MemberReference) and cond.operandl.member in constants:
                left_val = constants[cond.operandl.member]
            elif isinstance(cond.operandl, Literal) and str(cond.operandl.value).isdigit():
                left_val = int(cond.operandl.value)

            right_val = None
            if isinstance(cond.operandr, MemberReference) and cond.operandr.member in constants:
                right_val = constants[cond.operandr.member]
            elif isinstance(cond.operandr, Literal) and str(cond.operandr.value).isdigit():
                right_val = int(cond.operandr.value)

            if left_val is not None and right_val is not None:
                op = cond.operator
                if op == ">": return left_val > right_val
                if op == "<": return left_val < right_val
                if op == "==": return left_val == right_val
                if op == "!=": return left_val != right_val
                if op == ">=": return left_val >= right_val
                if op == "<=": return left_val <= right_val

        return None


class JavaContractEngine(BaseContractEngine):
    """
    100% Pure AST Contract Engine for Java Cryptography Architecture (JCA/JCE).
    Zero regex pattern matching; uses ljavalang concrete syntax tree parser with
    interprocedural parameter resolution, reaching definitions, and randomization tracking.
    """

    def __init__(self):
        self.db = get_signature_db()
        self._ast_cache: Dict[Path, CompilationUnit] = {}

    def _get_or_parse(self, file_path: Path) -> Optional[CompilationUnit]:
        if file_path in self._ast_cache:
            return self._ast_cache[file_path]
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
            tree = javalang.parse.parse(content)
            self._ast_cache[file_path] = tree
            return tree
        except Exception:
            try:
                wrapped = f"public class __DummyWrapper {{\n{content}\n}}"
                tree = javalang.parse.parse(wrapped)
                self._ast_cache[file_path] = tree
                return tree
            except Exception:
                return None

    def _preload_directory(self, dir_path: Path):
        for p in dir_path.glob("*.java"):
            if p not in self._ast_cache:
                self._get_or_parse(p)

    def scan_file(self, file_path: Path, base_dir: Path) -> List[CryptoAsset]:
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        rel_path = str(file_path.relative_to(base_dir) if file_path.is_relative_to(base_dir) else file_path)
        stem = file_path.stem

        self._preload_directory(file_path.parent)
        tree = self._get_or_parse(file_path)
        if not tree:
            return []

        assets: List[CryptoAsset] = []
        c_decl = getattr(tree, "types", [None])[0]
        class_name = c_decl.name if c_decl else stem

        # 1. Collect fields and int constants
        class_fields: Dict[str, Any] = {}
        int_constants: Dict[str, int] = {}

        for _, fdecl in tree.filter(FieldDeclaration):
            for d in fdecl.declarators:
                class_fields[d.name] = d.initializer
                if d.initializer and isinstance(d.initializer, Literal) and str(d.initializer.value).isdigit():
                    int_constants[d.name] = int(d.initializer.value)

        # 2. Check constructor field assignments from parameters across classes in file
        for c in getattr(tree, "types", []):
            for ctor in getattr(c, "constructors", []):
                param_names = [p.name for p in ctor.parameters]
                for _, assign in ctor.filter(Assignment):
                    if isinstance(assign.expressionl, MemberReference) and isinstance(assign.value, MemberReference):
                        f_name = assign.expressionl.member
                        p_name = assign.value.member
                        if p_name in param_names:
                            p_idx = param_names.index(p_name)
                            files_to_check = [file_path] + list(file_path.parent.glob("*.java"))
                            for sf in files_to_check:
                                st = self._ast_cache.get(sf)
                                if not st:
                                    continue
                                for _, cc in st.filter(ClassCreator):
                                    if getattr(cc.type, "name", "") == c.name and cc.arguments and len(cc.arguments) > p_idx:
                                        sf_scope: Dict[str, Any] = {}
                                        for _, ld in st.filter(LocalVariableDeclaration):
                                            for d in ld.declarators:
                                                sf_scope[d.name] = d.initializer
                                        val = JavaAstHelper.resolve_ast_expression(cc.arguments[p_idx], sf_scope, class_fields, st, sf)
                                        if val:
                                            class_fields[f_name] = Literal(value=f'"{val}"')
                                            if val.isdigit():
                                                int_constants[f_name] = int(val)

        # 3. Traverse Methods
        for _, method in tree.filter(MethodDeclaration):
            local_scope: Dict[str, Any] = {}
            method_int_constants = dict(int_constants)
            randomized_vars: Set[str] = set()
            maps: Dict[str, Dict[str, Any]] = defaultdict(dict)

            for _, ldecl in method.filter(LocalVariableDeclaration):
                for d in ldecl.declarators:
                    local_scope[d.name] = d.initializer
                    if d.initializer and isinstance(d.initializer, Literal) and str(d.initializer.value).isdigit():
                        method_int_constants[d.name] = int(d.initializer.value)
                    if d.initializer and isinstance(d.initializer, MethodInvocation):
                        if d.initializer.member in ("nextLong", "nextInt", "nextBytes", "generateSeed", "ints"):
                            randomized_vars.add(d.name)

            # Track Map.put
            for _, inv in method.filter(MethodInvocation):
                if inv.member == "put" and len(inv.arguments) >= 2 and inv.qualifier:
                    k = JavaAstHelper.resolve_ast_expression(inv.arguments[0], local_scope, class_fields, tree, file_path, maps)
                    v = JavaAstHelper.resolve_ast_expression(inv.arguments[1], local_scope, class_fields, tree, file_path, maps)
                    if k is not None and v is not None:
                        maps[inv.qualifier][k] = v

            # Track assignments in method body
            for _, assign in method.filter(Assignment):
                if isinstance(assign.expressionl, MemberReference):
                    v_name = assign.expressionl.member
                    local_scope[v_name] = assign.value
                    val_resolved = JavaAstHelper.resolve_ast_expression(assign.value, local_scope, class_fields, tree, file_path, maps)
                    if val_resolved and val_resolved.isdigit():
                        method_int_constants[v_name] = int(val_resolved)
                    if val_resolved == "DYNAMIC_RANDOM":
                        randomized_vars.add(v_name)

            # Interprocedural caller parameter resolution
            if method.parameters:
                for p_idx, param in enumerate(method.parameters):
                    resolved_p = JavaAstHelper.resolve_param_recursive(class_name, method.name, p_idx, file_path, self._ast_cache)
                    if resolved_p:
                        local_scope[param.name] = Literal(value=f'"{resolved_p}"')
                        if resolved_p.isdigit():
                            method_int_constants[param.name] = int(resolved_p)
                        if resolved_p == "DYNAMIC_RANDOM":
                            randomized_vars.add(param.name)

            # Track direct PRNG invocations
            for _, inv in method.filter(MethodInvocation):
                if inv.member in ("nextBytes", "generateSeed") and inv.arguments:
                    arg = inv.arguments[0]
                    if isinstance(arg, MemberReference):
                        randomized_vars.add(arg.member)

            # Dead code & variable reaching definitions via static conditions
            dead_invocations: Set[int] = set()
            overwritten_vars: Set[str] = set()
            for _, if_node in method.filter(IfStatement):
                cond = if_node.condition
                if isinstance(cond, BinaryOperation):
                    l_val = method_int_constants.get(getattr(cond.operandl, "member", None))
                    r_val = int(cond.operandr.value) if isinstance(cond.operandr, Literal) and str(cond.operandr.value).isdigit() else None
                    if l_val is not None and r_val is not None:
                        taken = (cond.operator == ">" and l_val > r_val) or (cond.operator == "==" and l_val == r_val)
                        if taken:
                            if if_node.else_statement:
                                for _, dead_inv in if_node.else_statement.filter(MethodInvocation):
                                    dead_invocations.add(id(dead_inv))
                            stmts = if_node.then_statement if isinstance(if_node.then_statement, list) else [if_node.then_statement]
                            for s in stmts:
                                for _, assign in s.filter(Assignment):
                                    if isinstance(assign.expressionl, MemberReference):
                                        v_name = assign.expressionl.member
                                        overwritten_vars.add(v_name)
                                        local_scope[v_name] = assign.value
                                        if isinstance(assign.value, Literal) and str(assign.value.value).isdigit():
                                            method_int_constants[v_name] = int(assign.value.value)
                                for _, inv in s.filter(MethodInvocation):
                                    if inv.member in ("nextBytes", "generateSeed") and inv.arguments:
                                        if isinstance(inv.arguments[0], MemberReference):
                                            randomized_vars.add(inv.arguments[0].member)
                        else:
                            stmts = if_node.then_statement if isinstance(if_node.then_statement, list) else [if_node.then_statement]
                            for s in stmts:
                                for _, dead_inv in s.filter(MethodInvocation):
                                    dead_invocations.add(id(dead_inv))

            # Scan Method Invocations
            for path, method_inv in method.filter(MethodInvocation):
                if id(method_inv) in dead_invocations:
                    continue

                assigned_to = None
                for p in reversed(path):
                    if isinstance(p, VariableDeclarator):
                        assigned_to = p.name
                        break
                    if isinstance(p, Assignment) and isinstance(p.expressionl, MemberReference):
                        assigned_to = p.expressionl.member
                        break

                if assigned_to and assigned_to in overwritten_vars:
                    in_then = any(isinstance(p, IfStatement) for p in path)
                    if not in_then:
                        continue

                qualifier = method_inv.qualifier or ""
                member = method_inv.member
                line_no = method_inv.position.line if method_inv.position else 1
                is_shred, tier = self.check_crypto_shredding_context(content, line_no)

                # Match standard SPI getInstance calls
                if member == "getInstance" and qualifier in JCA_SPI_CLASSES:
                    spi_info = JCA_SPI_CLASSES[qualifier]
                    args = method_inv.arguments or []
                    if not args:
                        continue

                    raw_arg = args[0]
                    resolved_arg = JavaAstHelper.resolve_ast_expression(
                        raw_arg, local_scope, class_fields, tree, file_path, maps
                    )

                    # Dynamic or unresolvable quarantine
                    if resolved_arg and resolved_arg.startswith("DYNAMIC_UNRESOLVED:"):
                        method_name = resolved_arg.split(":", 1)[1]
                        assets.append(self.build_crypto_asset(
                            asset_prefix="SRC-JAVA",
                            index=len(assets) + 1,
                            component_name=f"{stem}:dynamic_unresolved",
                            algorithm="DYNAMIC_UNRESOLVED",
                            key_size=None,
                            primitive_type=spi_info["prim"],
                            file_path=rel_path,
                            line_number=line_no,
                            tier=XTier.HUMAN_REVIEW,
                            has_shredding=is_shred,
                            evidence_level=EvidenceLevel.E0_UNCONFIRMED,
                            evidence_source="java_contract:dynamic_quarantine",
                            matched_code=f"{qualifier}.{member}(...)",
                            language="java",
                            cwe=None,
                            description=f"Dynamic unresolvable expression: {method_name}",
                            risk_level="MANUAL_REVIEW_REQUIRED",
                            extra_properties={
                                "ecdat:human_review_required": True,
                                "ecdat:risk_level": "MANUAL_REVIEW_REQUIRED",
                                "ecdat:dynamic_expression": method_name,
                                "ecdat:auditor_note": f"Dynamic crypto invocation cannot be statically verified (Expression: {method_name}). Manual verification required."
                            }
                        ))
                        continue

                    if not resolved_arg or resolved_arg == "DYNAMIC_RANDOM":
                        arg_repr = getattr(raw_arg, "member", getattr(raw_arg, "value", "unknown"))
                        assets.append(self.build_crypto_asset(
                            asset_prefix="SRC-JAVA",
                            index=len(assets) + 1,
                            component_name=f"{stem}:unresolved_reference",
                            algorithm="DYNAMIC_UNRESOLVED",
                            key_size=None,
                            primitive_type=spi_info["prim"],
                            file_path=rel_path,
                            line_number=line_no,
                            tier=XTier.HUMAN_REVIEW,
                            has_shredding=is_shred,
                            evidence_level=EvidenceLevel.E0_UNCONFIRMED,
                            evidence_source="java_contract:external_constant",
                            matched_code=f"{qualifier}.{member}({arg_repr})",
                            language="java",
                            cwe=None,
                            description=f"Unresolved external argument reference: {arg_repr}",
                            risk_level="MANUAL_REVIEW_REQUIRED",
                            extra_properties={
                                "ecdat:human_review_required": True,
                                "ecdat:risk_level": "MANUAL_REVIEW_REQUIRED",
                                "ecdat:dynamic_expression": str(arg_repr),
                                "ecdat:auditor_note": f"External constant or cross-file reference ({arg_repr}) cannot be resolved locally. Manual verification required."
                            }
                        ))
                        continue

                    clean_alg_name = resolved_arg.split("/")[0].strip()
                    alg_upper = clean_alg_name.upper()
                    full_upper = resolved_arg.upper()

                    contract_name = spi_info["contract"]

                    # 3a. SSLContextSpi
                    if contract_name == "SSLContextSpi":
                        is_legacy_ssl = any(p in alg_upper for p in ("SSL", "TLSV1.0", "TLSV1.1")) and ("TLSV1.2" not in alg_upper and "TLSV1.3" not in alg_upper)
                        if is_legacy_ssl:
                            alg = f"IMPROPER-SSL:{alg_upper}"
                            risk = "CRITICAL"
                            cwe = "CWE-326"
                        else:
                            alg = clean_alg_name
                            risk = "LOW"
                            cwe = None
                        prim = PrimitiveType.KEY_EXCHANGE
                        key_size = None
                        desc = f"Java SSLContext {alg}"

                    # 3b. CipherSpi
                    elif contract_name == "CipherSpi":
                        is_ecb = "ECB" in full_upper or ("AES" in alg_upper and "/" not in resolved_arg)
                        if "DESEDE" in alg_upper or "3DES" in alg_upper:
                            alg = "3DES-168"
                            key_size = 168
                            risk = "HIGH"
                            cwe = "CWE-327"
                        elif "DES" in alg_upper:
                            alg = "DES-56"
                            key_size = 56
                            risk = "CRITICAL"
                            cwe = "CWE-327"
                        elif "BLOWFISH" in alg_upper:
                            alg = "Blowfish-128"
                            key_size = 128
                            risk = "HIGH"
                            cwe = "CWE-327"
                        elif "AES" in alg_upper:
                            if is_ecb:
                                alg = "AES-ECB"
                                key_size = 128
                                risk = "HIGH"
                                cwe = "CWE-327"
                            else:
                                alg = "AES-256"
                                key_size = 256
                                risk = "LOW"
                                cwe = None
                        elif "RC4" in alg_upper or "ARCFOUR" in alg_upper:
                            alg = "RC4-128"
                            key_size = 128
                            risk = "CRITICAL"
                            cwe = "CWE-327"
                        elif "RC2" in alg_upper:
                            alg = "RC2-128"
                            key_size = 128
                            risk = "CRITICAL"
                            cwe = "CWE-327"
                        elif "IDEA" in alg_upper:
                            alg = "IDEA-128"
                            key_size = 128
                            risk = "CRITICAL"
                            cwe = "CWE-327"
                        elif "RSA" in alg_upper:
                            alg = "RSA-2048"
                            key_size = 2048
                            risk = "HIGH"
                            cwe = "CWE-780"
                        else:
                            alg = clean_alg_name
                            key_size = 256
                            risk = "LOW"
                            cwe = None

                        prim = PrimitiveType.KEY_EXCHANGE if "RSA" in alg_upper else PrimitiveType.ENCRYPTION
                        desc = f"Java Cipher invocation ({alg})"

                    # 3c. KeyGenerator
                    elif contract_name == "KeyGenerator":
                        if "DESEDE" in alg_upper or "3DES" in alg_upper:
                            alg = "3DES-168"
                            key_size = 168
                            risk = "HIGH"
                            cwe = "CWE-326"
                        elif "DES" in alg_upper:
                            alg = "DES-56"
                            key_size = 56
                            risk = "CRITICAL"
                            cwe = "CWE-326"
                        elif "BLOWFISH" in alg_upper:
                            alg = "Blowfish-128"
                            key_size = 128
                            risk = "HIGH"
                            cwe = "CWE-327"
                        elif "AES" in alg_upper:
                            alg = "AES-256"
                            key_size = 256
                            risk = "LOW"
                            cwe = None
                        else:
                            alg = clean_alg_name
                            key_size = 256
                            risk = "LOW"
                            cwe = None

                        prim = PrimitiveType.KEY_EXCHANGE
                        desc = f"Java KeyGenerator invocation ({alg})"

                    # 3d. KeyPairGenerator
                    elif contract_name == "KeyPairGenerator":
                        init_keysize_val = None
                        if assigned_to:
                            for _, init_call in method.filter(MethodInvocation):
                                if init_call.qualifier == assigned_to and init_call.member in ("init", "initialize") and init_call.arguments:
                                    init_val_str = JavaAstHelper.resolve_ast_expression(init_call.arguments[0], local_scope, class_fields, tree, file_path, maps)
                                    if init_val_str and init_val_str.isdigit():
                                        init_keysize_val = int(init_val_str)
                                        break

                        if "RSA" in alg_upper or "DSA" in alg_upper:
                            if init_keysize_val is not None:
                                key_size = init_keysize_val
                                if init_keysize_val < 2048:
                                    alg = f"RSA-{init_keysize_val}"
                                    risk = "CRITICAL" if init_keysize_val <= 1024 else "HIGH"
                                    cwe = "CWE-326"
                                else:
                                    alg = f"RSA-{init_keysize_val}"
                                    risk = "LOW"
                                    cwe = None
                            else:
                                alg = "RSA-2048"
                                key_size = 2048
                                risk = "LOW"
                                cwe = None
                        elif "EC" in alg_upper:
                            if init_keysize_val is not None and init_keysize_val < 224:
                                alg = f"ECDSA-{init_keysize_val}"
                                key_size = init_keysize_val
                                risk = "HIGH"
                                cwe = "CWE-326"
                            else:
                                alg = "ECDSA-256"
                                key_size = 256
                                risk = "LOW"
                                cwe = None
                        else:
                            alg = clean_alg_name
                            key_size = 256
                            risk = "LOW"
                            cwe = None

                        prim = PrimitiveType.SIGNATURE
                        desc = f"Java KeyPairGenerator invocation ({alg})"

                    # 3e. MessageDigestSpi
                    elif contract_name == "MessageDigestSpi":
                        prim = PrimitiveType.HASH
                        if "MD2" in alg_upper:
                            alg = "MD2"
                            key_size = 128
                            risk = "CRITICAL"
                            cwe = "CWE-328"
                        elif "MD4" in alg_upper:
                            alg = "MD4"
                            key_size = 128
                            risk = "CRITICAL"
                            cwe = "CWE-328"
                        elif "MD5" in alg_upper:
                            alg = "MD5"
                            key_size = 128
                            risk = "CRITICAL"
                            cwe = "CWE-328"
                        elif "SHA" in alg_upper and ("1" in alg_upper or "-1" in alg_upper) and "256" not in alg_upper and "512" not in alg_upper:
                            alg = "SHA-1"
                            key_size = 160
                            risk = "HIGH"
                            cwe = "CWE-328"
                        elif "SHA" in alg_upper and "256" in alg_upper:
                            alg = "SHA-256"
                            key_size = 256
                            risk = "LOW"
                            cwe = None
                        else:
                            alg = clean_alg_name
                            key_size = 256
                            risk = "LOW"
                            cwe = None
                        desc = f"Java MessageDigest invocation ({alg})"

                    # 3f. SignatureSpi
                    elif contract_name == "SignatureSpi":
                        prim = PrimitiveType.SIGNATURE
                        if "RSA" in alg_upper:
                            alg = f"RSA-{alg_upper}" if not alg_upper.startswith("RSA-") else alg_upper
                            key_size = 2048
                            is_broken = "SHA1" in alg_upper or "MD5" in alg_upper
                            risk = "HIGH" if is_broken else "LOW"
                            cwe = "CWE-347" if is_broken else None
                        elif "ECDSA" in alg_upper:
                            alg = f"ECDSA-{alg_upper}" if not alg_upper.startswith("ECDSA-") else alg_upper
                            key_size = 256
                            risk = "LOW"
                            cwe = None
                        else:
                            alg = clean_alg_name
                            key_size = 256
                            risk = "LOW"
                            cwe = None
                        desc = f"Java Signature invocation ({alg})"

                    # 3g. MacSpi
                    elif contract_name == "MacSpi":
                        prim = PrimitiveType.HASH
                        if "MD5" in alg_upper:
                            alg = "HMAC-MD5"
                            key_size = 128
                            risk = "CRITICAL"
                            cwe = "CWE-328"
                        elif "SHA1" in alg_upper or "SHA-1" in alg_upper:
                            alg = "HMAC-SHA1"
                            key_size = 160
                            risk = "HIGH"
                            cwe = "CWE-328"
                        elif "SHA256" in alg_upper or "SHA-256" in alg_upper:
                            alg = "HMAC-SHA256"
                            key_size = 256
                            risk = "LOW"
                            cwe = None
                        else:
                            alg = clean_alg_name
                            key_size = 256
                            risk = "LOW"
                            cwe = None
                        desc = f"Java Mac invocation ({alg})"

                    else:
                        alg = clean_alg_name
                        prim = spi_info["prim"]
                        key_size = 256
                        cwe = None
                        risk = "LOW"
                        desc = f"Java {contract_name} invocation"

                    safe_alg = alg.lower().replace("-", "_").replace(":", "_")
                    assets.append(self.build_crypto_asset(
                        asset_prefix="SRC-JAVA",
                        index=len(assets) + 1,
                        component_name=f"{stem}:{safe_alg}",
                        algorithm=alg,
                        key_size=key_size,
                        primitive_type=prim,
                        file_path=rel_path,
                        line_number=line_no,
                        tier=tier,
                        has_shredding=is_shred,
                        evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                        evidence_source=f"java_contract:{contract_name}",
                        matched_code=f"{qualifier}.{member}(\"{resolved_arg}\")",
                        language="java",
                        cwe=cwe,
                        description=desc,
                        risk_level=risk
                    ))

                # 3h. SecureRandom.setSeed
                elif member == "setSeed" and method_inv.arguments:
                    seed_arg = method_inv.arguments[0]
                    is_dynamic = False
                    if isinstance(seed_arg, MemberReference) and seed_arg.member in randomized_vars:
                        is_dynamic = True
                    elif isinstance(seed_arg, MethodInvocation) and seed_arg.member in ("getInstanceStrong", "generateSeed", "nextLong", "nextInt"):
                        is_dynamic = True

                    if not is_dynamic:
                        assets.append(self.build_crypto_asset(
                            asset_prefix="SRC-JAVA",
                            index=len(assets) + 1,
                            component_name=f"{stem}:predictable_seed",
                            algorithm="PREDICTABLE-SEED",
                            key_size=None,
                            primitive_type=PrimitiveType.KEY_EXCHANGE,
                            file_path=rel_path,
                            line_number=line_no,
                            tier=tier,
                            has_shredding=is_shred,
                            evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                            evidence_source="java_contract:SecureRandom_setSeed",
                            matched_code=f"{qualifier}.setSeed(...)",
                            language="java",
                            cwe="CWE-330",
                            description="Predictable seed used in SecureRandom.setSeed",
                            risk_level="HIGH"
                        ))

                # 3i. KeyStore.load
                elif member == "load" and method_inv.arguments and len(method_inv.arguments) >= 2:
                    pass_arg = method_inv.arguments[1]
                    is_safe = False
                    if isinstance(pass_arg, Literal) and pass_arg.value == "null":
                        is_safe = True
                    val = JavaAstHelper.resolve_ast_expression(pass_arg, local_scope, class_fields, tree, file_path, maps)
                    if val == "DYNAMIC_RANDOM":
                        is_safe = True
                    if isinstance(pass_arg, MethodInvocation) and pass_arg.qualifier:
                        if isinstance(pass_arg.qualifier, ClassCreator):
                            c_args = pass_arg.qualifier.arguments or []
                            if c_args and getattr(c_args[0], "member", "") in randomized_vars:
                                is_safe = True
                    if not is_safe:
                        assets.append(self.build_crypto_asset(
                            asset_prefix="SRC-JAVA",
                            index=len(assets) + 1,
                            component_name=f"{stem}:keystore_password",
                            algorithm="PREDICTABLE-KEYSTORE-PASSWORD",
                            key_size=None,
                            primitive_type=PrimitiveType.KEY_EXCHANGE,
                            file_path=rel_path,
                            line_number=line_no,
                            tier=tier,
                            has_shredding=is_shred,
                            evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                            evidence_source="java_contract:KeyStore_load",
                            matched_code=f"{qualifier}.load(..., ...)",
                            language="java",
                            cwe="CWE-798",
                            description="Predictable keystore password in KeyStore.load",
                            risk_level="HIGH"
                        ))

                # 3j. SSLSocketFactory.getDefault
                elif member == "getDefault" and qualifier == "SSLSocketFactory":
                    assets.append(self.build_crypto_asset(
                        asset_prefix="SRC-JAVA",
                        index=len(assets) + 1,
                        component_name=f"{stem}:improper_ssl_socket",
                        algorithm="IMPROPER-SSL-SOCKET-FACTORY",
                        key_size=None,
                        primitive_type=PrimitiveType.KEY_EXCHANGE,
                        file_path=rel_path,
                        line_number=line_no,
                        tier=tier,
                        has_shredding=is_shred,
                        evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                        evidence_source="java_contract:SSLSocketFactory",
                        matched_code="SSLSocketFactory.getDefault().createSocket without hostname validation",
                        language="java",
                        cwe="CWE-297",
                        description="SSLSocketFactory without hostname verification",
                        risk_level="HIGH"
                    ))

            # 4. Traverse Class Creators (Constructors) in Method
            for path, creator in method.filter(ClassCreator):
                if id(creator) in dead_invocations:
                    continue

                full_cls_name = JavaAstHelper.get_full_type_name(creator.type)
                simple_cls_name = creator.type.name if hasattr(creator.type, "name") else ""
                line_no = creator.position.line if creator.position else 1
                is_shred, tier = self.check_crypto_shredding_context(content, line_no)
                args = creator.arguments or []

                # 4a. SecretKeySpec
                if simple_cls_name == "SecretKeySpec" or full_cls_name.endswith("SecretKeySpec"):
                    if args:
                        key_ref = getattr(args[0], "member", None)
                        if key_ref and key_ref in randomized_vars:
                            pass
                        else:
                            assets.append(self.build_crypto_asset(
                                asset_prefix="SRC-JAVA",
                                index=len(assets) + 1,
                                component_name=f"{stem}:predictable_key",
                                algorithm="PREDICTABLE-KEY",
                                key_size=128,
                                primitive_type=PrimitiveType.ENCRYPTION,
                                file_path=rel_path,
                                line_number=line_no,
                                tier=tier,
                                has_shredding=is_shred,
                                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                                evidence_source="java_contract:SecretKeySpec",
                                matched_code="new SecretKeySpec(...)",
                                language="java",
                                cwe="CWE-321",
                                description="Hardcoded or predictable static key in SecretKeySpec",
                                risk_level="CRITICAL"
                            ))

                # 4b. PBEKeySpec
                elif simple_cls_name == "PBEKeySpec" or full_cls_name.endswith("PBEKeySpec"):
                    if args:
                        p_val = JavaAstHelper.resolve_ast_expression(args[0], local_scope, class_fields, tree, file_path, maps)
                        is_safe = (p_val == "DYNAMIC_RANDOM")
                        if isinstance(args[0], MethodInvocation) and args[0].qualifier:
                            if isinstance(args[0].qualifier, ClassCreator):
                                c_args = args[0].qualifier.arguments or []
                                if c_args and getattr(c_args[0], "member", "") in randomized_vars:
                                    is_safe = True

                        if not is_safe:
                            assets.append(self.build_crypto_asset(
                                asset_prefix="SRC-JAVA",
                                index=len(assets) + 1,
                                component_name=f"{stem}:hardcoded_password",
                                algorithm="HARDCODED-PASSWORD",
                                key_size=None,
                                primitive_type=PrimitiveType.KEY_EXCHANGE,
                                file_path=rel_path,
                                line_number=line_no,
                                tier=tier,
                                has_shredding=is_shred,
                                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                                evidence_source="java_contract:PBEKeySpec_password",
                                matched_code="new PBEKeySpec(...)",
                                language="java",
                                cwe="CWE-798",
                                description="Hardcoded static password in PBEKeySpec",
                                risk_level="CRITICAL"
                            ))

                        if len(args) >= 2:
                            salt_ref = getattr(args[1], "member", None)
                            if not (salt_ref and salt_ref in randomized_vars):
                                assets.append(self.build_crypto_asset(
                                    asset_prefix="SRC-JAVA",
                                    index=len(assets) + 1,
                                    component_name=f"{stem}:static_salt",
                                    algorithm="STATIC-SALT",
                                    key_size=None,
                                    primitive_type=PrimitiveType.KEY_EXCHANGE,
                                    file_path=rel_path,
                                    line_number=line_no,
                                    tier=tier,
                                    has_shredding=is_shred,
                                    evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                                    evidence_source="java_contract:PBEKeySpec_salt",
                                    matched_code="new PBEKeySpec(..., salt, ...)",
                                    language="java",
                                    cwe="CWE-326",
                                    description="Static or predictable salt in PBEKeySpec",
                                    risk_level="HIGH"
                                ))

                        if len(args) >= 3:
                            cnt = JavaAstHelper.resolve_ast_expression(args[2], local_scope, class_fields, tree, file_path, maps)
                            if cnt and cnt.isdigit() and int(cnt) <= 1000:
                                assets.append(self.build_crypto_asset(
                                    asset_prefix="SRC-JAVA",
                                    index=len(assets) + 1,
                                    component_name=f"{stem}:pbe_weak_iteration",
                                    algorithm="PBE-WEAK-ITERATION",
                                    key_size=None,
                                    primitive_type=PrimitiveType.KEY_EXCHANGE,
                                    file_path=rel_path,
                                    line_number=line_no,
                                    tier=tier,
                                    has_shredding=is_shred,
                                    evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                                    evidence_source="java_contract:PBEKeySpec_iteration",
                                    matched_code=f"new PBEKeySpec(..., {cnt})",
                                    language="java",
                                    cwe="CWE-326",
                                    description=f"Weak PBE iteration count ({cnt} <= 1000)",
                                    risk_level="HIGH"
                                ))

                # 4c. PBEParameterSpec
                elif simple_cls_name == "PBEParameterSpec" or full_cls_name.endswith("PBEParameterSpec"):
                    if args:
                        salt_ref = getattr(args[0], "member", None)
                        if not (salt_ref and salt_ref in randomized_vars):
                            assets.append(self.build_crypto_asset(
                                asset_prefix="SRC-JAVA",
                                index=len(assets) + 1,
                                component_name=f"{stem}:static_salt",
                                algorithm="STATIC-SALT",
                                key_size=None,
                                primitive_type=PrimitiveType.KEY_EXCHANGE,
                                file_path=rel_path,
                                line_number=line_no,
                                tier=tier,
                                has_shredding=is_shred,
                                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                                evidence_source="java_contract:PBEParameterSpec_salt",
                                matched_code="new PBEParameterSpec(salt, count)",
                                language="java",
                                cwe="CWE-326",
                                description="Static or predictable salt in PBEParameterSpec",
                                risk_level="HIGH"
                            ))

                        if len(args) >= 2:
                            cnt = JavaAstHelper.resolve_ast_expression(args[1], local_scope, class_fields, tree, file_path, maps)
                            if cnt and cnt.isdigit() and int(cnt) <= 1000:
                                assets.append(self.build_crypto_asset(
                                    asset_prefix="SRC-JAVA",
                                    index=len(assets) + 1,
                                    component_name=f"{stem}:pbe_weak_iteration",
                                    algorithm="PBE-WEAK-ITERATION",
                                    key_size=None,
                                    primitive_type=PrimitiveType.KEY_EXCHANGE,
                                    file_path=rel_path,
                                    line_number=line_no,
                                    tier=tier,
                                    has_shredding=is_shred,
                                    evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                                    evidence_source="java_contract:PBEParameterSpec_iteration",
                                    matched_code=f"new PBEParameterSpec(..., {cnt})",
                                    language="java",
                                    cwe="CWE-326",
                                    description=f"Weak PBE iteration count ({cnt} <= 1000)",
                                    risk_level="HIGH"
                                ))

                # 4d. IvParameterSpec
                elif simple_cls_name == "IvParameterSpec" or full_cls_name.endswith("IvParameterSpec"):
                    iv_ref = getattr(args[0], "member", None) if args else None
                    if not (iv_ref and iv_ref in randomized_vars):
                        assets.append(self.build_crypto_asset(
                            asset_prefix="SRC-JAVA",
                            index=len(assets) + 1,
                            component_name=f"{stem}:static_iv",
                            algorithm="STATIC-IV",
                            key_size=128,
                            primitive_type=PrimitiveType.ENCRYPTION,
                            file_path=rel_path,
                            line_number=line_no,
                            tier=tier,
                            has_shredding=is_shred,
                            evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                            evidence_source="java_contract:IvParameterSpec",
                            matched_code="new IvParameterSpec(...)",
                            language="java",
                            cwe="CWE-329",
                            description="Static or predictable IV in IvParameterSpec",
                            risk_level="HIGH"
                        ))

                # 4e. SecureRandom constructor with seed
                elif simple_cls_name == "SecureRandom" or full_cls_name.endswith("SecureRandom"):
                    if args:
                        seed_ref = getattr(args[0], "member", None)
                        if not (seed_ref and seed_ref in randomized_vars):
                            assets.append(self.build_crypto_asset(
                                asset_prefix="SRC-JAVA",
                                index=len(assets) + 1,
                                component_name=f"{stem}:predictable_seed",
                                algorithm="PREDICTABLE-SEED",
                                key_size=None,
                                primitive_type=PrimitiveType.KEY_EXCHANGE,
                                file_path=rel_path,
                                line_number=line_no,
                                tier=tier,
                                has_shredding=is_shred,
                                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                                evidence_source="java_contract:SecureRandom_constructor",
                                matched_code="new SecureRandom(seed)",
                                language="java",
                                cwe="CWE-330",
                                description="Predictable seed passed to SecureRandom constructor",
                                risk_level="HIGH"
                            ))
                    else:
                        assets.append(self.build_crypto_asset(
                            asset_prefix="SRC-JAVA",
                            index=len(assets) + 1,
                            component_name=f"{stem}:secure_prng",
                            algorithm="SECURE-PRNG",
                            key_size=None,
                            primitive_type=PrimitiveType.KEY_EXCHANGE,
                            file_path=rel_path,
                            line_number=line_no,
                            tier=tier,
                            has_shredding=is_shred,
                            evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                            evidence_source="java_contract:SecureRandom",
                            matched_code="new SecureRandom()",
                            language="java",
                            cwe=None,
                            description="Secure pseudo-random number generator (java.security.SecureRandom)",
                            risk_level="LOW"
                        ))

                # 4f. java.net.URL cleartext http
                elif simple_cls_name == "URL" or full_cls_name.endswith("URL"):
                    if args:
                        url_str = JavaAstHelper.resolve_ast_expression(args[0], local_scope, class_fields, tree, file_path, maps)
                        if url_str and url_str.lower().startswith("http://") and not any(h in url_str for h in ("schemas.", "www.w3.org", "java.sun.com")):
                            assets.append(self.build_crypto_asset(
                                asset_prefix="SRC-JAVA",
                                index=len(assets) + 1,
                                component_name=f"{stem}:cleartext_http",
                                algorithm="CLEARTEXT-HTTP",
                                key_size=None,
                                primitive_type=PrimitiveType.KEY_EXCHANGE,
                                file_path=rel_path,
                                line_number=line_no,
                                tier=tier,
                                has_shredding=is_shred,
                                evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                                evidence_source="java_contract:URL_HTTP",
                                matched_code=f"new URL(\"{url_str}\")",
                                language="java",
                                cwe="CWE-319",
                                description="Cleartext unencrypted HTTP communication channel",
                                risk_level="HIGH"
                            ))

                # 4g. java.util.Random
                elif simple_cls_name == "Random" or full_cls_name.endswith("Random"):
                    assets.append(self.build_crypto_asset(
                        asset_prefix="SRC-JAVA",
                        index=len(assets) + 1,
                        component_name=f"{stem}:untrusted_prng",
                        algorithm="UNTRUSTED-PRNG",
                        key_size=None,
                        primitive_type=PrimitiveType.KEY_EXCHANGE,
                        file_path=rel_path,
                        line_number=line_no,
                        tier=tier,
                        has_shredding=is_shred,
                        evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                        evidence_source="java_contract:Random_PRNG",
                        matched_code="new Random()",
                        language="java",
                        cwe="CWE-338",
                        description="Untrusted pseudo-random number generator (java.util.Random) in cryptographic context",
                        risk_level="MEDIUM"
                    ))

        # 5. Inspect Class Declarations for interface contracts
        for _, class_decl in tree.filter(ClassDeclaration):
            implements_list = [JavaAstHelper.get_full_type_name(i) for i in (class_decl.implements or [])]
            line_no = class_decl.position.line if class_decl.position else 1
            is_shred, tier = self.check_crypto_shredding_context(content, line_no)

            # 5a. X509TrustManager
            if any("X509TrustManager" in iface for iface in implements_list):
                is_dummy = True
                for m in class_decl.methods:
                    if m.name == "checkServerTrusted" and m.body:
                        has_throw = any(True for _ in m.filter(ThrowStatement))
                        has_calls = len(m.body) > 0
                        if has_throw or has_calls:
                            is_dummy = False
                        break

                if is_dummy:
                    assets.append(self.build_crypto_asset(
                        asset_prefix="SRC-JAVA",
                        index=len(assets) + 1,
                        component_name=f"{stem}:dummy_cert_validation",
                        algorithm="DUMMY-CERT-VALIDATION",
                        key_size=None,
                        primitive_type=PrimitiveType.SIGNATURE,
                        file_path=rel_path,
                        line_number=line_no,
                        tier=tier,
                        has_shredding=is_shred,
                        evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                        evidence_source="java_contract:X509TrustManager",
                        matched_code="class implements X509TrustManager with dummy checkServerTrusted",
                        language="java",
                        cwe="CWE-295",
                        description="Dummy X509TrustManager accepting all server certificates",
                        risk_level="CRITICAL"
                    ))

            # 5b. HostnameVerifier
            if any("HostnameVerifier" in iface for iface in implements_list):
                returns_true = False
                for m in class_decl.methods:
                    if m.name == "verify" and m.body:
                        has_ifs = any(True for _ in m.filter(IfStatement))
                        if not has_ifs:
                            for _, ret_stmt in m.filter(ReturnStatement):
                                if isinstance(ret_stmt.expression, Literal) and ret_stmt.expression.value == "true":
                                    returns_true = True
                        break

                if returns_true:
                    assets.append(self.build_crypto_asset(
                        asset_prefix="SRC-JAVA",
                        index=len(assets) + 1,
                        component_name=f"{stem}:dummy_hostname_verifier",
                        algorithm="DUMMY-HOSTNAME-VERIFIER",
                        key_size=None,
                        primitive_type=PrimitiveType.SIGNATURE,
                        file_path=rel_path,
                        line_number=line_no,
                        tier=tier,
                        has_shredding=is_shred,
                        evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                        evidence_source="java_contract:HostnameVerifier",
                        matched_code="verify() unconditionally returns true",
                        language="java",
                        cwe="CWE-297",
                        description="Dummy HostnameVerifier accepting all hostnames",
                        risk_level="CRITICAL"
                    ))
                else:
                    assets.append(self.build_crypto_asset(
                        asset_prefix="SRC-JAVA",
                        index=len(assets) + 1,
                        component_name=f"{stem}:secure_hostname_verifier",
                        algorithm="TLS-HOSTNAME-VERIFIER",
                        key_size=None,
                        primitive_type=PrimitiveType.SIGNATURE,
                        file_path=rel_path,
                        line_number=line_no,
                        tier=tier,
                        has_shredding=is_shred,
                        evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                        evidence_source="java_contract:HostnameVerifier",
                        matched_code="Custom HostnameVerifier with active session verification",
                        language="java",
                        cwe=None,
                        description="Custom HostnameVerifier with active verification",
                        risk_level="LOW"
                    ))

        return assets
