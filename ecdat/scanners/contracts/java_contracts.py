"""
ECDAT Java Cryptographic Contract Engine:
Statically discovers Java cryptographic primitives across standard JCA/JCE Service Provider
Interfaces (CipherSpi, MessageDigestSpi, SignatureSpi, MacSpi, KeyAgreementSpi, SSLContextSpi)
and Bouncy Castle lightweight APIs, with backward data-flow tracking and honest dynamic quarantine.
"""

import re
from pathlib import Path
from typing import List, Dict, Tuple, Optional, Set, Any

from ecdat.models import (
    CryptoAsset,
    PrimitiveType,
    XTier,
    EvidenceLevel,
    IntentClass,
    AgilityLevel
)
from ecdat.rules.signature_db import get_signature_db
from ecdat.scanners.contracts.base import BaseContractEngine

# Java SPI Invocations
JAVA_SPI_CALLS = [
    {"contract": "CipherSpi", "method": "getInstance", "class": r"(?:javax\.crypto\.)?Cipher", "prim": PrimitiveType.ENCRYPTION},
    {"contract": "MessageDigestSpi", "method": "getInstance", "class": r"(?:java\.security\.)?MessageDigest", "prim": PrimitiveType.HASH},
    {"contract": "SignatureSpi", "method": "getInstance", "class": r"(?:java\.security\.)?Signature", "prim": PrimitiveType.SIGNATURE},
    {"contract": "MacSpi", "method": "getInstance", "class": r"(?:javax\.crypto\.)?Mac", "prim": PrimitiveType.HASH},
    {"contract": "KeyAgreementSpi", "method": "getInstance", "class": r"(?:javax\.crypto\.)?KeyAgreement", "prim": PrimitiveType.KEY_EXCHANGE},
    {"contract": "KeyGenerator", "method": "getInstance", "class": r"(?:java\.security\.|javax\.crypto\.)?KeyGenerator", "prim": PrimitiveType.KEY_EXCHANGE},
    {"contract": "KeyPairGenerator", "method": "getInstance", "class": r"(?:java\.security\.)?KeyPairGenerator", "prim": PrimitiveType.SIGNATURE},
    {"contract": "SSLContextSpi", "method": "getInstance", "class": r"(?:javax\.net\.ssl\.)?SSLContext", "prim": PrimitiveType.KEY_EXCHANGE},
]

DYNAMIC_METHOD_RE = re.compile(
    r"(?:[\"']\s*\.|\b[a-zA-Z0-9_]+\s*\.)\s*(?:replace|replaceAll|replaceFirst|substring|toLowerCase|toUpperCase|concat|trim|format)\s*\(",
    re.IGNORECASE
)

KNOWN_JAVA_ALGS_RE = re.compile(
    r"[\"']((?:DESede|3DES|DES|Blowfish|RC4|ARCFOUR|RC2|IDEA|MD5|MD4|MD2|SHA-?1|SHA-?256|SHA-?512|SHA-?384|AES|RSA|ECDSA|DSA|DiffieHellman|DH|Hmac[A-Za-z0-9]+)[^\"']*)[\"']",
    re.IGNORECASE
)


def _find_matching_brace(s: str, start: int) -> int:
    depth = 0
    for i in range(start, len(s)):
        if s[i] == "{":
            depth += 1
        elif s[i] == "}":
            depth -= 1
            if depth == 0:
                return i
    return -1


def _blank_out(s: str, start: int, end: int) -> str:
    sub = s[start:end]
    blanked = "".join("\n" if c == "\n" else " " for c in sub)
    return s[:start] + blanked + s[end:]


def _preprocess_java_path_conditions(content: str) -> str:
    """Evaluates statically provable branch conditions to eliminate dead code branches."""
    constants = {}
    for m in re.finditer(r"\bint\s+([a-zA-Z0-9_]+)\s*=\s*(\d+)\s*;", content):
        constants[m.group(1)] = int(m.group(2))
    if not constants:
        return content

    for var_name, var_val in constants.items():
        for if_m in re.finditer(r"\bif\s*\(\s*" + re.escape(var_name) + r"\s*(>|<|==|!=|>=|<=)\s*(\d+)\s*\)", content):
            op, val = if_m.group(1), int(if_m.group(2))
            if op == ">": cond_val = var_val > val
            elif op == "<": cond_val = var_val < val
            elif op == "==": cond_val = var_val == val
            elif op == "!=": cond_val = var_val != val
            elif op == ">=": cond_val = var_val >= val
            elif op == "<=": cond_val = var_val <= val
            else: continue

            if cond_val:
                reassign_pat = re.compile(
                    r"((?:[A-Za-z0-9_<>[\]]+\s+)?([A-Za-z0-9_]+)\s*=\s*[^;]+;)\s*" +
                    re.escape(if_m.group(0)) +
                    r"\s*(\2\s*=\s*[^;]+;)"
                )
                m_reassign = reassign_pat.search(content)
                if m_reassign:
                    content = _blank_out(content, m_reassign.start(1), m_reassign.end(1))

    for m in list(re.finditer(r"\bif\s*\(([^)]+)\)", content)):
        cond_str = m.group(1).strip()
        cond_m = re.match(r"([a-zA-Z0-9_]+)\s*(==|!=|>=|<=|>|<)\s*(\d+)", cond_str)
        if not cond_m:
            continue
        var_name, op, val_str = cond_m.group(1), cond_m.group(2), cond_m.group(3)
        if var_name not in constants:
            continue
        var_val = constants[var_name]
        val = int(val_str)
        if op == ">": cond_val = var_val > val
        elif op == "<": cond_val = var_val < val
        elif op == "==": cond_val = var_val == val
        elif op == "!=": cond_val = var_val != val
        elif op == ">=": cond_val = var_val >= val
        elif op == "<=": cond_val = var_val <= val
        else: continue

        idx = m.end()
        while idx < len(content) and content[idx].isspace():
            idx += 1
        if idx >= len(content):
            continue

        if content[idx] == "{":
            if_end = _find_matching_brace(content, idx)
            if if_end == -1:
                continue
            if_body_start, if_body_end = idx + 1, if_end
            next_idx = if_end + 1
        else:
            semi = content.find(";", idx)
            if semi == -1:
                continue
            if_body_start, if_body_end = idx, semi + 1
            next_idx = semi + 1

        rem = content[next_idx:]
        else_m = re.match(r"\s*else\b", rem)
        if bool(else_m):
            else_start = next_idx + else_m.end()
            while else_start < len(content) and content[else_start].isspace():
                else_start += 1
            if else_start < len(content):
                if content[else_start] == "{":
                    else_end = _find_matching_brace(content, else_start)
                    else_body_start, else_body_end = (else_start + 1, else_end) if else_end != -1 else (None, None)
                else:
                    semi = content.find(";", else_start)
                    else_body_start, else_body_end = (else_start, semi + 1) if semi != -1 else (None, None)
            else:
                else_body_start, else_body_end = None, None
        else:
            else_body_start, else_body_end = None, None

        if cond_val:
            if else_body_start is not None:
                content = _blank_out(content, else_body_start, else_body_end)
        else:
            content = _blank_out(content, if_body_start, if_body_end)

    return content


def _strip_java_comments(text: str) -> str:
    """Strips block and inline comments while strictly preserving string literals, line counts, and offsets."""
    def replacer(match):
        s = match.group(0)
        if s.startswith("/"):
            return "".join("\n" if c == "\n" else " " for c in s)
        else:
            return s
    pattern = re.compile(
        r"//.*?$|/\*.*?\*/|'(?:\\.|[^\\'])*'|\"(?:\\.|[^\\\"])*\"",
        re.DOTALL | re.MULTILINE
    )
    return re.sub(pattern, replacer, text)


class JavaContractEngine(BaseContractEngine):
    """AST/Syntax Contract Engine for Java Cryptography Architecture (JCA/JCE)."""

    def __init__(self):
        self.db = get_signature_db()

    def _extract_call_args_balanced(self, content: str, open_paren_pos: int) -> List[str]:
        pos = open_paren_pos
        depth = 0
        in_quote = False
        quote_char = None
        escape = False
        args: List[str] = []
        curr: List[str] = []

        while pos < len(content):
            ch = content[pos]
            if escape:
                curr.append(ch)
                escape = False
                pos += 1
                continue
            if ch == "\\":
                curr.append(ch)
                escape = True
                pos += 1
                continue
            if in_quote:
                curr.append(ch)
                if ch == quote_char:
                    in_quote = False
                pos += 1
                continue
            if ch in ('"', "'"):
                in_quote = True
                quote_char = ch
                curr.append(ch)
                pos += 1
                continue
            if ch in ('(', '[', '{'):
                depth += 1
                curr.append(ch)
                pos += 1
                continue
            if ch in (')', ']', '}'):
                if depth == 0:
                    break
                depth -= 1
                curr.append(ch)
                pos += 1
                continue
            if ch == ',' and depth == 0:
                args.append("".join(curr).strip())
                curr = []
                pos += 1
                continue
            curr.append(ch)
            pos += 1

        if curr:
            args.append("".join(curr).strip())
        return args

    def _trace_java_var(self, var_name: str, before_pos: int, content: str, max_depth: int = 10, visited: Optional[set] = None, file_path: Optional[Path] = None) -> Optional[str]:
        if max_depth <= 0:
            return None
        curr_var = var_name.strip()
        if (curr_var.startswith('"') and curr_var.endswith('"')) or (curr_var.startswith("'") and curr_var.endswith("'")):
            return curr_var[1:-1]
        if curr_var.isdigit():
            return curr_var

        unwrap_patterns = [
            r"^(?:String\.valueOf|new\s+String|\(String\)|\(int\)|Integer\.parseInt|new\s+Integer|\(Integer\)|Long\.parseLong|new\s+Long|\(Long\))\s*\(\s*([^()]+)\s*\)$",
            r"^([a-zA-Z0-9_]+)\s*\.\s*(?:toCharArray|getBytes|toString|trim|toLowerCase|toUpperCase)\s*\(\s*\)$",
        ]
        changed = True
        while changed:
            changed = False
            for upat in unwrap_patterns:
                um = re.match(upat, curr_var)
                if um:
                    curr_var = um.group(1).strip()
                    changed = True
                    break

        if (curr_var.startswith('"') and curr_var.endswith('"')) or (curr_var.startswith("'") and curr_var.endswith("'")):
            return curr_var[1:-1]
        if curr_var.isdigit():
            return curr_var

        if visited is None:
            visited = set()
        state_key = (curr_var, before_pos, str(file_path) if file_path else "")
        if state_key in visited:
            return None
        visited.add(state_key)

        # 1. Check if curr_var is a field access like obj.field
        if "." in curr_var:
            parts = curr_var.split(".", 1)
            obj_name, field_name = parts[0].strip(), parts[1].strip()
            direct_pat = r"(?:\b[a-zA-Z0-9_<>[\]]+\s+)?" + re.escape(obj_name) + r"\." + re.escape(field_name) + r"\s*=\s*([^;]+);"
            m_direct = list(re.finditer(direct_pat, content[:before_pos]))
            if m_direct:
                rhs = m_direct[-1].group(1).strip()
                res = self._trace_java_var(rhs, m_direct[-1].start(), content, max_depth - 1, visited, file_path)
                if res:
                    return res
            field_pat = r"(?:\b[a-zA-Z0-9_<>[\]]+\s+)?\b" + re.escape(field_name) + r"\s*=\s*([^;]+);"
            m_field = list(re.finditer(field_pat, content))
            for mf in reversed(m_field):
                rhs = mf.group(1).strip()
                res = self._trace_java_var(rhs, mf.start(), content, max_depth - 1, visited, file_path)
                if res:
                    return res
            obj_res = self._trace_java_var(obj_name, before_pos, content, max_depth - 1, visited, file_path)
            if obj_res:
                return obj_res

        # 2. Local backward search for curr_var = <rhs>;
        curr_pos = before_pos
        pat = r"(?:(?:\b(?:public|private|protected|static|final|volatile|transient|[a-zA-Z0-9_<>[\]]+)\s+)+)?\b" + re.escape(curr_var) + r"\s*=\s*([^;]+);"
        matches = list(re.finditer(pat, content[:curr_pos]))
        if matches:
            last_m = matches[-1]
            rhs = last_m.group(1).strip()
            curr_pos = last_m.start()

            known_m = KNOWN_JAVA_ALGS_RE.search(rhs)
            if known_m:
                return known_m.group(1)

            if DYNAMIC_METHOD_RE.search(rhs):
                return f"DYNAMIC_UNRESOLVED:{rhs}"

            str_m = re.search(r'["\']([^"\']+)["\']', rhs)
            if str_m:
                return str_m.group(1)

            if rhs.isdigit():
                return rhs

            map_get_m = re.search(r'([a-zA-Z0-9_]+)\.get\s*\(\s*["\']([^"\']+)["\']\s*\)', rhs)
            if map_get_m:
                map_name = map_get_m.group(1)
                map_key = map_get_m.group(2)
                put_pat = r"\b" + re.escape(map_name) + r"\.put\s*\(\s*[\"']" + re.escape(map_key) + r"[\"']\s*,\s*([^)]+)\)"
                put_m = list(re.finditer(put_pat, content[:curr_pos]))
                if put_m:
                    put_val = put_m[-1].group(1).strip()
                    res = self._trace_java_var(put_val, put_m[-1].start(), content, max_depth - 1, visited, file_path)
                    if res:
                        return res

            call_m = re.match(r'^[a-zA-Z0-9_.]+\s*\(\s*([^()]+)\s*\)$', rhs)
            if call_m:
                call_arg = call_m.group(1).strip()
                res = self._trace_java_var(call_arg, curr_pos, content, max_depth - 1, visited, file_path)
                if res:
                    return res

            new_obj_m = re.search(r'new\s+[a-zA-Z0-9_.]+\s*\(\s*["\']([^"\']+)["\']', rhs)
            if new_obj_m:
                return new_obj_m.group(1)

            new_byte_m = re.search(r'new\s+byte\s*\[\s*\]\s*\{([^}]+)\}', rhs)
            if new_byte_m:
                return new_byte_m.group(1).strip()

            res = self._trace_java_var(rhs, curr_pos, content, max_depth - 1, visited, file_path)
            if res:
                return res

        # 3. Global search anywhere in content for curr_var = <rhs>; (for fields/static variables)
        global_matches = list(re.finditer(pat, content))
        for gm in reversed(global_matches):
            if gm.start() == curr_pos:
                continue
            rhs = gm.group(1).strip()
            known_m = KNOWN_JAVA_ALGS_RE.search(rhs)
            if known_m:
                return known_m.group(1)
            str_m = re.search(r'["\']([^"\']+)["\']', rhs)
            if str_m:
                return str_m.group(1)
            if rhs.isdigit():
                return rhs
            map_get_m = re.search(r'([a-zA-Z0-9_]+)\.get\s*\(\s*["\']([^"\']+)["\']\s*\)', rhs)
            if map_get_m:
                map_name = map_get_m.group(1)
                map_key = map_get_m.group(2)
                put_pat = r"\b" + re.escape(map_name) + r"\.put\s*\(\s*[\"']" + re.escape(map_key) + r"[\"']\s*,\s*([^)]+)\)"
                put_m = list(re.finditer(put_pat, content[:gm.start()]))
                if put_m:
                    put_val = put_m[-1].group(1).strip()
                    res = self._trace_java_var(put_val, put_m[-1].start(), content, max_depth - 1, visited, file_path)
                    if res:
                        return res
            call_m = re.match(r'^[a-zA-Z0-9_.]+\s*\(\s*([^()]+)\s*\)$', rhs)
            if call_m:
                call_arg = call_m.group(1).strip()
                res = self._trace_java_var(call_arg, gm.start(), content, max_depth - 1, visited, file_path)
                if res:
                    return res
            res = self._trace_java_var(rhs, gm.start(), content, max_depth - 1, visited, file_path)
            if res:
                return res

        # 4. Inter-procedural Parameter Binding
        method_decl_pat = re.compile(
            r"\b(?:public|private|protected|static|final|synchronized|\s)*\s*(?:[a-zA-Z0-9_<>[\]]+\s+)?([a-zA-Z0-9_]+)\s*\(([^)]*)\)\s*(?:throws\s+[^{]+)?\{"
        )
        enclosing_method = None
        param_index = -1
        for m in method_decl_pat.finditer(content[:before_pos]):
            brace_end = _find_matching_brace(content, m.end() - 1)
            if brace_end == -1 or brace_end >= before_pos:
                fn_name = m.group(1)
                raw_params = m.group(2)
                if not raw_params.strip():
                    continue
                params = [p.strip() for p in raw_params.split(",") if p.strip()]
                for idx, p in enumerate(params):
                    p_ident = p.split()[-1].strip()
                    if p_ident == curr_var:
                        enclosing_method = fn_name
                        param_index = idx
                        break
                if enclosing_method:
                    break

        if enclosing_method and param_index >= 0:
            call_files = [(content, file_path)]
            if file_path and file_path.parent.exists():
                for sib in file_path.parent.glob("*.java"):
                    if sib != file_path:
                        try:
                            s_text = sib.read_text(encoding="utf-8", errors="replace")
                            call_files.append((s_text, sib))
                        except Exception:
                            pass
            call_pat = re.compile(r"\b(?:[a-zA-Z0-9_]+\s*\.\s*)?\b" + re.escape(enclosing_method) + r"\b\s*\(")
            for c_text, c_path in call_files:
                for cm in call_pat.finditer(c_text):
                    # verify it is not the definition itself
                    decl_m = re.search(r"\b(?:public|private|protected|static|void|int|String|class)\b[^{;]*\b" + re.escape(enclosing_method) + r"\s*\(", c_text[max(0, cm.start() - 60):cm.end()])
                    if decl_m:
                        continue
                    call_paren_pos = cm.end()
                    call_args = self._extract_call_args_balanced(c_text, call_paren_pos)
                    if len(call_args) > param_index:
                        passed_arg = call_args[param_index].strip()
                        res = self._trace_java_var(passed_arg, cm.start(), c_text, max_depth - 1, visited, c_path)
                        if res:
                            return res

        return None

    def scan_file(self, file_path: Path, base_dir: Path) -> List[CryptoAsset]:
        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []

        # 1. Comment stripping & dead path elimination
        content = _strip_java_comments(content)
        content = _preprocess_java_path_conditions(content)

        rel_path = str(file_path.relative_to(base_dir) if file_path.is_relative_to(base_dir) else file_path)
        stem = file_path.stem
        assets: List[CryptoAsset] = []

        # 2. Inspect standard SPI calls
        for spi in JAVA_SPI_CALLS:
            pattern = re.compile(rf"\b{spi['class']}\.{spi['method']}\s*\(", re.MULTILINE)
            for m in pattern.finditer(content):
                open_paren_pos = m.end()
                args = self._extract_call_args_balanced(content, open_paren_pos)
                if not args:
                    continue

                raw_arg = args[0].strip()
                line_no = self.extract_line_number(content, m.start())
                matched_code = content[m.start():content.find(")", m.start()) + 1] if ")" in content[m.start():] else content[m.start():m.start() + 80]
                is_shred, tier = self.check_crypto_shredding_context(content, line_no)

                # Check if expression is dynamic/unresolvable
                if DYNAMIC_METHOD_RE.search(raw_arg):
                    assets.append(self.build_crypto_asset(
                        asset_prefix="SRC-JAVA",
                        index=len(assets) + 1,
                        component_name=f"{stem}:dynamic_unresolved",
                        algorithm="DYNAMIC_UNRESOLVED",
                        key_size=None,
                        primitive_type=spi["prim"],
                        file_path=rel_path,
                        line_number=line_no,
                        tier=XTier.HUMAN_REVIEW,
                        has_shredding=is_shred,
                        evidence_level=EvidenceLevel.E0_UNCONFIRMED,
                        evidence_source="java_contract:dynamic_quarantine",
                        matched_code=matched_code,
                        language="java",
                        cwe=None,
                        description=f"Dynamic unresolvable expression: {raw_arg}",
                        risk_level="MANUAL_REVIEW_REQUIRED",
                        extra_properties={
                            "ecdat:human_review_required": True,
                            "ecdat:risk_level": "MANUAL_REVIEW_REQUIRED",
                            "ecdat:dynamic_expression": raw_arg,
                            "ecdat:auditor_note": f"Dynamic crypto invocation cannot be statically verified (Expression: {raw_arg}). Manual verification required."
                        }
                    ))
                    continue

                resolved_arg = raw_arg
                if not any(q in raw_arg for q in ('"', "'")):
                    traced = self._trace_java_var(raw_arg, m.start(), content, file_path=file_path)
                    if traced:
                        resolved_arg = traced

                if resolved_arg.startswith("DYNAMIC_UNRESOLVED:"):
                    raw_expr = resolved_arg.split(":", 1)[1].strip()
                    assets.append(self.build_crypto_asset(
                        asset_prefix="SRC-JAVA",
                        index=len(assets) + 1,
                        component_name=f"{stem}:dynamic_unresolved",
                        algorithm="DYNAMIC_UNRESOLVED",
                        key_size=None,
                        primitive_type=spi["prim"],
                        file_path=rel_path,
                        line_number=line_no,
                        tier=XTier.HUMAN_REVIEW,
                        has_shredding=is_shred,
                        evidence_level=EvidenceLevel.E0_UNCONFIRMED,
                        evidence_source="java_contract:dynamic_quarantine",
                        matched_code=matched_code,
                        language="java",
                        cwe=None,
                        description=f"Dynamic unresolvable expression: {raw_expr}",
                        risk_level="MANUAL_REVIEW_REQUIRED",
                        extra_properties={
                            "ecdat:human_review_required": True,
                            "ecdat:risk_level": "MANUAL_REVIEW_REQUIRED",
                            "ecdat:dynamic_expression": raw_expr,
                            "ecdat:auditor_note": f"Dynamic crypto invocation cannot be statically verified (Expression: {raw_expr}). Manual verification required."
                        }
                    ))
                    continue

                clean_alg_name = resolved_arg.strip("\"'").split("/")[0].strip()
                alg_upper = clean_alg_name.upper()
                full_upper = resolved_arg.strip("\"'").upper()

                # SSLContext Protocol handling
                if spi["contract"] == "SSLContextSpi":
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
                elif spi["contract"] == "CipherSpi":
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
                        prim = PrimitiveType.KEY_EXCHANGE
                    else:
                        alg = clean_alg_name
                        key_size = 256
                        risk = "LOW"
                        cwe = None
                    prim = PrimitiveType.KEY_EXCHANGE if "RSA" in alg_upper else PrimitiveType.ENCRYPTION
                    desc = f"Java Cipher invocation ({alg})"
                elif spi["contract"] == "KeyGenerator":
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
                    elif "AES" in alg_upper:
                        alg = "AES-256"
                        key_size = 256
                        risk = "LOW"
                        cwe = None
                    elif "BLOWFISH" in alg_upper:
                        alg = "Blowfish-128"
                        key_size = 128
                        risk = "HIGH"
                        cwe = "CWE-327"
                    else:
                        alg = clean_alg_name
                        key_size = 256
                        risk = "LOW"
                        cwe = None

                    prefix = content[max(0, m.start() - 120):m.start()].strip()
                    m_var = re.search(r"([a-zA-Z0-9_]+)\s*=\s*$", prefix)
                    if m_var:
                        var_name = m_var.group(1)
                        m_init = re.search(r"\b" + re.escape(var_name) + r"\s*\.\s*(?:initialize|init)\s*\(\s*([^,)\s]+)", content[open_paren_pos:])
                        if m_init:
                            raw_keysize_arg = m_init.group(1).strip()
                            keysize_pos = open_paren_pos + m_init.start()
                            traced_keysize = self._trace_java_var(raw_keysize_arg, keysize_pos, content, file_path=file_path)
                            if traced_keysize and traced_keysize.isdigit():
                                val = int(traced_keysize)
                                key_size = val
                                if val < 128:
                                    alg = f"{alg_upper}-{val}"
                                    risk = "CRITICAL" if val <= 64 else "HIGH"
                                    cwe = "CWE-326"
                                    desc = f"Weak key size in KeyGenerator ({alg}, {val} bits < 128)"
                                else:
                                    alg = f"{alg_upper}-{val}"
                                    risk = "LOW"
                                    cwe = None
                                    desc = f"Java KeyGenerator invocation ({alg})"

                    prim = PrimitiveType.KEY_EXCHANGE
                    desc = f"Java KeyGenerator invocation ({alg})"
                elif spi["contract"] == "KeyPairGenerator":
                    prefix = content[max(0, m.start() - 120):m.start()].strip()
                    m_var = re.search(r"([a-zA-Z0-9_]+)\s*=\s*$", prefix)
                    init_keysize_val = None
                    if m_var:
                        var_name = m_var.group(1)
                        m_init = re.search(r"\b" + re.escape(var_name) + r"\s*\.\s*(?:initialize|init)\s*\(\s*([^,)\s]+)", content[open_paren_pos:])
                        if m_init:
                            raw_keysize_arg = m_init.group(1).strip()
                            keysize_pos = open_paren_pos + m_init.start()
                            traced_keysize = self._trace_java_var(raw_keysize_arg, keysize_pos, content, file_path=file_path)
                            if traced_keysize and traced_keysize.isdigit():
                                init_keysize_val = int(traced_keysize)

                    if "RSA" in alg_upper or "DSA" in alg_upper:
                        if init_keysize_val is not None:
                            key_size = init_keysize_val
                            if init_keysize_val < 2048:
                                alg = f"{alg_upper}-{init_keysize_val}"
                                risk = "CRITICAL" if init_keysize_val <= 1024 else "HIGH"
                                cwe = "CWE-326"
                                desc = f"Weak key size in KeyPairGenerator ({alg}, {init_keysize_val} bits < 2048)"
                            else:
                                alg = f"{alg_upper}-{init_keysize_val}"
                                risk = "LOW"
                                cwe = None
                                desc = f"Java KeyPairGenerator invocation ({alg})"
                        else:
                            alg = f"{alg_upper}-2048"
                            key_size = 2048
                            risk = "LOW"
                            cwe = None
                            desc = f"Java KeyPairGenerator invocation ({alg})"
                    elif "EC" in alg_upper:
                        if init_keysize_val is not None and init_keysize_val < 224:
                            alg = f"ECDSA-{init_keysize_val}"
                            key_size = init_keysize_val
                            risk = "HIGH"
                            cwe = "CWE-326"
                            desc = f"Weak key size in KeyPairGenerator ({alg}, {init_keysize_val} bits < 224)"
                        else:
                            alg = "ECDSA-256"
                            key_size = 256
                            risk = "LOW"
                            cwe = None
                            desc = f"Java KeyPairGenerator invocation ({alg})"
                    else:
                        alg = clean_alg_name
                        key_size = 256
                        risk = "LOW"
                        cwe = None
                        desc = f"Java KeyPairGenerator invocation ({alg})"
                    prim = PrimitiveType.SIGNATURE
                    desc = f"Java KeyPairGenerator invocation ({alg})"
                elif spi["contract"] == "MessageDigestSpi":
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
                elif spi["contract"] == "SignatureSpi":
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
                elif spi["contract"] == "MacSpi":
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
                    else:
                        alg = clean_alg_name
                        key_size = 256
                        risk = "LOW"
                        cwe = None
                    desc = f"Java Mac invocation ({alg})"
                else:
                    sig = self.db.lookup_symbol("java", spi["contract"], "getInstance")
                    if not sig:
                        sig = self.db.lookup_algorithm(clean_alg_name)
                    alg = clean_alg_name
                    prim = spi["prim"]
                    key_size = 256
                    cwe = None
                    risk = "LOW"
                    desc = f"Java {spi['contract']} invocation"

                assets.append(self.build_crypto_asset(
                    asset_prefix="SRC-JAVA",
                    index=len(assets) + 1,
                    component_name=f"{stem}:{alg.lower().replace('-', '_').replace(':', '_')}",
                    algorithm=alg,
                    key_size=key_size,
                    primitive_type=prim,
                    file_path=rel_path,
                    line_number=line_no,
                    tier=tier,
                    has_shredding=is_shred,
                    evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                    evidence_source=f"java_contract:{spi['contract']}",
                    matched_code=matched_code,
                    language="java",
                    cwe=cwe,
                    description=desc,
                    risk_level=risk
                ))

        # 3. Inspect SecretKeySpec for hardcoded / predictable keys
        for m in re.finditer(r"new\s+(?:javax\.crypto\.spec\.)?SecretKeySpec\s*\(\s*([^,]+),\s*([^)]+)\)", content):
            key_arg = m.group(1).strip()
            line_no = self.extract_line_number(content, m.start())
            is_shred, tier = self.check_crypto_shredding_context(content, line_no)
            has_dynamic_random = bool(
                re.search(r"nextBytes\s*\(\s*" + re.escape(key_arg) + r"\s*\)", content) or
                ("KeyGenerator" in content and "generateKey" in content)
            )
            traced_key = self._trace_java_var(key_arg, m.start(), content, file_path=file_path)
            has_static_key = bool(
                re.search(r"byte\s*(?:\[\s*\])?\s*" + re.escape(key_arg) + r"\s*(?:\[\s*\])?\s*=\s*(?:new\s+byte\s*\[\s*\]\s*)?\{", content) or
                re.search(r"String\s+" + re.escape(key_arg) + r"\s*=\s*[\"']", content) or
                re.search(r"\b" + re.escape(key_arg) + r"\s*=\s*[a-zA-Z0-9_.]*(?:getBytes|\.substring)\b", content) or
                re.search(r'String\s+[a-zA-Z0-9_]+\s*=\s*["\'][^"\']+["\']', content) or
                re.search(r"byte\s*(?:\[\s*\])?\s*[a-zA-Z0-9_]+\s*(?:\[\s*\])?\s*=\s*(?:new\s+byte\s*\[\s*\]\s*)?\{[0-9\s,xX\(\)byte\-]+\}", content) or
                re.search(re.escape(key_arg) + r"\[\s*\d+\s*\]\s*=\s*\d+", content) or
                (traced_key and any(c.isdigit() for c in traced_key))
            )
            if not has_static_key and file_path and file_path.parent.exists():
                for sib in file_path.parent.glob("*.java"):
                    if sib != file_path:
                        try:
                            s_txt = sib.read_text(encoding="utf-8", errors="replace")
                            if key_arg in s_txt:
                                if (re.search(r"byte\s*(?:\[\s*\])?\s*" + re.escape(key_arg) + r"\s*(?:\[\s*\])?\s*=\s*\{", s_txt) or
                                    re.search(r"String\s+[a-zA-Z0-9_]+\s*=\s*[\"'][^\"']+[\"']", s_txt)):
                                    has_static_key = True
                                    break
                        except Exception:
                            pass
            if has_static_key and not has_dynamic_random:
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
                    matched_code=m.group(0)[:80],
                    language="java",
                    cwe="CWE-321",
                    description="Hardcoded or predictable static key in SecretKeySpec",
                    risk_level="CRITICAL"
                ))

        # 4. Inspect PBEKeySpec for hardcoded password, static salt, and weak iterations
        has_secure_pwd_gen = bool(re.search(r"(?:random\.ints|ints\(\)|readPassword|getenv|System\.console)", content))
        for m in re.finditer(r"new\s+(?:javax\.crypto\.spec\.)?PBEKeySpec\s*\(\s*((?:[^,()]|\([^()]*\))+)(?:,\s*((?:[^,()]|\([^()]*\))+))?(?:,\s*((?:[^,()]|\([^()]*\))+))?", content):
            pass_arg = m.group(1).strip()
            salt_arg = m.group(2).strip() if m.group(2) else None
            count_arg = m.group(3).strip() if m.group(3) else None
            line_no = self.extract_line_number(content, m.start())
            is_shred, tier = self.check_crypto_shredding_context(content, line_no)

            is_dynamic_pass = (
                has_secure_pwd_gen or
                (pass_arg == "password" and "getPassword" in content) or
                "readPassword" in content or
                "console" in content.lower()
            )
            has_static_pass = bool(
                re.search(r'String\s+' + re.escape(pass_arg) + r'\s*=\s*["\'][^"\']+["\']', content) or
                re.search(r'String\s+defaultKey\s*=\s*["\'][^"\']+["\']', content) or
                re.search(r'["\'][a-zA-Z0-9_\-\.\$]{4,}["\']', pass_arg)
            )
            if not is_dynamic_pass and (has_static_pass or not any(x in pass_arg.lower() for x in ["getpassword", "arg", "param", "passcode"])):
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
                    matched_code=m.group(0)[:80],
                    language="java",
                    cwe="CWE-798",
                    description="Hardcoded static password in PBEKeySpec",
                    risk_level="CRITICAL"
                ))

            if salt_arg:
                has_dynamic_salt = bool(
                    re.search(r"nextBytes\s*\(\s*" + re.escape(salt_arg) + r"\s*\)", content) or
                    "SecureRandom" in content
                )
                if not has_dynamic_salt:
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
                        matched_code=m.group(0)[:80],
                        language="java",
                        cwe="CWE-326",
                        description="Static or predictable salt in PBEKeySpec",
                        risk_level="HIGH"
                    ))

            traced_count = self._trace_java_var(count_arg, m.start(), content, file_path=file_path) if count_arg else None
            count_val = None
            if count_arg and count_arg.strip().isdigit():
                count_val = int(count_arg.strip())
            elif traced_count and traced_count.isdigit():
                count_val = int(traced_count)

            if count_val is not None and count_val <= 1000:
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
                    matched_code=m.group(0)[:80],
                    language="java",
                    cwe="CWE-326",
                    description=f"Weak PBE iteration count ({count_val} <= 1000)",
                    risk_level="HIGH"
                ))

        # 4.5 Inspect PBEParameterSpec for static salt and weak iterations
        for m in re.finditer(r"new\s+(?:javax\.crypto\.spec\.)?PBEParameterSpec\s*\(\s*([^,]+),\s*([^)]+)\)", content):
            salt_arg = m.group(1).strip()
            count_arg = m.group(2).strip()
            line_no = self.extract_line_number(content, m.start())
            is_shred, tier = self.check_crypto_shredding_context(content, line_no)

            traced_salt = self._trace_java_var(salt_arg, m.start(), content, file_path=file_path)
            has_dynamic_salt = bool(
                re.search(r"nextBytes\s*\(\s*" + re.escape(salt_arg) + r"\s*\)", content) or
                (traced_salt and "random" in traced_salt.lower())
            )
            is_static_salt = bool(
                not has_dynamic_salt and (
                    re.search(r"byte\s*(?:\[\s*\])?\s*" + re.escape(salt_arg) + r"\s*(?:\[\s*\])?\s*=\s*(?:new\s+byte\s*\[\s*\]\s*)?\{", content) or
                    re.search(r"new\s+byte\s*\[\s*\]\s*\{", salt_arg) or
                    (traced_salt and any(c.isdigit() for c in traced_salt)) or
                    "Identity" in salt_arg
                )
            )
            if is_static_salt or not has_dynamic_salt:
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
                    matched_code=m.group(0)[:80],
                    language="java",
                    cwe="CWE-326",
                    description="Static or predictable salt in PBEParameterSpec",
                    risk_level="HIGH"
                ))

            traced_count = self._trace_java_var(count_arg, m.start(), content, file_path=file_path)
            count_val = None
            if count_arg.isdigit():
                count_val = int(count_arg)
            elif traced_count and traced_count.isdigit():
                count_val = int(traced_count)

            if count_val is not None and count_val <= 1000:
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
                    matched_code=m.group(0)[:80],
                    language="java",
                    cwe="CWE-326",
                    description=f"Weak PBE iteration count ({count_val} <= 1000)",
                    risk_level="HIGH"
                ))

        # KeyStore.load hardcoded passwords
        for m in re.finditer(r"\.load\s*\([^,]+,\s*([^)]+)\)", content):
            pass_arg = m.group(1).strip()
            line_no = self.extract_line_number(content, m.start())
            is_shred, tier = self.check_crypto_shredding_context(content, line_no)
            if pass_arg != "null" and not has_secure_pwd_gen:
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
                    matched_code=m.group(0)[:80],
                    language="java",
                    cwe="CWE-798",
                    description="Predictable keystore password in KeyStore.load",
                    risk_level="HIGH"
                ))

        # 5. Inspect IvParameterSpec for static IV
        for m in re.finditer(r"new\s+(?:javax\.crypto\.spec\.)?IvParameterSpec\s*\(([^)]+)\)", content):
            line_no = self.extract_line_number(content, m.start())
            is_shred, tier = self.check_crypto_shredding_context(content, line_no)
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
                matched_code=m.group(0)[:80],
                language="java",
                cwe="CWE-329",
                description="Static or predictable IV in IvParameterSpec",
                risk_level="HIGH"
            ))

        # 6. Inspect SecureRandom for static seed
        # Check constructor new SecureRandom(seed) with non-empty argument
        for m in re.finditer(r"new\s+(?:java\.security\.)?SecureRandom\s*\(\s*([^)]+)\)", content):
            seed_arg = m.group(1).strip()
            if not seed_arg:
                continue
            line_no = self.extract_line_number(content, m.start())
            is_shred, tier = self.check_crypto_shredding_context(content, line_no)
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
                evidence_source="java_contract:SecureRandom_constructor_seed",
                matched_code=m.group(0)[:80],
                language="java",
                cwe="CWE-330",
                description="Predictable seed passed to SecureRandom constructor",
                risk_level="HIGH"
            ))

        for m in re.finditer(r"(?:[a-zA-Z0-9_]+)\.setSeed\s*\(\s*([^)]+)\)", content):
            seed_arg = m.group(1).strip()
            line_no = self.extract_line_number(content, m.start())
            is_shred, tier = self.check_crypto_shredding_context(content, line_no)
            traced_seed = self._trace_java_var(seed_arg, m.start(), content, file_path=file_path)
            is_dynamic_seed = bool(
                (traced_seed and any(k in traced_seed for k in ["getInstanceStrong", "randomBytes", "nextLong"])) or
                re.search(r"getInstanceStrong\(\)", seed_arg)
            )
            if not is_dynamic_seed:
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
                    matched_code=m.group(0)[:80],
                    language="java",
                    cwe="CWE-330",
                    description="Predictable seed used in SecureRandom.setSeed",
                    risk_level="HIGH"
                ))
            else:
                assets.append(self.build_crypto_asset(
                    asset_prefix="SRC-JAVA",
                    index=len(assets) + 1,
                    component_name=f"{stem}:dynamic_seed",
                    algorithm="SECURE-PRNG",
                    key_size=None,
                    primitive_type=PrimitiveType.KEY_EXCHANGE,
                    file_path=rel_path,
                    line_number=line_no,
                    tier=tier,
                    has_shredding=is_shred,
                    evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
                    evidence_source="java_contract:SecureRandom_dynamic_seed",
                    matched_code=m.group(0)[:80],
                    language="java",
                    cwe=None,
                    description="Secure dynamic seed for SecureRandom",
                    risk_level="LOW"
                ))

        # 7. Inspect X509TrustManager and HostnameVerifier
        if re.search(r"checkServerTrusted\s*\([^\)]*\)\s*\{\s*\}", content) or re.search(r"class\s+\w+\s+implements\s+X509TrustManager", content):
            m_tm = re.search(r"checkServerTrusted\s*\([^)]*\)(?:\s*throws\s+[^{]+)?\s*\{([\s\S]*?)\n\s*\}", content)
            is_dummy = True
            if m_tm:
                body = m_tm.group(1).strip()
                if "throw" in body or "validate" in body or "verify" in body:
                    is_dummy = False
            if is_dummy:
                line_no = 1
                is_shred, tier = self.check_crypto_shredding_context(content, line_no)
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

        has_hv_interface = bool(
            re.search(r"\bimplements\s+[^{]*\bHostnameVerifier\b", content) or
            re.search(r"\bnew\s+HostnameVerifier\s*\(", content) or
            "HostnameVerifier" in content
        )
        if re.search(r"verify\s*\([^\)]*\)\s*\{[\s\S]*?\breturn\s+true\s*;", content) and has_hv_interface:
            line_no = 1
            is_shred, tier = self.check_crypto_shredding_context(content, line_no)
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
        elif re.search(r"class\s+\w+\s+implements\s+HostnameVerifier", content) or "setDefaultHostnameVerifier" in content:
            line_no = 1
            is_shred, tier = self.check_crypto_shredding_context(content, line_no)
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

        # 8. Inspect SSLSocketFactory.getDefault()
        if re.search(r"SSLSocketFactory\.getDefault\(\)", content):
            line_no = 1
            is_shred, tier = self.check_crypto_shredding_context(content, line_no)
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

        # 9. Inspect cleartext HTTP communication
        for m in re.finditer(r"new\s+URL\s*\(\s*[\"']http://|String\s+[a-zA-Z0-9_]*url\s*=\s*[\"']http://|[\"']http://(?!schemas\.|www\.w3\.org|java\.sun\.com)[a-zA-Z0-9_\.\-:/]+[\"']", content, re.IGNORECASE):
            line_no = self.extract_line_number(content, m.start())
            is_shred, tier = self.check_crypto_shredding_context(content, line_no)
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
                matched_code=m.group(0)[:80],
                language="java",
                cwe="CWE-319",
                description="Cleartext unencrypted HTTP communication channel",
                risk_level="HIGH"
            ))

        # 10. Inspect PRNG usage
        if re.search(r"new\s+Random\s*\(\s*\)", content) and (
            "PBEParameterSpec" in content or
            "randomBytes" in content or
            "session" in content.lower() or
            "nonce" in content.lower() or
            "DigestAuthentication" in content
        ):
            line_no = 1
            is_shred, tier = self.check_crypto_shredding_context(content, line_no)
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
                matched_code="new Random() used for cryptographic parameter generation",
                language="java",
                cwe="CWE-338",
                description="Untrusted pseudo-random number generator (java.util.Random) in cryptographic context",
                risk_level="MEDIUM"
            ))
        elif (re.search(r"new\s+SecureRandom\s*\(\s*\)|SecureRandom\.getInstanceStrong\(\)", content) and
              not re.search(r"\.setSeed\s*\(", content) and
              not re.search(r"new\s+SecureRandom\s*\(\s*[^)]+\)", content)):
            m_sr = re.search(r"new\s+SecureRandom\s*\(\s*\)|SecureRandom\.getInstanceStrong\(\)", content)
            line_no = self.extract_line_number(content, m_sr.start()) if m_sr else 1
            is_shred, tier = self.check_crypto_shredding_context(content, line_no)
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
                matched_code=m_sr.group(0)[:80] if m_sr else "new SecureRandom()",
                language="java",
                cwe=None,
                description="Secure pseudo-random number generator (java.security.SecureRandom)",
                risk_level="LOW"
            ))

        return assets
