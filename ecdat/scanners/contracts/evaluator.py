"""
ECDAT AST Call-Site Bifurcation Evaluator:
Provides zero-regex syntactic evaluation of cryptographic invocation parameters.
Bifurcates expressions into:
1. StaticResolution (Closed-World Constant Folding): .replace(), string addition, .toUpperCase(), etc. -> Routed to CBOM.
2. DynamicIngress (Open-World Ingress): process.env, config.get(), database rows, parameters -> Routed to Father Marko Lineage.
Strictly zero-regex: operates exclusively on Pygments token streams and AST token structures.
"""

from dataclasses import dataclass
from typing import List, Tuple, Optional, Any
from pygments.token import Token


@dataclass
class StaticResolution:
    """Represents a closed-world constant expression evaluated to a concrete string."""
    value: str
    is_static: bool = True


@dataclass
class DynamicIngress:
    """Represents an open-world external parameter binding."""
    source_type: str        # 'ENV', 'CONFIG', 'DATABASE', 'PARAMETER'
    key_name: str           # e.g., 'VOTE_CIPHER_SUITE', 'security.mode'
    fallback_value: Optional[str] = None
    is_static: bool = False


class CallSiteEvaluator:
    """
    Zero-regex token-stream evaluator for call-site arguments.
    Operates on Pygments (ttype, value) or (ttype, value, offset) token tuples.
    """

    @staticmethod
    def _strip_quotes(s: str) -> str:
        """Strips surrounding single, double, or backtick quotes without regex."""
        if (s.startswith("'") and s.endswith("'")) or \
           (s.startswith('"') and s.endswith('"')) or \
           (s.startswith('`') and s.endswith('`')):
            return s[1:-1]
        return s

    @classmethod
    def evaluate_argument_tokens(
        cls,
        tokens: List[Tuple[Any, ...]],
        start_idx: int,
        max_lookahead: int = 35
    ) -> Tuple[Optional[Any], int]:
        """
        Evaluates the argument expression starting at start_idx.
        Returns (StaticResolution | DynamicIngress | None, next_token_idx).
        """
        n_tokens = len(tokens)
        if start_idx >= n_tokens:
            return None, start_idx

        # Pre-filter non-whitespace tokens in the lookahead window
        limit = min(n_tokens, start_idx + max_lookahead)
        clean_tokens = []
        clean_indices = []

        for i in range(start_idx, limit):
            tok_val = tokens[i][1]
            if tok_val.strip() != "":
                clean_tokens.append((tokens[i][0], tok_val))
                clean_indices.append(i)

        if not clean_tokens:
            return None, start_idx

        n_clean = len(clean_tokens)

        # -------------------------------------------------------------
        # Branch A: Check for Ingress Patterns (process.env, config, DB)
        # -------------------------------------------------------------
        ttype0, val0 = clean_tokens[0]

        # A1: process.env.KEY or process.env['KEY']
        if val0 == "process" and n_clean >= 3:
            if clean_tokens[1][1] == "." and clean_tokens[2][1] == "env":
                # process.env.KEY
                if n_clean >= 5 and clean_tokens[3][1] == ".":
                    key_name = clean_tokens[4][1]
                    fallback = cls._check_fallback_clean(clean_tokens, 5)
                    next_idx = clean_indices[4] + 1
                    return DynamicIngress(source_type="ENV", key_name=key_name, fallback_value=fallback), next_idx
                # process.env['KEY']
                elif n_clean >= 5 and clean_tokens[3][1] == "[":
                    key_name = cls._strip_quotes(clean_tokens[4][1])
                    end_clean_idx = 5
                    if n_clean >= 6 and clean_tokens[5][1] == "]":
                        end_clean_idx = 6
                    fallback = cls._check_fallback_clean(clean_tokens, end_clean_idx)
                    next_idx = clean_indices[end_clean_idx - 1] + 1
                    return DynamicIngress(source_type="ENV", key_name=key_name, fallback_value=fallback), next_idx

        # A2: os.environ['KEY'] or os.getenv('KEY')
        if val0 == "os" and n_clean >= 3:
            sub = clean_tokens[2][1]
            if clean_tokens[1][1] == "." and sub in {"environ", "getenv"}:
                if n_clean >= 5 and clean_tokens[3][1] in {"[", "("}:
                    key_name = cls._strip_quotes(clean_tokens[4][1])
                    end_clean_idx = 5
                    if n_clean >= 6 and clean_tokens[5][1] in {"]", ")"}:
                        end_clean_idx = 6
                    fallback = cls._check_fallback_clean(clean_tokens, end_clean_idx)
                    next_idx = clean_indices[end_clean_idx - 1] + 1
                    return DynamicIngress(source_type="ENV", key_name=key_name, fallback_value=fallback), next_idx

        # A3: System.getenv("KEY") in Java
        if val0 == "System" and n_clean >= 5:
            if clean_tokens[1][1] == "." and clean_tokens[2][1] == "getenv" and clean_tokens[3][1] == "(":
                key_name = cls._strip_quotes(clean_tokens[4][1])
                next_idx = clean_indices[min(5, n_clean - 1)] + 1
                return DynamicIngress(source_type="ENV", key_name=key_name), next_idx

        # A4: config.get("key.path") or app.config["KEY"]
        if val0 in {"config", "appConfig", "app_config", "settings"} and n_clean >= 3:
            op = clean_tokens[1][1]
            if op == "." and n_clean >= 5 and clean_tokens[2][1] == "get" and clean_tokens[3][1] == "(":
                keypath = cls._strip_quotes(clean_tokens[4][1])
                next_idx = clean_indices[min(5, n_clean - 1)] + 1
                return DynamicIngress(source_type="CONFIG", key_name=keypath), next_idx
            elif op == "[" and n_clean >= 3:
                keypath = cls._strip_quotes(clean_tokens[2][1])
                next_idx = clean_indices[min(3, n_clean - 1)] + 1
                return DynamicIngress(source_type="CONFIG", key_name=keypath), next_idx

        # A5: Database row access: row.algorithm, record.cipher, tenant.crypto_mode
        if val0 in {"row", "record", "doc", "tenant", "entity"} and n_clean >= 3:
            if clean_tokens[1][1] == ".":
                prop = clean_tokens[2][1]
                next_idx = clean_indices[2] + 1
                return DynamicIngress(source_type="DATABASE", key_name=f"{val0}.{prop}"), next_idx

        # -------------------------------------------------------------
        # Branch B: Closed-World Constant Folding (.replace, +, .toUpperCase)
        # -------------------------------------------------------------
        if ttype0 in Token.Literal.String or val0.startswith(("'","\"", "`")):
            term_val, last_clean_idx = cls._evaluate_string_term(clean_tokens, 0, n_clean)
            if term_val is not None:
                # Handle string concatenations (+)
                idx = last_clean_idx
                while idx < n_clean and clean_tokens[idx][1] == "+":
                    next_val, next_last = cls._evaluate_string_term(clean_tokens, idx + 1, n_clean)
                    if next_val is not None:
                        term_val += next_val
                        idx = next_last
                    else:
                        break

                orig_next_idx = clean_indices[min(idx, n_clean - 1)] + 1
                return StaticResolution(value=term_val), orig_next_idx

        # -------------------------------------------------------------
        # Branch C: Single Identifier / Parameter (e.g., customCipher)
        # -------------------------------------------------------------
        if ttype0 in Token.Name and val0 not in {",", ")", ";", "}"}:
            orig_next_idx = clean_indices[0] + 1
            return DynamicIngress(source_type="PARAMETER", key_name=val0), orig_next_idx

        return None, start_idx + 1

    @classmethod
    def _evaluate_string_term(
        cls,
        clean_tokens: List[Tuple[Any, str]],
        start: int,
        limit: int
    ) -> Tuple[Optional[str], int]:
        """Evaluates a single string literal followed by any chained methods."""
        if start >= limit:
            return None, start

        ttype, val = clean_tokens[start]
        if not (ttype in Token.Literal.String or val.startswith(("'", '"', '`'))):
            return None, start

        cur = cls._strip_quotes(val)
        idx = start + 1

        while idx < limit:
            if clean_tokens[idx][1] == "." and idx + 1 < limit:
                method = clean_tokens[idx + 1][1]
                # Method 1: .replace(target, replacement)
                if method == "replace" and idx + 5 < limit and clean_tokens[idx + 2][1] == "(":
                    target = cls._strip_quotes(clean_tokens[idx + 3][1])
                    if clean_tokens[idx + 4][1] == ",":
                        repl = cls._strip_quotes(clean_tokens[idx + 5][1])
                        cur = cur.replace(target, repl)
                        k = idx + 6
                        while k < limit and clean_tokens[k][1] != ")":
                            k += 1
                        idx = k + 1
                        continue
                # Method 2: .toUpperCase() / .upper()
                elif method in {"toUpperCase", "upper"} and idx + 2 < limit and clean_tokens[idx + 2][1] == "(":
                    cur = cur.upper()
                    idx = idx + 4 if idx + 3 < limit and clean_tokens[idx + 3][1] == ")" else idx + 3
                    continue
                # Method 3: .toLowerCase() / .lower()
                elif method in {"toLowerCase", "lower"} and idx + 2 < limit and clean_tokens[idx + 2][1] == "(":
                    cur = cur.lower()
                    idx = idx + 4 if idx + 3 < limit and clean_tokens[idx + 3][1] == ")" else idx + 3
                    continue
                # Method 4: .trim() / .strip()
                elif method in {"trim", "strip"} and idx + 2 < limit and clean_tokens[idx + 2][1] == "(":
                    cur = cur.strip()
                    idx = idx + 4 if idx + 3 < limit and clean_tokens[idx + 3][1] == ")" else idx + 3
                    continue
            break

        return cur, idx

    @classmethod
    def _check_fallback_clean(cls, clean_tokens: List[Tuple[Any, str]], start_idx: int) -> Optional[str]:
        """Checks for default value in ternary or logical OR within clean tokens."""
        n = len(clean_tokens)
        idx = start_idx
        while idx < n:
            val = clean_tokens[idx][1]
            if val == "||" and idx + 1 < n:
                return cls._strip_quotes(clean_tokens[idx + 1][1])
            elif val == ":" and idx + 1 < n:
                return cls._strip_quotes(clean_tokens[idx + 1][1])
            elif val in {",", ")", ";"}:
                break
            idx += 1
        return None
