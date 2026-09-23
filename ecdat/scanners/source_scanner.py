"""
ECDAT Polyglot Source Code Cryptographic Scanner:
Statically discovers in-code cryptographic primitive invocations across
JavaScript/TypeScript (.js, .mjs, .cjs, .ts), Go (.go), Rust (.rs), Java (.java),
Python (.py), and Ruby (.rb) leveraging formal, non-regex contract engines and AST analysis.
"""

import os
from pathlib import Path
from typing import List, Dict, Any, Optional, Tuple, Set

from ecdat.models import CryptoAsset, PrimitiveType, XTier, EvidenceLevel, IntentClass, AgilityLevel
from ecdat.intent.classifier import classify_intent
from ecdat.agility.cams_detector import detect_cams_agility
from ecdat.scanners.filters import should_scan_file
from ecdat.scanners.contracts.javascript_contracts import JavaScriptContractEngine
from ecdat.scanners.contracts.rust_contracts import RustContractEngine
from ecdat.scanners.contracts.go_contracts import GoContractEngine
from ecdat.scanners.contracts.ruby_contracts import RubyContractEngine
from ecdat.scanners.contracts.java_contracts import JavaContractEngine
from ecdat.scanners.contracts.python_contracts import PythonContractEngine

EXCLUDED_DIRS = {
    "venv", ".venv", "env", "node_modules", "site-packages",
    "__pycache__", ".git", "dist", "build", "target", ".cache",
    ".agents", ".gemini", ".antigravity", ".codex", ".superpowers", "agents"
}

# Instantiate Singleton Contract Engines (All Lexer/AST-driven, zero regex)
_js_engine = JavaScriptContractEngine()
_rust_engine = RustContractEngine()
_go_engine = GoContractEngine()
_ruby_engine = RubyContractEngine()
_java_engine = JavaContractEngine()
_python_engine = PythonContractEngine()

def scan_javascript_file(file_path: Path, base_dir: Path) -> List[CryptoAsset]:
    """Scans a JavaScript/TypeScript source file using token-driven contract engine."""
    return _js_engine.scan_file(file_path, base_dir)

def scan_rust_file(file_path: Path, base_dir: Path) -> List[CryptoAsset]:
    """Scans a Rust source file using token-driven contract engine."""
    return _rust_engine.scan_file(file_path, base_dir)

def scan_go_file(file_path: Path, base_dir: Path) -> List[CryptoAsset]:
    """Scans a Go source file for in-code crypto operations using contract invariance."""
    return _go_engine.scan_file(file_path, base_dir)

def scan_ruby_file(file_path: Path, base_dir: Path) -> List[CryptoAsset]:
    """Scans a Ruby source file for in-code crypto operations using OpenSSL contracts."""
    return _ruby_engine.scan_file(file_path, base_dir)

def scan_java_file(file_path: Path, base_dir: Path) -> List[CryptoAsset]:
    """Scans a Java source file for JCA/JCE in-code crypto operations using contract invariance."""
    return _java_engine.scan_file(file_path, base_dir)

def scan_python_file(file_path: Path, base_dir: Path) -> List[CryptoAsset]:
    """Scans a Python source file for in-code crypto operations using native AST contract engine."""
    return _python_engine.scan_file(file_path, base_dir)

def discover_polyglot_crypto_assets(target_dir: str) -> List[CryptoAsset]:
    """
    Recursively scans target_dir for in-code cryptographic operations across
    JavaScript (.js, .mjs, .cjs, .ts), Go (.go), Rust (.rs), Java (.java),
    Python (.py), and Ruby (.rb) via pure contract engines.
    """
    target_path = Path(target_dir).resolve()
    if not target_path.exists():
        return []

    all_assets: List[CryptoAsset] = []
    seen_keys: Set[str] = set()

    for p in sorted(target_path.glob("**/*")):
        if not p.is_file():
            continue
        rel = p.relative_to(target_path) if p.is_relative_to(target_path) else p
        if any((part.startswith(".") and part != ".") or part.lower() in EXCLUDED_DIRS for part in rel.parts[:-1]):
            continue
        if not should_scan_file(str(p), base_dir=str(target_path)):
            continue

        file_assets: List[CryptoAsset] = []
        suffix = p.suffix.lower()

        if suffix in {".js", ".mjs", ".cjs", ".ts"}:
            file_assets = scan_javascript_file(p, target_path)
        elif suffix == ".go":
            file_assets = scan_go_file(p, target_path)
        elif suffix == ".rs":
            file_assets = scan_rust_file(p, target_path)
        elif suffix == ".java":
            file_assets = scan_java_file(p, target_path)
        elif suffix == ".rb":
            file_assets = scan_ruby_file(p, target_path)
        elif suffix == ".py":
            file_assets = scan_python_file(p, target_path)

        for a in file_assets:
            dedup_key = f"{a.file_path}:{a.algorithm}:{a.primitive_type.value}:{a.line_number}"
            if dedup_key in seen_keys:
                continue
            seen_keys.add(dedup_key)
            all_assets.append(a)

    for idx, a in enumerate(all_assets, start=1):
        a.asset_id = f"SRC-CRYPTO-{idx:03d}"
        if a.agility_level == AgilityLevel.RIGID:
            matched = a.raw_properties.get("matched_code", "")
            if matched:
                lvl, desc = detect_cams_agility(matched)
                if lvl != AgilityLevel.RIGID:
                    a.agility_level = lvl
                    a.raw_properties["cams_evidence"] = desc

    return all_assets
