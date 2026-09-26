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

import concurrent.futures

def _scan_single_file_dispatch(file_path: Path, base_dir: Path) -> List[CryptoAsset]:
    """Dispatches a single source file to its corresponding contract engine."""
    suffix = file_path.suffix.lower()
    if suffix in {".js", ".mjs", ".cjs", ".ts"}:
        return scan_javascript_file(file_path, base_dir)
    elif suffix == ".go":
        return scan_go_file(file_path, base_dir)
    elif suffix == ".rs":
        return scan_rust_file(file_path, base_dir)
    elif suffix == ".java":
        return scan_java_file(file_path, base_dir)
    elif suffix == ".rb":
        return scan_ruby_file(file_path, base_dir)
    elif suffix == ".py":
        return scan_python_file(file_path, base_dir)
    return []

def _scan_file_batch(args: Tuple[List[Path], Path]) -> List[CryptoAsset]:
    """Worker function for batch file processing in worker processes."""
    file_paths, base_dir = args
    results: List[CryptoAsset] = []
    for fp in file_paths:
        try:
            file_assets = _scan_single_file_dispatch(fp, base_dir)
            if file_assets:
                results.extend(file_assets)
        except Exception:
            continue
    return results

def discover_polyglot_crypto_assets(target_dir: str) -> List[CryptoAsset]:
    """
    Recursively scans target_dir for in-code cryptographic operations across
    JavaScript (.js, .mjs, .cjs, .ts), Go (.go), Rust (.rs), Java (.java),
    Python (.py), and Ruby (.rb) via pure contract engines.
    Employs multi-core batch chunking for enterprise repos.
    """
    target_path = Path(target_dir).resolve()
    if not target_path.exists():
        return []

    candidate_files: List[Path] = []
    for p in sorted(target_path.glob("**/*")):
        if not p.is_file():
            continue
        rel = p.relative_to(target_path) if p.is_relative_to(target_path) else p
        if any((part.startswith(".") and part != ".") or part.lower() in EXCLUDED_DIRS for part in rel.parts[:-1]):
            continue
        if not should_scan_file(str(p), base_dir=str(target_path)):
            continue
        candidate_files.append(p)

    raw_assets: List[CryptoAsset] = []

    # Parallelize when scanning more than 12 files
    if len(candidate_files) > 12:
        cpu_count = os.cpu_count() or 4
        max_workers = min(8, max(1, cpu_count))
        chunk_size = max(10, len(candidate_files) // (max_workers * 4))
        chunks = [
            (candidate_files[i:i + chunk_size], target_path)
            for i in range(0, len(candidate_files), chunk_size)
        ]
        try:
            with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as executor:
                for batch_result in executor.map(_scan_file_batch, chunks):
                    raw_assets.extend(batch_result)
        except Exception:
            # Fallback to sequential scanning if multiprocessing is unavailable
            for p in candidate_files:
                raw_assets.extend(_scan_single_file_dispatch(p, target_path))
    else:
        for p in candidate_files:
            raw_assets.extend(_scan_single_file_dispatch(p, target_path))

    all_assets: List[CryptoAsset] = []
    seen_keys: Set[str] = set()

    for a in raw_assets:
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
