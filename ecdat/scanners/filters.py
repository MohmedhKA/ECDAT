"""
ECDAT Path and File Exclusion Filters:
Provides generalized filtering to exclude non-production documentation, research notes,
environment sample templates, developer test fixtures, and build caches across any codebase.
"""

import os
import re
from pathlib import Path
from typing import Set, Optional

# Generalized directory names to always exclude from cryptographic asset discovery
EXCLUDED_DIR_NAMES: Set[str] = {
    # Virtual environments & dependencies
    "venv", ".venv", "env", "node_modules", "site-packages", "vendor",
    # Version control & caches
    ".git", ".svn", ".hg", "__pycache__", ".pytest_cache", ".cache",
    # Build artifacts & package outputs
    "dist", "build", "target", "out", ".next", ".nuxt", "coverage",
    # Documentation & research scratchpads
    "docs", "documentation", "Research", "research", "reports", "benchmarks",
    # Test fixture & mock directories
    "fixtures", "mocks", "mock", "testdata", "test_fixtures",
}

# Regex patterns matching file paths that should not be cataloged as active cryptographic assets
EXCLUDED_PATH_PATTERNS = [
    # Environment templates and sample configs (never contain real active production keys)
    r"(^|/)\.env\.(example|sample|template|test|local|dev|stage|dist)$",
    # Static test/sample keypair files and mock certificates
    r"(^|/)keys?/.*-(?:keypair|mock|sample|test)\.(?:json|pem|key|crt)$",
    r"(^|/)tests?/.*(?:fixture|sample|mock).*\.(?:json|pem|key|crt)$",
    # Generic documentation and markdown notes (unless specifically scanned as code)
    r"\.(?:md|markdown|rst|txt|pdf|docx|pptx|png|jpg|jpeg|svg|gif)$",
]

COMPILED_PATTERNS = [re.compile(p, re.IGNORECASE) for p in EXCLUDED_PATH_PATTERNS]

def should_scan_file(file_path: str, base_dir: Optional[str] = None) -> bool:
    """
    Determines if a file should be included in cryptographic scanning.
    Returns False for documentation, build caches, test mocks, and environment templates.
    """
    p = Path(file_path)
    if base_dir:
        try:
            p = p.resolve().relative_to(Path(base_dir).resolve())
        except ValueError:
            pass

    # 1. Check directory components (excluding filename)
    dir_parts = set(p.parts[:-1]) if len(p.parts) > 1 else set()
    if dir_parts.intersection(EXCLUDED_DIR_NAMES):
        return False

    for part in dir_parts:
        if part.lower() in EXCLUDED_DIR_NAMES:
            return False

    # 2. Whitelist standard package manifests that use .txt extension
    if p.name.lower().startswith("requirements") and p.suffix.lower() == ".txt":
        return True

    # 3. Check regex patterns against normalized path string
    norm_path = str(p).replace("\\", "/")
    for pattern in COMPILED_PATTERNS:
        if pattern.search(norm_path):
            return False

    return True
