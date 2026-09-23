"""
Tests for ECDAT 1-Click Code Remediation Engine & Journal:
Verifies:
1. Remediation of weak symmetric ciphers (AES-128-CBC -> AES-256-GCM).
2. Remediation of broken hash algorithms (MD5 / SHA-1 -> SHA-256).
3. Remediation of Java Cipher instances (DES/CBC -> AES/GCM).
4. Dry-run diff generation without altering source files.
5. Atomic disk writes and cryptographic before/after SHA-256 verification.
6. Safe, reversible Undo and Redo operations.
7. External tampering detection (preventing undo when file modified externally).
8. Strict zero-regex rule compliance.
"""

import json
from pathlib import Path
import pytest

from ecdat.models import CryptoAsset, PrimitiveType, XTier, IntentClass
from ecdat.remediation.journal import RemediationJournal
from ecdat.remediation.engine import RemediationEngine


def test_remediation_symmetric_aes_cbc_to_gcm(tmp_path):
    src_file = tmp_path / "cipher_service.js"
    src_file.write_text("const cipher = crypto.createCipheriv('aes-128-cbc', key, iv);\n", encoding="utf-8")

    asset = CryptoAsset(
        asset_id="ASSET-001",
        component_name="crypto.createCipheriv",
        algorithm="AES-128-CBC",
        primitive_type=PrimitiveType.SYMMETRIC_CIPHER,
        file_path=str(src_file),
        line_number=1,
        x_tier=XTier.OPERATIONAL,
        intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
    )

    journal_path = tmp_path / ".ecdat_journal.json"
    engine = RemediationEngine(journal_path=journal_path)

    # 1. Apply remediation
    tx = engine.remediate_asset(asset, target_file=src_file, mode="safe_classical")
    assert tx is not None
    assert tx["status"] == "APPLIED"
    assert "aes-256-gcm" in src_file.read_text(encoding="utf-8")

    # 2. Undo
    undo_ok = engine.undo_last()
    assert undo_ok is True
    reverted_content = src_file.read_text(encoding="utf-8")
    assert "aes-128-cbc" in reverted_content

    # 3. Redo
    redo_ok = engine.redo_last()
    assert redo_ok is True
    assert "aes-256-gcm" in src_file.read_text(encoding="utf-8")


def test_dry_run_does_not_modify_file(tmp_path):
    src_file = tmp_path / "hasher.py"
    original = "import hashlib\nh = hashlib.md5(data).hexdigest()\n"
    src_file.write_text(original, encoding="utf-8")

    journal_path = tmp_path / ".ecdat_journal.json"
    engine = RemediationEngine(journal_path=journal_path)

    patch = engine.generate_patch(src_file, rule="REPLACE_MD5_SHA256")
    assert patch.has_changes is True
    assert "hashlib.sha256" in patch.patched_content
    assert "-" in patch.diff and "+" in patch.diff

    # File on disk must remain completely unchanged
    assert src_file.read_text(encoding="utf-8") == original


def test_remediation_java_cipher_instance(tmp_path):
    src_file = tmp_path / "CryptoHelper.java"
    java_code = (
        "package com.example;\n"
        "import javax.crypto.Cipher;\n"
        "public class CryptoHelper {\n"
        "    Cipher c = Cipher.getInstance(\"AES/CBC/PKCS5Padding\");\n"
        "}\n"
    )
    src_file.write_text(java_code, encoding="utf-8")

    journal_path = tmp_path / ".ecdat_journal.json"
    engine = RemediationEngine(journal_path=journal_path)

    patch = engine.generate_patch(src_file, rule="REPLACE_CBC_GCM")
    assert patch.has_changes is True
    assert "AES/GCM/NoPadding" in patch.patched_content

    tx = engine.apply_patch(src_file, patch)
    assert tx is not None
    assert "AES/GCM/NoPadding" in src_file.read_text(encoding="utf-8")


def test_remediation_common_legacy_literal_forms(tmp_path):
    java_file = tmp_path / "Legacy.java"
    java_file.write_text('Cipher c = Cipher.getInstance("DES");\n', encoding="utf-8")
    python_file = tmp_path / "legacy_hash.py"
    python_file.write_text('digest = hashlib.new("md5", data)\n', encoding="utf-8")
    node_file = tmp_path / "legacy.js"
    node_file.write_text("const c = crypto.createCipheriv('des-ede3-cbc', key, iv);\n", encoding="utf-8")

    engine = RemediationEngine(journal_path=tmp_path / ".journal.json")
    assert engine.generate_patch(java_file, rule="REPLACE_DES_AES_GCM").has_changes is True
    assert engine.generate_patch(python_file, rule="REPLACE_MD5_SHA256").has_changes is True
    assert engine.generate_patch(node_file, rule="REPLACE_DES_AES_GCM").has_changes is True


def test_remediation_blowfish_key_generator_constant_size(tmp_path):
    source = tmp_path / "CryptoTest.java"
    source.write_text(
        'KeyGenerator keyGen = KeyGenerator.getInstance("Blowfish");\n'
        'keyGen.init(Math.abs(64));\n',
        encoding="utf-8",
    )
    patch = RemediationEngine().generate_patch(source, rule="REPLACE_DES_AES_GCM")
    assert patch.status == "READY"
    assert "KeyGenerator.getInstance(\"AES\")" in patch.patched_content
    assert "keyGen.init(256);" in patch.patched_content


def test_tampering_detection_prevents_corrupt_undo(tmp_path):
    src_file = tmp_path / "test.py"
    src_file.write_text("h = hashlib.md5(x)\n", encoding="utf-8")

    journal_path = tmp_path / ".ecdat_journal.json"
    engine = RemediationEngine(journal_path=journal_path)

    patch = engine.generate_patch(src_file, rule="REPLACE_MD5_SHA256")
    engine.apply_patch(src_file, patch)

    # Now simulate an external editor tampering with the file after patch
    src_file.write_text("TAMPERED CONTENT\n", encoding="utf-8")

    # Undo should fail because after_sha256 does not match current file
    with pytest.raises(ValueError, match="Checksum mismatch"):
        engine.undo_last()

    # Content remains tampered, not overwritten
    assert src_file.read_text(encoding="utf-8") == "TAMPERED CONTENT\n"


def test_journal_history_and_listing(tmp_path):
    journal_path = tmp_path / ".ecdat_journal.json"
    journal = RemediationJournal(journal_path=journal_path)

    assert len(journal.list_transactions()) == 0

    tx1 = journal.record_transaction(
        target_file="/tmp/a.js",
        rule_id="RULE-1",
        description="Fix 1",
        before_sha256="aaa",
        after_sha256="bbb",
        diff="--- diff1",
        original_content="old 1",
        remediated_content="new 1",
    )
    assert tx1["tx_id"].startswith("tx-")
    assert len(journal.list_transactions()) == 1
    assert journal.get_last_applied()["tx_id"] == tx1["tx_id"]

    journal.mark_status(tx1["tx_id"], "REVERTED")
    assert journal.get_last_applied() is None
    assert journal.get_last_reverted()["tx_id"] == tx1["tx_id"]


def test_remediate_target_directory_and_dryrun(tmp_path):
    proj_dir = tmp_path / "my_project"
    proj_dir.mkdir()
    f1 = proj_dir / "app.py"
    f1.write_text("import hashlib\nh = hashlib.md5(b'test').hexdigest()\n", encoding="utf-8")
    f2 = proj_dir / "server.js"
    f2.write_text("const c = crypto.createCipheriv('aes-128-cbc', k, iv);\n", encoding="utf-8")
    f3 = proj_dir / "clean.py"
    f3.write_text("import os\nprint('hello')\n", encoding="utf-8")

    journal_path = tmp_path / ".ecdat_journal.json"
    engine = RemediationEngine(journal_path=journal_path)

    # Test Dry Run across directory
    dry_results = engine.remediate_target(proj_dir, dry_run=True)
    assert len(dry_results) == 2
    assert all(r["status"] == "DRY_RUN" for r in dry_results)
    # Confirm no files modified on disk during dry run
    assert "md5" in f1.read_text(encoding="utf-8")
    assert "aes-128-cbc" in f2.read_text(encoding="utf-8")

    # Test Actual Apply across directory
    applied_results = engine.remediate_target(proj_dir, dry_run=False)
    assert len(applied_results) == 2
    assert "sha256" in f1.read_text(encoding="utf-8")
    assert "aes-256-gcm" in f2.read_text(encoding="utf-8")

    # Undo sequentially
    assert engine.undo_last() is True
    # One file undone
    assert engine.undo_last() is True
    # Both files undone
    assert "md5" in f1.read_text(encoding="utf-8")
    assert "aes-128-cbc" in f2.read_text(encoding="utf-8")



def test_zero_regex_compliance():
    repo_root = Path(__file__).resolve().parent.parent
    target_files = [
        repo_root / "ecdat" / "remediation" / "journal.py",
        repo_root / "ecdat" / "remediation" / "engine.py",
        repo_root / "ecdat" / "remediation" / "__init__.py",
    ]
    for fpath in target_files:
        if fpath.exists():
            content = fpath.read_text(encoding="utf-8")
            assert "import re" not in content, f"Zero-regex violation: 'import re' found in {fpath}"
            assert "from re import" not in content, f"Zero-regex violation: 'from re import' found in {fpath}"
            assert "re.compile" not in content, f"Zero-regex violation: 're.compile' found in {fpath}"
            assert "re.search" not in content, f"Zero-regex violation: 're.search' found in {fpath}"
            assert "re." not in content, f"Zero-regex violation: 're.' found in {fpath}"

def test_cst_format_preservation_and_non_crypto_string_protection(tmp_path):
    py_file = tmp_path / "format_test.py"
    # Notice: contains comments, custom spacing, and non-cryptographic string mentioning 'md5'
    original = (
        "# Security utility module\n"
        "def compute_hash(data):\n"
        "    # Note: legacy hash below\n"
        "    digest = hashlib.md5(data).hexdigest()\n"
        "    log_msg = \"calculating md5 checksum for audit log\"\n"
        "    return digest, log_msg\n"
    )
    py_file.write_text(original, encoding="utf-8")

    engine = RemediationEngine(journal_path=tmp_path / ".journal.json")
    patch = engine.generate_patch(py_file, rule="REPLACE_MD5_SHA256")
    assert patch.has_changes is True

    # hashlib.md5 must be rewritten to hashlib.sha256
    assert "hashlib.sha256(data)" in patch.patched_content
    # Comments must be completely preserved
    assert "# Security utility module" in patch.patched_content
    assert "# Note: legacy hash below" in patch.patched_content
    # Non-crypto string literal must NOT be touched
    assert "calculating md5 checksum for audit log" in patch.patched_content
