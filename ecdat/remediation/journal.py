"""
ECDAT Remediation Journal:
Audit log and state tracker for automated cryptographic code remediations.
Tracks atomic patch applications, before/after SHA-256 integrity digests,
and maintains transaction history to support deterministic multi-step Undo and Redo.
Strictly zero-regex compliant: uses standard JSON serialization and path utilities.
"""

import json
import time
from pathlib import Path
from typing import Dict, Any, List, Optional


DEFAULT_JOURNAL_FILE = ".ecdat_remediation_journal.json"


class RemediationJournal:
    def __init__(self, journal_path: Optional[Path] = None):
        self.journal_path = Path(journal_path) if journal_path else Path.cwd() / DEFAULT_JOURNAL_FILE
        self._transactions: List[Dict[str, Any]] = []
        self._load()

    def _load(self) -> None:
        if self.journal_path.exists():
            try:
                data = json.loads(self.journal_path.read_text(encoding="utf-8"))
                self._transactions = data.get("transactions", [])
            except Exception:
                self._transactions = []
        else:
            self._transactions = []

    def _save(self) -> None:
        self.journal_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            "version": "1.0",
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "total_transactions": len(self._transactions),
            "transactions": self._transactions,
        }
        tmp_path = self.journal_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp_path.replace(self.journal_path)

    def record_transaction(
        self,
        target_file: str,
        rule_id: str,
        description: str,
        before_sha256: str,
        after_sha256: str,
        diff: str,
        original_content: str,
        remediated_content: str,
        asset_id: Optional[str] = None,
    ) -> Dict[str, Any]:
        tx_id = f"tx-{int(time.time() * 1000)}-{len(self._transactions) + 1:03d}"
        tx_record: Dict[str, Any] = {
            "tx_id": tx_id,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "target_file": str(Path(target_file).resolve()),
            "asset_id": asset_id or "",
            "rule_id": rule_id,
            "description": description,
            "before_sha256": before_sha256,
            "after_sha256": after_sha256,
            "diff": diff,
            "original_content": original_content,
            "remediated_content": remediated_content,
            "status": "APPLIED",
        }
        self._transactions.append(tx_record)
        self._save()
        return tx_record

    def get_transaction(self, tx_id: str) -> Optional[Dict[str, Any]]:
        for tx in self._transactions:
            if tx.get("tx_id") == tx_id:
                return tx
        return None

    def get_last_applied(self) -> Optional[Dict[str, Any]]:
        for tx in reversed(self._transactions):
            if tx.get("status") == "APPLIED":
                return tx
        return None

    def get_last_reverted(self) -> Optional[Dict[str, Any]]:
        for tx in reversed(self._transactions):
            if tx.get("status") == "REVERTED":
                return tx
        return None

    def mark_status(self, tx_id: str, status: str) -> bool:
        tx = self.get_transaction(tx_id)
        if tx:
            tx["status"] = status
            tx["status_updated_at"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
            self._save()
            return True
        return False

    def list_transactions(self) -> List[Dict[str, Any]]:
        return list(self._transactions)
