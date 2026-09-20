"""
ECDAT CI/CD Cryptographic Quality Gate:
Evaluates cryptographic posture against enterprise compliance policies,
enforcing quantum-safe migration thresholds and preventing pipeline deployment
of deprecated or vulnerable algorithms.
"""

from typing import List, Dict, Any, Union
from pydantic import BaseModel, Field

from ecdat.models import CryptoAsset
from ecdat.report_sarif import _resolve_risk_level

SEVERITY_RANKS: Dict[str, int] = {
    "CRITICAL": 3,
    "HIGH": 2,
    "MEDIUM": 1,
    "LOW": 0,
}


class GateResult(BaseModel):
    """Result of an evaluated cryptographic CI/CD quality gate."""
    passed: bool = Field(..., description="Whether the quality gate passed")
    exit_code: int = Field(..., description="0 if passed, 1 if failed")
    violations: List[CryptoAsset] = Field(default_factory=list, description="Violating assets")
    threshold: str = Field("CRITICAL", description="Failure severity threshold")
    max_allowed: int = Field(0, description="Maximum allowed violations before failure")
    summary: Dict[str, Any] = Field(default_factory=dict, description="Summary statistics")
    banner: str = Field("", description="Executive CI/CD console output banner")


def evaluate_quality_gate(
    assets: Union[List[CryptoAsset], Any],
    fail_on: str = "CRITICAL",
    max_allowed: int = 0,
    policy: str = "nist-sp-800-131a",
) -> GateResult:
    """
    Evaluates discovered cryptographic assets against an organization's CI/CD
    quality gate policy and severity threshold (strictly zero-regex).

    Args:
        assets: Discovered CryptoAsset instances or scan pipeline result.
        fail_on: Severity threshold to trigger violation ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW').
        max_allowed: Maximum count of violations allowed before gate fails.
        policy: Policy identifier (e.g. 'nist-sp-800-131a', 'pqc-migration-2026').

    Returns:
        GateResult instance with exit_code (0=pass, 1=fail), violations, and formatted banner.
    """
    if isinstance(assets, dict) and "assets" in assets:
        asset_list: List[CryptoAsset] = assets["assets"]
    elif hasattr(assets, "assets") and isinstance(getattr(assets, "assets"), list):
        asset_list = getattr(assets, "assets")
    else:
        asset_list = list(assets)

    threshold_clean = (fail_on or "CRITICAL").upper()
    target_rank = SEVERITY_RANKS.get(threshold_clean, 3)

    violations: List[CryptoAsset] = []
    critical_count = 0
    high_count = 0
    medium_count = 0
    low_count = 0

    for asset in asset_list:
        risk_str = _resolve_risk_level(asset).upper()
        if risk_str == "CRITICAL":
            critical_count += 1
            asset_rank = 3
        elif risk_str == "HIGH":
            high_count += 1
            asset_rank = 2
        elif risk_str in ("MEDIUM", "MANUAL_REVIEW_REQUIRED"):
            medium_count += 1
            asset_rank = 1
        else:
            low_count += 1
            asset_rank = 0

        if asset_rank >= target_rank:
            violations.append(asset)

    passed = len(violations) <= max_allowed
    exit_code = 0 if passed else 1

    summary: Dict[str, Any] = {
        "total_assets": len(asset_list),
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "violations_count": len(violations),
        "threshold": threshold_clean,
        "max_allowed": max_allowed,
        "policy": policy,
        "passed": passed,
        "exit_code": exit_code,
    }

    # Construct executive CI/CD console banner
    status_tag = "PASSED" if passed else "FAILED"
    banner_lines = [
        "=" * 80,
        f"           ECDAT CRYPTOGRAPHIC CI/CD QUALITY GATE: {status_tag}",
        "=" * 80,
        f"Policy:             {policy}",
        f"Severity Threshold: {threshold_clean} (Fails if violations > {max_allowed})",
        f"Total Assets:       {len(asset_list)}",
        f"Gate Violations:    {len(violations)} (Max Allowed: {max_allowed})",
        f"Severity Breakdown: CRITICAL: {critical_count} | HIGH: {high_count} | MEDIUM: {medium_count} | LOW: {low_count}",
    ]
    if passed:
        banner_lines.append(f"Status:             PASSED — Cryptographic assets comply with {policy} policy requirements.")
    else:
        banner_lines.append(f"Status:             FAILED — {len(violations)} asset(s) exceed maximum allowed threshold of {max_allowed} for {threshold_clean} risk.")

    if violations:
        banner_lines.append("-" * 80)
        banner_lines.append(f"Violating Cryptographic Assets ({len(violations)}):")
        for v in violations[:15]:
            v_risk = _resolve_risk_level(v)
            banner_lines.append(f"  * [{v.asset_id}] {v.algorithm} ({v.component_name}) @ {v.file_path}:{v.line_number} -> {v_risk}")
        if len(violations) > 15:
            banner_lines.append(f"  ... and {len(violations) - 15} additional violation(s).")
    banner_lines.append("=" * 80)

    banner_text = "\n".join(banner_lines)

    return GateResult(
        passed=passed,
        exit_code=exit_code,
        violations=violations,
        threshold=threshold_clean,
        max_allowed=max_allowed,
        summary=summary,
        banner=banner_text,
    )
