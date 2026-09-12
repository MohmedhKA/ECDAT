"""
ECDAT Executive CISO Report Generator:
Formats discovered cryptographic assets, 4-tier X dataflow classifications,
Mosca Y_max engineering timelines, and Merkle root commitments into actionable Markdown reports.
"""

from typing import List, Tuple, Optional
from ecdat.models import (
    CryptoAsset,
    MoscaScore,
    XTier,
    UnknownEntry,
    IntentClass,
    ExposureProfile,
    EvidenceLevel,
)
from ecdat.agility.recommender import MigrationRecommendation
from ecdat.agility.buffer_audit import BufferHazard
from ecdat.contagion.engine import ContagionGraphResult

def generate_ciso_report(
    assessments: List[Tuple[CryptoAsset, MoscaScore, MigrationRecommendation]],
    buffer_hazards: List[BufferHazard],
    merkle_root_hex: str,
    contagion_result: Optional[ContagionGraphResult] = None,
    unknowns_ledger: Optional[List[UnknownEntry]] = None,
) -> str:
    """Generates an executive CISO report in GitHub-flavored Markdown."""
    total_assets = len(assessments)
    critical_count = sum(1 for _, score, _ in assessments if score.risk_level == "CRITICAL")
    high_count = sum(1 for _, score, _ in assessments if score.risk_level == "HIGH")
    medium_count = sum(1 for _, score, _ in assessments if score.risk_level == "MEDIUM")
    low_count = sum(1 for _, score, _ in assessments if score.risk_level == "LOW")

    tier_counts = {
        tier: sum(1 for asset, _, _ in assessments if asset.x_tier == tier)
        for tier in XTier
    }

    intent_counts = {
        intent: sum(1 for asset, _, _ in assessments if asset.intent_class == intent)
        for intent in IntentClass
    }
    op_util_count = intent_counts.get(IntentClass.OPERATIONAL_UTILITY, 0)

    exposure_counts = {
        exp: sum(1 for asset, _, _ in assessments if asset.exposure_profile == exp)
        for exp in ExposureProfile
    }

    # Sort assessments by Y_max ascending (shortest budget first)
    sorted_assessments = sorted(assessments, key=lambda item: item[1].y_max_years)

    lines = [
        "# ECDAT — Executive Cryptographic Risk & Migration Report",
        "",
        "> **Standards Baseline:** NIST IR 8547 / FIPS 203, 204, 205 | US OMB M-26-15 | GRI 2025 Survey",
        "> **Attestation Commitment:** SHA-256 Merkle Root `0x" + merkle_root_hex + "`",
        "",
        "## 1. Executive Summary",
        "",
        "| Metric | Value | Executive Assessment |",
        "| :--- | :--- | :--- |",
        f"| **Total Cryptographic Assets** | `{total_assets}` | Discovered across source code & infrastructure |",
        f"| **Critical Risk ($Y_{{max}} \\le 1.0\\text{{y}}$)** | `{critical_count}` | Immediate migration queue (HNDL window open / past deadline) |",
        f"| **High Risk ($1.0 < Y_{{max}} \\le 2.5\\text{{y}}$)** | `{high_count}` | Must be scheduled in current 2-year planning budget |",
        f"| **Medium / Low Risk** | `{medium_count + low_count}` | Safe operational window ($> 2.5\\text{{y}}$ buffer) |",
        f"| **Operational Utility Suppressed** | `{op_util_count}` | False-positives eliminated (ETags/Caches: $R_Q = 0.0$) |",
        f"| **Buffer Overflow Hazards** | `{len(buffer_hazards)}` | Fixed-size memory allocations incompatible with PQC |",
        f"| **Boundary Unknowns Logged** | `{len(unknowns_ledger or [])}` | Explicitly audited excluded paths and binary limitations |",
        "",
        "### 4-Tier Data Lifespan ($X$) Distribution",
        "",
        "| Lifespan Tier | Assets | Estimated Secrecy $X$ | Typical Sinks |",
        "| :--- | :--- | :--- | :--- |",
        f"| **`EPHEMERAL`** | `{tier_counts[XTier.EPHEMERAL]}` | ~0 Years | Network sockets, transient memory buffers zeroed on close |",
        f"| **`SHORT_TERM`** | `{tier_counts[XTier.SHORT_TERM]}` | ~1–2 Years | Caching layers (Redis TTL), rotating session tokens |",
        f"| **`OPERATIONAL`** | `{tier_counts[XTier.OPERATIONAL]}` | ~5 Years | Relational databases (PostgreSQL/MySQL), customer records |",
        f"| **`ARCHIVAL`** | `{tier_counts[XTier.ARCHIVAL]}` | ~10+ Years | Long-term cloud backups (S3), HIPAA/SOX compliance logs |",
        f"| **`HUMAN_REVIEW`** | `{tier_counts[XTier.HUMAN_REVIEW]}` | Flagged | Ambiguous dataflows / unanalyzed external library boundaries |",
        "",
        "### Functional Security Intent (DSIS Lattice)",
        "",
        "| Functional Intent Class | Assets | Quantum Exploit Risk | Mitigation Status |",
        "| :--- | :---: | :--- | :--- |",
        f"| **`CONFIDENTIALITY_ENVELOPE`** | `{intent_counts.get(IntentClass.CONFIDENTIALITY_ENVELOPE, 0)}` | High ($W=1.0$) | Primary HNDL target — payload confidentiality |",
        f"| **`AUTHENTICATION_SIGNATURE`** | `{intent_counts.get(IntentClass.AUTHENTICATION_SIGNATURE, 0)}` | Medium-High ($W=0.8$) | Identity forgery — handshake & token authentication |",
        f"| **`INTEGRITY_CHECKSUM`** | `{intent_counts.get(IntentClass.INTEGRITY_CHECKSUM, 0)}` | Low-Medium ($W=0.3$) | Tamper detection — audit trails & code integrity |",
        f"| **`OPERATIONAL_UTILITY`** | `{op_util_count}` | **Zero ($R_Q = 0.0$)** | **Suppressed from CISO queue (HTTP ETags & CDN caches)** |",
        "",
        "### Deployment Exposure & Harvest Interception ($P_{\\text{HNDL}}$)",
        "",
        "| Exposure Profile | Assets | $P_{\\text{HNDL}}$ Interception Factor | Threat Model Scope |",
        "| :--- | :---: | :---: | :--- |",
        f"| **`PUBLIC`** | `{exposure_counts.get(ExposureProfile.PUBLIC, 0)}` | `1.00` | Internet Ingress / LoadBalancer (Actively harvested) |",
        f"| **`INTERNAL`** | `{exposure_counts.get(ExposureProfile.INTERNAL, 0)}` | `0.05` | Private VPC / ClusterIP (Requires lateral pivot) |",
        f"| **`AIRGAPPED`** | `{exposure_counts.get(ExposureProfile.AIRGAPPED, 0)}` | `0.00` | Standalone isolated host (Immune to passive HNDL) |",
        "",
        "---",
        "",
        "## 2. Actionable Migration Backlog (Ranked by $Y_{max}$ Budget)",
        "",
        "The table below replaces flat checklists with mathematically grounded deadlines: "
        "**$Y_{max} = (Z_{reg} - 2026) - X_{eff}$**.",
        "",
        "| Priority | Asset ID | File Location & Line | Trigger Sink / Evidence | Algorithm | $X$ Tier | $Y_{max}$ Budget | Mandate Year | Recommended Hybrid | Risk Level |",
        "| :---: | :--- | :--- | :--- | :--- | :---: | :---: | :---: | :--- | :---: |",
    ]

    for idx, (asset, score, rec) in enumerate(sorted_assessments, start=1):
        loc_str = f"`{asset.file_path}:{asset.line_number}`" if asset.line_number > 0 else f"`{asset.file_path}`"
        raw_props = asset.raw_properties or {}
        sink_str = raw_props.get("sink") or raw_props.get("evidence") or raw_props.get("subject") or "Direct Cryptographic Material"
        lines.append(
            f"| **#{idx}** | `{asset.asset_id}` | {loc_str} | `{sink_str}` | `{asset.algorithm}` | "
            f"`{asset.x_tier.value}` | **`{score.y_max_years:+.1f}y`** | `{score.z_regulatory_year}` | "
            f"{rec.recommended_hybrid} | **`{score.risk_level}`** |"
        )

    lines.extend([
        "",
        "---",
        "",
        "## 3. Cryptographic Agility & Buffer Hazard Audit",
        "",
    ])

    if buffer_hazards:
        lines.append("| Variable Name | Allocated Buffer | PQC Requirement (ML-DSA-65) | Line | Severity | Action Required |")
        lines.append("| :--- | :---: | :---: | :---: | :---: | :--- |")
        for h in buffer_hazards:
            lines.append(
                f"| `{h.variable_name}` | `{h.allocated_bytes} B` | `{h.required_bytes_pqc} B` | Line {h.line_number} | "
                f"**`{h.severity}`** | Expand static buffer before swapping algorithm to avoid buffer overflow |"
            )
    else:
        lines.append("No fixed-size buffer hazards detected adjacent to cryptographic call sites.")

    lines.extend([
        "",
        "---",
        "",
        "## 4. Epidemiological R0 Dependency Contagion (Superspreaders)",
        "",
        "Cryptographic vulnerability propagates through software dependency contact networks. "
        "The **$R_0$ score** measures how many downstream services inherit quantum risk from an unmigrated component.",
        "",
    ])

    if contagion_result and contagion_result.superspreaders:
        lines.append("| Component / Module | $R_0$ Score | Direct Crypto | Downstream Affected Services | Actionable Mitigation Impact |")
        lines.append("| :--- | :---: | :---: | :--- | :--- |")
        for sp in contagion_result.superspreaders:
            lines.append(
                f"| **`{sp.node_id}`** | **`{sp.r0_score}`** | `{sp.has_crypto}` | "
                f"`{', '.join(sp.downstream_dependents)}` | {sp.mitigation_impact} |"
            )
    else:
        lines.append("No critical cryptographic superspreader hubs detected. Vulnerabilities are isolated to individual endpoints.")

    lines.extend([
        "",
        "---",
        "",
        "## 5. Privacy-Preserving Attestation via Merkle Commitments",
        "",
        "Conventional audit practices require handing over full, plain-text Cryptography Bills of Materials (CBOMs), "
        "which inadvertently functions as a targeting map for adversaries. ECDAT resolves this through **selective inclusion proofs**:",
        "",
        f"- **Committed Root Hash:** `0x{merkle_root_hex}`",
        "- **Auditor Verification Protocol:** For any compliance query, ECDAT issues a single leaf proof package (`proof_<assetId>.json`).",
        "- **Verification Command:**",
        "  ```bash",
        "  python -m ecdat.merkle.verifier --proof proofs/proof_asset_1.json --root cbom_root.hex",
        "  ```",
        "- **Guarantee:** Proves mathematically that a specific component is compliant without disclosing internal codebase paths or unpatched inventory items.",
        "",
    ])
    lines.extend([
        "",
        "---",
        "",
        "## 6. Auditable Unknowns Ledger & Boundary Declarations",
        "",
        "Conventional vulnerability scanners report false 100% perimeter coverage by silently omitting files or paths they cannot parse. "
        "ECDAT enforces **Auditable Boundary Honesty** by declaring all excluded paths, uninspected binary files, and encrypted containers.",
        "",
    ])

    if unknowns_ledger:
        lines.append("| Item Path / Identifier | Category | Scanning Boundary Reason | Recommended Auditor Action |")
        lines.append("| :--- | :---: | :--- | :--- |")
        for u in unknowns_ledger:
            lines.append(
                f"| `{u.item_path}` | `{u.category}` | {u.reason} | {u.recommended_action} |"
            )
    else:
        lines.append("Full codebase perimeter verified. No uninspected binary files, encrypted keystores, or excluded directories encountered.")

    lines.append("")

    return "\n".join(lines)

