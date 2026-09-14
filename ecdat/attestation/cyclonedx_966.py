"""
ECDAT CycloneDX Discussion #966 Attestation Layer:
Implements the emerging standard taxonomy for CBOM 2.0 / CDXA discussed in CycloneDX Community #966:
- reachabilityProof: static/dynamic evidence confirming asset reachability
- dataLifetime: schema/ORM-derived secrecy lifetimes
- runtimeExecutionStatus: active, configuration-confirmed, or dormant state
- adversarialExposure: network harvest interception probability P_HNDL
- camsMaturity: code-level cryptographic agility level (0-3) and effort discount
- pathMtuProfile: transport MTU constraints and PQC fragmentation counts
"""

from typing import Dict, Any, Optional
from ecdat.models import CryptoAsset, MoscaScore, RouteProfile, PathMTUResult, EvidenceLevel
from ecdat.agility.recommender import MigrationRecommendation
from ecdat.agility.cams_detector import get_cams_y_multiplier

def enrich_cyclonedx_component_966(
    component: Dict[str, Any],
    asset: CryptoAsset,
    score: MoscaScore,
    rec: MigrationRecommendation,
    path_mtu: Optional[PathMTUResult] = None,
) -> Dict[str, Any]:
    """
    Enriches a CycloneDX 1.6 component dictionary with Discussion #966 attestation objects
    and property tags.
    """
    effective_route = rec.path_profile or (path_mtu.route_profile if path_mtu else RouteProfile.STANDARD)
    effective_mtu = path_mtu.effective_mtu if path_mtu else 1500

    # 1. Determine Runtime Execution Status
    if asset.evidence_level == EvidenceLevel.E4_RUNTIME_OBSERVED:
        exec_status = "ACTIVE"
    elif asset.evidence_level == EvidenceLevel.E3_CONFIG_CONFIRMED:
        exec_status = "CONFIG_CONFIRMED"
    elif asset.evidence_level == EvidenceLevel.DORMANT:
        exec_status = "DORMANT"
    else:
        exec_status = "STATIC_REACHABLE"

    # 2. Build Structured #966 Attestation Objects
    reachability_proof = {
        "evidenceLevel": asset.evidence_level.value,
        "reachabilityType": "STATIC_AST_FORWARD_FLOW" if "ast" in str(asset.evidence_sources).lower() else "CONFIGURATION_AUDIT",
        "callLocation": f"{asset.file_path}:{asset.line_number}",
        "confirmedSinks": [asset.raw_properties.get("sink")] if asset.raw_properties.get("sink") else [],
        "intentClassification": asset.intent_class.value if hasattr(asset.intent_class, "value") else str(asset.intent_class),
    }

    data_lifetime = {
        "lifespanTier": asset.x_tier.value,
        "effectiveSecrecyYears": score.x_years_effective,
        "extractionProvenance": asset.x_auto_source,
        "cryptoShreddingActive": asset.has_crypto_shredding,
    }

    adversarial_exposure = {
        "exposureProfile": asset.exposure_profile.value if hasattr(asset.exposure_profile, "value") else str(asset.exposure_profile),
        "pHndlInterceptionFactor": score.p_hndl,
        "harvestRiskCategory": "CRITICAL_HARVEST_TARGET" if score.p_hndl >= 0.8 else "INTERNAL_DEFENDED",
    }

    cams_maturity = {
        "agilityLevel": int(asset.agility_level),
        "agilityClassification": asset.agility_level.name if hasattr(asset.agility_level, "name") else str(asset.agility_level),
        "camsDiscountFactor": score.agility_factor,
        "migrationEffortMultiplier": get_cams_y_multiplier(asset.agility_level),
    }

    path_mtu_profile = {
        "routeProfile": effective_route.value if hasattr(effective_route, "value") else str(effective_route),
        "effectiveMtuBytes": effective_mtu,
        "pqcFragmentSegments": rec.packet_segments,
        "mtuConstrained": rec.mtu_constrained,
        "middleboxWarning": rec.mtu_warning,
    }

    # 3. Attach standard and #966 extension dictionaries
    component.setdefault("cdxAttestation", {})
    component["cdxAttestation"]["discussion966"] = {
        "reachabilityProof": reachability_proof,
        "dataLifetime": data_lifetime,
        "runtimeExecutionStatus": exec_status,
        "adversarialExposure": adversarial_exposure,
        "camsMaturity": cams_maturity,
        "pathMtuProfile": path_mtu_profile,
    }

    # 4. Also register as flat properties for backward-compatible CycloneDX 1.6 parsers
    existing_props = component.setdefault("properties", [])
    existing_props.extend([
        {"name": "ecdat:cdx966:reachability", "value": asset.evidence_level.value},
        {"name": "ecdat:cdx966:dataLifetimeYears", "value": str(score.x_years_effective)},
        {"name": "ecdat:cdx966:runtimeStatus", "value": exec_status},
        {"name": "ecdat:cdx966:exposureProfile", "value": adversarial_exposure["exposureProfile"]},
        {"name": "ecdat:cdx966:camsLevel", "value": str(cams_maturity["agilityLevel"])},
        {"name": "ecdat:cdx966:routeProfile", "value": path_mtu_profile["routeProfile"]},
        {"name": "ecdat:cdx966:pqcSegments", "value": str(rec.packet_segments)},
    ])

    return component
