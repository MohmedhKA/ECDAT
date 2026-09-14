import pytest
from ecdat.models import (
    CryptoAsset,
    PrimitiveType,
    XTier,
    IntentClass,
    EvidenceLevel,
    AgilityLevel,
    ExposureProfile,
    MoscaScore,
    RouteProfile,
    PathMTUResult,
)
from ecdat.agility.recommender import recommend_pqc_migration
from ecdat.network.mtu_prober import probe_network_mtu
from ecdat.attestation.cyclonedx_966 import enrich_cyclonedx_component_966

def test_enrich_cyclonedx_component_966():
    asset = CryptoAsset(
        asset_id="ASSET-001",
        component_name="gateway",
        algorithm="ECDH-P256",
        primitive_type=PrimitiveType.KEY_EXCHANGE,
        file_path="gateway.py",
        line_number=15,
        x_tier=XTier.EPHEMERAL,
        intent_class=IntentClass.CONFIDENTIALITY_ENVELOPE,
        evidence_level=EvidenceLevel.E1_STATIC_ARTIFACT,
        evidence_sources=["ast_tracer"],
        agility_level=AgilityLevel.CONFIGURABLE,
        exposure_profile=ExposureProfile.PUBLIC,
        p_hndl=1.0,
        x_auto_source="orm_ttl",
    )

    score = MoscaScore(
        asset_id="ASSET-001",
        x_years_effective=0.0,
        z_regulatory_year=2030,
        z_regulatory_phase=3,
        z_physical_10yr_prob="7-18%",
        y_max_years=4.0,
        deadline_year=2030.0,
        risk_level="MEDIUM",
        crypto_shredding_viable=False,
        planning_note="Standard migration",
        p_hndl=1.0,
        agility_factor=0.30,
        r_q_score=0.0,
    )

    pmtu = probe_network_mtu(override_profile=RouteProfile.STANDARD, override_mtu=1500)
    rec = recommend_pqc_migration(asset, path_mtu=pmtu)

    base_component = {
        "type": "cryptographic-asset",
        "name": asset.component_name,
        "bom-ref": asset.asset_id,
    }

    enriched = enrich_cyclonedx_component_966(
        base_component,
        asset=asset,
        score=score,
        rec=rec,
        path_mtu=pmtu,
    )

    assert "cdxAttestation" in enriched
    att = enriched["cdxAttestation"]["discussion966"]

    # Verify reachabilityProof
    assert att["reachabilityProof"]["evidenceLevel"] == "E1_STATIC_ARTIFACT"
    assert att["reachabilityProof"]["intentClassification"] == "CONFIDENTIALITY_ENVELOPE"

    # Verify dataLifetime
    assert att["dataLifetime"]["lifespanTier"] == "EPHEMERAL"
    assert att["dataLifetime"]["extractionProvenance"] == "orm_ttl"

    # Verify runtimeExecutionStatus
    assert att["runtimeExecutionStatus"] == "STATIC_REACHABLE"

    # Verify adversarialExposure
    assert att["adversarialExposure"]["exposureProfile"] == "PUBLIC"
    assert att["adversarialExposure"]["pHndlInterceptionFactor"] == 1.0

    # Verify camsMaturity
    assert att["camsMaturity"]["agilityLevel"] == 1
    assert att["camsMaturity"]["camsDiscountFactor"] == 0.30

    # Verify pathMtuProfile
    assert att["pathMtuProfile"]["routeProfile"] == "STANDARD"
    assert att["pathMtuProfile"]["effectiveMtuBytes"] == 1500
    assert att["pathMtuProfile"]["pqcFragmentSegments"] == 1

    # Verify flat properties
    prop_names = [p["name"] for p in enriched["properties"]]
    assert "ecdat:cdx966:reachability" in prop_names
    assert "ecdat:cdx966:camsLevel" in prop_names
    assert "ecdat:cdx966:routeProfile" in prop_names
