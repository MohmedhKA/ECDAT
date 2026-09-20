"""
ECDAT Hybrid-First Migration Recommender:
Maps quantum-vulnerable classical primitives to NIST FIPS 203/204/205 standards
and standardized hybrid combiners (RFC 9180, IETF composite drafts).
Integrated with PQCStandardsCatalog for declarative fine-grained parameter targets.
"""

from typing import Optional
from ecdat.models import CryptoAsset, RouteProfile, PathMTUResult
from ecdat.agility.standards_catalog import (
    PQCStandardsCatalog,
    PQCAlgorithmSpec,
    MigrationRecommendation,
)


class AgilityRecommender:
    """
    AgilityRecommender integrates the declarative PQCStandardsCatalog to provide
    fine-grained parameter recommendations (ML-DSA-44/65/87, ML-KEM-512/768/1024)
    and network-aware MTU routing guidance.
    """

    def __init__(self, catalog: Optional[PQCStandardsCatalog] = None) -> None:
        self.catalog = catalog or PQCStandardsCatalog.load_default()

    def recommend(
        self,
        asset: CryptoAsset,
        path_mtu: Optional[PathMTUResult] = None,
        path_profile: Optional[RouteProfile] = None,
    ) -> MigrationRecommendation:
        """
        Generate fine-grained migration recommendation for a given cryptographic asset.
        """
        return self.catalog.recommend_for_asset(
            asset=asset, path_mtu=path_mtu, path_profile=path_profile
        )


_DEFAULT_RECOMMENDER: Optional[AgilityRecommender] = None


def get_recommender() -> AgilityRecommender:
    """Get or initialize the process-wide default AgilityRecommender instance."""
    global _DEFAULT_RECOMMENDER
    if _DEFAULT_RECOMMENDER is None:
        _DEFAULT_RECOMMENDER = AgilityRecommender()
    return _DEFAULT_RECOMMENDER


def recommend_pqc_migration(
    asset: CryptoAsset,
    path_mtu: Optional[PathMTUResult] = None,
    path_profile: Optional[RouteProfile] = None,
) -> MigrationRecommendation:
    """
    Generates standardized post-quantum migration guidance for a cryptographic asset,
    prioritizing hybrid-first deployment to maintain backward compatibility.
    Delegates to the declarative standards catalog via AgilityRecommender.
    """
    return get_recommender().recommend(
        asset=asset, path_mtu=path_mtu, path_profile=path_profile
    )


__all__ = [
    "AgilityRecommender",
    "PQCStandardsCatalog",
    "PQCAlgorithmSpec",
    "MigrationRecommendation",
    "recommend_pqc_migration",
    "get_recommender",
]
