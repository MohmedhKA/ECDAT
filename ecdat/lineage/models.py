"""
ECDAT Father Marko Cryptographic Lineage Models:
Defines Pydantic data schemas for Tripartite Lineage Graphs:
Ingress Sources (ENV, Config, DB) ──► Cryptographic Nexus (Call-Sites) ──► Egress Persistence Sinks (Redis, DB, Ledger).
"""

from enum import Enum
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class LineageCategory(str, Enum):
    INGRESS = "INGRESS"
    NEXUS = "NEXUS"
    EGRESS = "EGRESS"


class LineageSourceType(str, Enum):
    ENV = "ENV"
    CONFIG = "CONFIG"
    DATABASE = "DATABASE"
    PARAMETER = "PARAMETER"
    CALLSITE = "CALLSITE"
    CACHE = "CACHE"
    STREAM = "STREAM"
    STORAGE = "STORAGE"
    LEDGER = "LEDGER"


class LineageNode(BaseModel):
    node_id: str = Field(..., description="Unique node identifier (e.g. INGRESS:ENV:VOTE_CIPHER)")
    label: str = Field(..., description="Display label on graph")
    category: LineageCategory = Field(..., description="INGRESS, NEXUS, or EGRESS")
    source_type: LineageSourceType = Field(..., description="Specific subsystem type")
    file_path: Optional[str] = Field(None, description="Associated source file if applicable")
    line_number: Optional[int] = Field(None, description="Line number of invocation or sink")
    details: Dict[str, Any] = Field(default_factory=dict, description="Metadata (key name, TTL, parameters)")


class LineageEdge(BaseModel):
    source_id: str = Field(..., description="Origin node identifier")
    target_id: str = Field(..., description="Destination node identifier")
    edge_type: str = Field(..., description="PARAMETER_BINDING, CIPHERTEXT_EGRESS, KEY_PERSISTENCE")
    label: str = Field(..., description="Edge display text (e.g. 'binds: algo')")


class LineageGraphResult(BaseModel):
    nodes: List[LineageNode] = Field(default_factory=list)
    edges: List[LineageEdge] = Field(default_factory=list)
    ingress_count: int = 0
    nexus_count: int = 0
    egress_count: int = 0
    graph_json: Dict[str, Any] = Field(
        default_factory=dict,
        description="Stratified tripartite graph structure ready for D3 visualization"
    )
