"""
ECDAT Epidemiological Dependency Contagion Engine:
Models software dependency networks as epidemiological contact graphs,
computing R0 infection propagation metrics and identifying cryptographic superspreaders.
"""

import ast
import os
from pathlib import Path
from typing import List, Dict, Set, Any, Tuple, Optional
import networkx as nx
from pydantic import BaseModel, Field
from ecdat.models import CryptoAsset
from ecdat.mosca.engine import is_post_quantum, is_safe_quantum_or_symmetric

class ContagionNode(BaseModel):
    node_id: str = Field(..., description="Unique module or component name")
    file_path: str = Field(..., description="Relative or absolute file path")
    has_crypto: bool = Field(False, description="Whether this node directly instantiates cryptography")
    r0_score: int = Field(0, description="Downstream infection count: number of dependents exposed")
    downstream_dependents: List[str] = Field(default_factory=list, description="IDs of affected downstream components")
    is_superspreader: bool = Field(False, description="Whether this node is a critical contagion hub")
    is_pqc_anchor: bool = Field(False, description="Whether this node acts as a post-quantum immunization anchor")
    mitigation_impact: str = Field(..., description="Actionable CISO summary of migration impact")

class ContagionGraphResult(BaseModel):
    total_nodes: int
    total_edges: int
    superspreaders: List[ContagionNode]
    pqc_anchors: List[ContagionNode] = Field(default_factory=list, description="Post-quantum nodes that immunize downstream dependents")
    nodes: List[ContagionNode]
    graph_json: Dict[str, Any] = Field(
        ..., description="Force-directed bubble graph format (nodes + links) ready for D3.js visualization"
    )

def extract_module_dependencies(file_path: str) -> List[str]:
    """
    Statically analyzes source files (Python, JS/TS, Go, Rust) to extract imported module names.
    """
    imported_modules: List[str] = []
    p = Path(file_path)
    suffix = p.suffix.lower()

    try:
        with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
            content = f.read()
    except Exception:
        return imported_modules

    if suffix == ".py":
        try:
            tree = ast.parse(content, filename=file_path)
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imported_modules.append(alias.name.split(".")[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imported_modules.append(node.module.split(".")[0])
        except Exception:
            pass
    elif suffix in {".js", ".mjs", ".cjs", ".ts", ".tsx"}:
        import re
        for m in re.finditer(r"(?:import\s+(?:[\w*\s{},]*\s+from\s+)?|require\s*\(\s*)['\"]([^'\"]+)['\"]", content):
            raw_path = m.group(1)
            stem = Path(raw_path).stem
            imported_modules.append(stem)
            if "/" in raw_path and not raw_path.startswith("."):
                pkg = raw_path.split("/")[0] if not raw_path.startswith("@") else "/".join(raw_path.split("/")[:2])
                imported_modules.append(pkg)
    elif suffix == ".go":
        import re
        for m in re.finditer(r"['\"]([^'\"]+)['\"]", content):
            raw_path = m.group(1)
            imported_modules.append(Path(raw_path).stem)
    elif suffix == ".rs":
        import re
        for m in re.finditer(r"use\s+([a-zA-Z0-9_:]+);", content):
            first_part = m.group(1).split("::")[0]
            imported_modules.append(first_part)

    return imported_modules

def build_contagion_network(
    file_paths: List[str],
    crypto_assets: Optional[List[CryptoAsset]] = None,
    manifest_dependencies: Optional[List[Any]] = None,
) -> Tuple[nx.DiGraph, Dict[str, str], Set[str]]:
    """
    Builds a directed dependency and PKI authority graph.
    Edge direction represents contagion flow: Provider/Issuer -> Consumer/Relying party.
    If Service A imports Common Library B, edge B -> A.
    If Root CA issues identity to Peer0/Orderer1, edge CA -> Peer0/Orderer1.
    """
    G = nx.DiGraph()
    stem_to_path: Dict[str, str] = {}
    crypto_modules: Set[str] = set()

    # Exclude any hidden directories, virtualenvs, and agent folders
    excluded_dirs = {
        "venv", ".venv", "env", "node_modules", "site-packages", "__pycache__", ".git",
        "dist", "build", "target", ".cache", ".agents", ".gemini", ".antigravity", ".codex", ".superpowers", "agents"
    }
    valid_file_paths = [
        f for f in file_paths
        if not any((part.startswith(".") and part != ".") or part.lower() in excluded_dirs for part in Path(f).parts[:-1])
    ]

    # 1. Register all local code modules
    for fpath in valid_file_paths:
        stem = Path(fpath).stem
        stem_to_path[stem] = fpath
        G.add_node(stem, file_path=fpath, algorithms=set())

    # Add edges based on local imports
    for fpath in valid_file_paths:
        consumer_stem = Path(fpath).stem
        imports = extract_module_dependencies(fpath)
        for imp in imports:
            if imp in stem_to_path and imp != consumer_stem:
                provider_stem = imp
                G.add_edge(provider_stem, consumer_stem)

    # 2. Add and connect cryptographic assets (Theia certificates, keys, secrets, AST assets)
    if crypto_assets:
        for asset in crypto_assets:
            fpath = asset.file_path or ""
            stem = Path(fpath).stem
            parts = Path(fpath).parts
            alg = asset.algorithm

            if stem in stem_to_path:
                crypto_modules.add(stem)
                G.nodes[stem].setdefault("algorithms", set()).add(alg)

            # Check for PKI / Fabric organization hierarchy
            if "organizations" in parts:
                org_idx = parts.index("organizations")
                sub = parts[org_idx + 1 :]
                if len(sub) >= 2:
                    org_type, org_name = sub[0], sub[1]
                    ca_node = f"{org_name}-ca"
                    if not G.has_node(ca_node):
                        G.add_node(ca_node, file_path=fpath, algorithms=set())
                        stem_to_path[ca_node] = fpath
                    crypto_modules.add(ca_node)
                    G.nodes[ca_node].setdefault("algorithms", set()).add(alg)

                    if len(sub) >= 4 and sub[2] in ("orderers", "peers", "users"):
                        entity_name = sub[3]
                        entity_node = entity_name
                        if not G.has_node(entity_node):
                            G.add_node(entity_node, file_path=fpath, algorithms=set())
                            stem_to_path[entity_node] = fpath
                        crypto_modules.add(entity_node)
                        G.nodes[entity_node].setdefault("algorithms", set()).add(alg)
                        # CA issues credentials to entity -> CA is the provider/issuer
                        G.add_edge(ca_node, entity_node)
            elif any(k in parts for k in ("wallet", "keys")):
                k_node = stem or Path(fpath).name
                if not G.has_node(k_node):
                    G.add_node(k_node, file_path=fpath, algorithms=set())
                    stem_to_path[k_node] = fpath
                crypto_modules.add(k_node)
                G.nodes[k_node].setdefault("algorithms", set()).add(alg)
                app_node = "backend-service"
                if not G.has_node(app_node):
                    G.add_node(app_node, file_path="backend", algorithms=set())
                    stem_to_path[app_node] = "backend"
                G.add_edge(k_node, app_node)
            elif fpath.endswith(".env"):
                env_node = ".env"
                if not G.has_node(env_node):
                    G.add_node(env_node, file_path=fpath, algorithms=set())
                    stem_to_path[env_node] = fpath
                crypto_modules.add(env_node)
                G.nodes[env_node].setdefault("algorithms", set()).add(alg)
                app_node = "backend-service"
                if not G.has_node(app_node):
                    G.add_node(app_node, file_path="backend", algorithms=set())
                    stem_to_path[app_node] = "backend"
                G.add_edge(env_node, app_node)
            else:
                if stem and not G.has_node(stem):
                    G.add_node(stem, file_path=fpath, algorithms=set())
                    stem_to_path[stem] = fpath
                    crypto_modules.add(stem)
                if stem in G:
                    G.nodes[stem].setdefault("algorithms", set()).add(alg)

    # 3. Add Polyglot Supply Chain Manifest Dependencies
    if manifest_dependencies:
        for dep in manifest_dependencies:
            pname = dep.package_name if hasattr(dep, "package_name") else dep.get("package_name", "")
            mpath = dep.manifest_path if hasattr(dep, "manifest_path") else dep.get("manifest_path", "")
            eco = dep.ecosystem if hasattr(dep, "ecosystem") else dep.get("ecosystem", "")
            cat = dep.category if hasattr(dep, "category") else dep.get("category", "")
            readiness = dep.pqc_readiness if hasattr(dep, "pqc_readiness") else dep.get("pqc_readiness", "")
            if pname:
                dep_node = f"{pname}"
                if not G.has_node(dep_node):
                    G.add_node(dep_node, file_path=mpath, algorithms=set())
                    stem_to_path[dep_node] = mpath
                crypto_modules.add(dep_node)
                G.nodes[dep_node].setdefault("algorithms", set()).add(pname)
                if cat:
                    G.nodes[dep_node]["algorithms"].add(cat)
                if readiness:
                    G.nodes[dep_node]["algorithms"].add(readiness)

                # Connect to component that declared this manifest
                parent_dir = Path(mpath).parent.name
                target_component = parent_dir if parent_dir not in ("", ".") else f"{eco}-app"
                if not G.has_node(target_component):
                    G.add_node(target_component, file_path=str(Path(mpath).parent), algorithms=set())
                    stem_to_path[target_component] = str(Path(mpath).parent)
                G.add_edge(dep_node, target_component)

    return G, stem_to_path, crypto_modules

def analyze_contagion(
    file_paths: List[str],
    crypto_assets: List[CryptoAsset],
    manifest_dependencies: Optional[List[Any]] = None,
    superspreader_threshold: int = 2,
) -> ContagionGraphResult:
    """
    Computes R0 contagion scores across the dependency graph.
    Pinpoints superspreaders: shared cryptographic modules that infect multiple downstream services.
    Distinguishes post-quantum immunization anchors and safe symmetric algorithms from classical vulnerable hubs.
    """
    G, stem_to_path, crypto_modules = build_contagion_network(
        file_paths, crypto_assets, manifest_dependencies
    )

    # Pre-map assets by component_name and stem for fast lookup
    node_to_algs: Dict[str, Set[str]] = {}
    if crypto_assets:
        for a in crypto_assets:
            alg = a.algorithm
            node_to_algs.setdefault(a.component_name, set()).add(alg)
            if a.file_path:
                node_to_algs.setdefault(Path(a.file_path).stem, set()).add(alg)

    contagion_nodes: List[ContagionNode] = []
    superspreaders: List[ContagionNode] = []
    pqc_anchors: List[ContagionNode] = []

    for node in G.nodes():
        fpath = stem_to_path.get(node, node)
        node_data = G.nodes[node]
        algs = set(node_data.get("algorithms", set()))
        if node in node_to_algs:
            algs.update(node_to_algs[node])

        has_crypto = (node in crypto_modules) or bool(algs)

        # Compute R0: all downstream reachable nodes (descendants in the infection DAG)
        if G.has_node(node):
            descendants = list(nx.descendants(G, node))
        else:
            descendants = []

        r0 = len(descendants)

        # Classify cryptographic posture
        has_pqc = any(
            is_post_quantum(a) or a in ("MIGRATED_PQC", "POST_QUANTUM")
            for a in algs
        )
        has_vulnerable_classical = any(
            not is_safe_quantum_or_symmetric(a) and a not in ("MIGRATED_PQC", "POST_QUANTUM", "SAFE_SYMMETRIC", "SYMMETRIC_OR_HASH")
            for a in algs
        ) if algs else (has_crypto and not has_pqc)

        is_pqc_anchor = False
        is_superspreader = False

        if has_pqc and not has_vulnerable_classical:
            # Purely post-quantum component: immunizes downstream consumers
            is_pqc_anchor = True
            is_superspreader = False
            impact_desc = (
                f"IMMUNIZATION ANCHOR (R0={r0}): Supplies post-quantum security to {r0} downstream services: {', '.join(descendants)}."
                if r0 > 0
                else "IMMUNIZATION ANCHOR: Standalone post-quantum component."
            )
        elif not has_vulnerable_classical and has_crypto:
            # Grover-safe symmetric or hash component
            is_pqc_anchor = False
            is_superspreader = False
            impact_desc = f"Grover-resilient symmetric/hash component (R0={r0}): no Shor's algorithm vulnerability propagated."
        elif has_vulnerable_classical:
            # Classical asymmetric cryptographic component
            is_superspreader = (r0 >= superspreader_threshold) and has_crypto
            if is_superspreader:
                impact_desc = (
                    f"SUPERSPREADER (R0={r0}): Migrating '{node}' to PQC immediately eliminates "
                    f"quantum risk across {r0} downstream services: {', '.join(descendants)}."
                )
            elif has_crypto and r0 > 0:
                impact_desc = f"Infects {r0} downstream service(s). Contagion propagates to {', '.join(descendants)}."
            elif has_crypto:
                impact_desc = "Isolated endpoint: no downstream consumers affected (R0=0)."
            else:
                impact_desc = "Consumer service: inherits risk from upstream cryptographic dependencies."
        else:
            impact_desc = (
                f"Intermediary service: routes dependencies to {r0} downstream services."
                if r0 > 0
                else "Consumer service: inherits risk from upstream cryptographic dependencies."
            )

        c_node = ContagionNode(
            node_id=node,
            file_path=fpath,
            has_crypto=has_crypto,
            r0_score=r0,
            downstream_dependents=descendants,
            is_superspreader=is_superspreader,
            is_pqc_anchor=is_pqc_anchor,
            mitigation_impact=impact_desc,
        )
        contagion_nodes.append(c_node)
        if is_superspreader:
            superspreaders.append(c_node)
        if is_pqc_anchor:
            pqc_anchors.append(c_node)

    # Sort superspreaders and anchors by R0 descending
    superspreaders.sort(key=lambda n: n.r0_score, reverse=True)
    pqc_anchors.sort(key=lambda n: n.r0_score, reverse=True)

    # Build D3 force-directed JSON bubble graph format
    nodes_json = []
    for c_node in contagion_nodes:
        if c_node.is_superspreader:
            color = "#ef4444"  # Bright Red (Critical Superspreader)
            radius = 24 + min(c_node.r0_score * 4, 30)
            group = "superspreader"
        elif c_node.is_pqc_anchor:
            color = "#10b981"  # Emerald Green (Immunization Anchor)
            radius = 24 + min(c_node.r0_score * 4, 30) if c_node.r0_score > 0 else 18
            group = "pqc_anchor"
        elif c_node.has_crypto and "Grover-resilient" in c_node.mitigation_impact:
            color = "#06b6d4"  # Cyan (Symmetric / Safe)
            radius = 18
            group = "safe_symmetric"
        elif c_node.has_crypto:
            color = "#f97316"  # Orange (Direct Crypto Source)
            radius = 18
            group = "crypto_source"
        elif c_node.r0_score > 0:
            color = "#3b82f6"  # Blue (Intermediary Router)
            radius = 14
            group = "intermediary"
        else:
            color = "#64748b"  # Slate Gray (Leaf Consumer)
            radius = 10
            group = "consumer"

        nodes_json.append({
            "id": c_node.node_id,
            "label": c_node.node_id,
            "file_path": c_node.file_path,
            "r0": c_node.r0_score,
            "has_crypto": c_node.has_crypto,
            "is_superspreader": c_node.is_superspreader,
            "is_pqc_anchor": c_node.is_pqc_anchor,
            "color": color,
            "size": radius,
            "group": group,
            "dependents": c_node.downstream_dependents,
        })

    links_json = []
    for u, v in G.edges():
        links_json.append({
            "source": u,
            "target": v,
            "value": 1,
        })

    graph_payload = {
        "nodes": nodes_json,
        "links": links_json,
    }

    return ContagionGraphResult(
        total_nodes=G.number_of_nodes(),
        total_edges=G.number_of_edges(),
        superspreaders=superspreaders,
        pqc_anchors=pqc_anchors,
        nodes=contagion_nodes,
        graph_json=graph_payload,
    )
