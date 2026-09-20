"""
ECDAT Father Marko Cryptographic Lineage Engine:
Constructs a Tripartite Cryptographic Lineage Graph:
Upstream Ingress Sources (ENV, Config, DB) ──► Cryptographic Nexus (AST Call-Sites) ──► Downstream Egress Sinks (Redis, DB, Ledger).
Strictly zero-regex: Operates exclusively on Pygments token streams and AST visitors.
"""

from pathlib import Path
from typing import List, Dict, Set, Any, Optional, Tuple
from pygments.lexers import get_lexer_for_filename, JavascriptLexer, PythonLexer, GoLexer, JavaLexer
from pygments.token import Token

from ecdat.lineage.models import (
    LineageNode,
    LineageEdge,
    LineageGraphResult,
    LineageCategory,
    LineageSourceType,
)
from ecdat.scanners.contracts.evaluator import CallSiteEvaluator, DynamicIngress, StaticResolution
from ecdat.models import CryptoAsset


def analyze_crypto_lineage(
    file_paths: List[str],
    crypto_assets: Optional[List[CryptoAsset]] = None,
    target_dir: Optional[str] = None,
) -> LineageGraphResult:
    """
    Analyzes all source files to construct the Father Marko Tripartite Lineage Graph.
    Extracts:
    1. Ingress Nodes: Environment variables, configuration lookups, and DB model fields.
    2. Nexus Nodes: Cryptographic invocation call-sites with file and line provenance.
    3. Egress Nodes: Persistence destinations (Redis cache, streams, databases, ledgers).
    """
    nodes_dict: Dict[str, LineageNode] = {}
    edges_list: List[LineageEdge] = []
    seen_edge_keys: Set[str] = set()

    base_path = Path(target_dir).resolve() if target_dir else None

    for fpath_str in file_paths:
        p = Path(fpath_str)
        if not p.is_file():
            continue

        rel_path = str(p.relative_to(base_path)) if base_path and p.is_relative_to(base_path) else p.name
        suffix = p.suffix.lower()

        if suffix not in {".js", ".mjs", ".cjs", ".ts", ".tsx", ".py", ".go", ".java"}:
            continue

        try:
            content = p.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue

        # Select appropriate Pygments Lexer
        if suffix in {".js", ".mjs", ".cjs", ".ts", ".tsx"}:
            lexer = JavascriptLexer()
        elif suffix == ".py":
            lexer = PythonLexer()
        elif suffix == ".go":
            lexer = GoLexer()
        elif suffix == ".java":
            lexer = JavaLexer()
        else:
            continue

        raw_tokens = list(lexer.get_tokens_unprocessed(content))
        # Format: [(offset, ttype, val)] -> sort by offset
        raw_tokens.sort(key=lambda t: t[0])
        tokens = [(t[1], t[2], t[0]) for t in raw_tokens]

        n_tokens = len(tokens)
        if n_tokens == 0:
            continue

        def get_line(offset: int) -> int:
            return content.count("\n", 0, offset) + 1

        # File-level ingress sources and egress sinks discovered in this file
        file_ingress_nodes: List[LineageNode] = []
        file_egress_nodes: List[LineageNode] = []

        # Scan for Ingress Sources in the file (.env, config, DB)
        for idx in range(n_tokens):
            val = tokens[idx][1]
            off = tokens[idx][2]

            # Ingress 1: Node.js process.env.KEY or process.env['KEY']
            if val == "process" and idx + 2 < n_tokens:
                if tokens[idx + 1][1] == "." and tokens[idx + 2][1] == "env":
                    var_name = None
                    if idx + 4 < n_tokens and tokens[idx + 3][1] == ".":
                        var_name = tokens[idx + 4][1]
                    elif idx + 4 < n_tokens and tokens[idx + 3][1] == "[":
                        var_name = CallSiteEvaluator._strip_quotes(tokens[idx + 4][1])
                    if var_name and var_name.isidentifier() and var_name not in {"NODE_ENV", "PORT", "LOG_LEVEL"}:
                        ing_id = f"INGRESS:ENV:{var_name}"
                        if ing_id not in nodes_dict:
                            ing_node = LineageNode(
                                node_id=ing_id,
                                label=f"ENV: {var_name}",
                                category=LineageCategory.INGRESS,
                                source_type=LineageSourceType.ENV,
                                file_path=rel_path,
                                line_number=get_line(off),
                                details={"key": var_name, "type": "ENV", "fallback": None}
                            )
                            nodes_dict[ing_id] = ing_node
                        file_ingress_nodes.append(nodes_dict[ing_id])

            # Ingress 2: Python os.environ['KEY'] or os.getenv('KEY')
            elif val == "os" and idx + 2 < n_tokens:
                if tokens[idx + 1][1] == "." and tokens[idx + 2][1] in {"environ", "getenv"}:
                    if idx + 4 < n_tokens and tokens[idx + 3][1] in {"[", "("}:
                        var_name = CallSiteEvaluator._strip_quotes(tokens[idx + 4][1])
                        if var_name and var_name not in {"PATH", "PYTHONPATH"}:
                            ing_id = f"INGRESS:ENV:{var_name}"
                            if ing_id not in nodes_dict:
                                ing_node = LineageNode(
                                    node_id=ing_id,
                                    label=f"ENV: {var_name}",
                                    category=LineageCategory.INGRESS,
                                    source_type=LineageSourceType.ENV,
                                    file_path=rel_path,
                                    line_number=get_line(off),
                                    details={"key": var_name, "type": "ENV", "fallback": None}
                                )
                                nodes_dict[ing_id] = ing_node
                            file_ingress_nodes.append(nodes_dict[ing_id])

            # Ingress 3: Java System.getenv("KEY")
            elif val == "System" and idx + 4 < n_tokens:
                if tokens[idx + 1][1] == "." and tokens[idx + 2][1] == "getenv" and tokens[idx + 3][1] == "(":
                    var_name = CallSiteEvaluator._strip_quotes(tokens[idx + 4][1])
                    if var_name and var_name not in {"JAVA_HOME", "PATH"}:
                        ing_id = f"INGRESS:ENV:{var_name}"
                        if ing_id not in nodes_dict:
                            ing_node = LineageNode(
                                node_id=ing_id,
                                label=f"ENV: {var_name}",
                                category=LineageCategory.INGRESS,
                                source_type=LineageSourceType.ENV,
                                file_path=rel_path,
                                line_number=get_line(off),
                                details={"key": var_name, "type": "ENV", "fallback": None}
                            )
                            nodes_dict[ing_id] = ing_node
                        file_ingress_nodes.append(nodes_dict[ing_id])

            # Ingress 4: config.get("KEY") or appConfig["KEY"]
            elif val in {"config", "appConfig", "app_config", "settings"} and idx + 2 < n_tokens:
                if tokens[idx + 1][1] == "." and tokens[idx + 2][1] == "get" and idx + 4 < n_tokens:
                    cfg_key = CallSiteEvaluator._strip_quotes(tokens[idx + 4][1])
                    if cfg_key:
                        ing_id = f"INGRESS:CONFIG:{cfg_key}"
                        if ing_id not in nodes_dict:
                            ing_node = LineageNode(
                                node_id=ing_id,
                                label=f"CONFIG: {cfg_key}",
                                category=LineageCategory.INGRESS,
                                source_type=LineageSourceType.CONFIG,
                                file_path=rel_path,
                                line_number=get_line(off),
                                details={"key": cfg_key, "type": "CONFIG", "fallback": None}
                            )
                            nodes_dict[ing_id] = ing_node
                        file_ingress_nodes.append(nodes_dict[ing_id])

        # Scan for Egress Sinks in the file (Redis, Fabric, DB, etc.)
        for idx in range(n_tokens):
            val = tokens[idx][1]
            off = tokens[idx][2]

            # Egress 1: Redis Stream (XADD) or Redis Cache (set with EX)
            if val in {"XADD", "xadd"} or (val == "xAdd" and idx + 1 < n_tokens):
                sink_id = f"EGRESS:STREAM:redis_stream:{rel_path}"
                if sink_id not in nodes_dict:
                    sink_node = LineageNode(
                        node_id=sink_id,
                        label="Redis Stream (In-Memory Queue)",
                        category=LineageCategory.EGRESS,
                        source_type=LineageSourceType.STREAM,
                        file_path=rel_path,
                        line_number=get_line(off),
                        details={"storage": "Redis 7 Stream", "retention": "Volatile / Rolling Consumption"}
                    )
                    nodes_dict[sink_id] = sink_node
                    file_egress_nodes.append(sink_node)

            if val in {"redisClient", "redis", "client"} and idx + 2 < n_tokens:
                if tokens[idx + 1][1] == "." and tokens[idx + 2][1] in {"set", "setEx", "hSet", "lPush", "LPUSH"}:
                    sink_id = f"EGRESS:CACHE:redis_store:{rel_path}"
                    if sink_id not in nodes_dict:
                        sink_node = LineageNode(
                            node_id=sink_id,
                            label="Redis Ephemeral Store / Cache",
                            category=LineageCategory.EGRESS,
                            source_type=LineageSourceType.CACHE,
                            file_path=rel_path,
                            line_number=get_line(off),
                            details={"storage": "Redis 7 In-Memory KeyStore", "retention": "Rolling Lease / TTL"}
                        )
                        nodes_dict[sink_id] = sink_node
                        file_egress_nodes.append(sink_node)

            # Egress 2: Hyperledger Fabric Ledger / CouchDB World-State
            if val in {"gateway", "network", "contract"} and idx + 2 < n_tokens:
                if tokens[idx + 1][1] == "." and tokens[idx + 2][1] in {"submitTransaction", "evaluateTransaction", "submit"}:
                    sink_id = "EGRESS:LEDGER:fabric_smartbft"
                    if sink_id not in nodes_dict:
                        sink_node = LineageNode(
                            node_id=sink_id,
                            label="Fabric Ledger (CouchDB / SmartBFT)",
                            category=LineageCategory.EGRESS,
                            source_type=LineageSourceType.LEDGER,
                            file_path=rel_path,
                            line_number=get_line(off),
                            details={"consensus": "SmartBFT", "immutability": "Permanent Ledger Commit"}
                        )
                        nodes_dict[sink_id] = sink_node
                        file_egress_nodes.append(sink_node)

            # Egress 3: SQL / ORM Database
            if val in {"db", "repository", "orm", "prisma", "sequelize"} and idx + 2 < n_tokens:
                if tokens[idx + 1][1] == "." and tokens[idx + 2][1] in {"insert", "save", "update", "create"}:
                    sink_id = f"EGRESS:DATABASE:sql_store:{rel_path}"
                    if sink_id not in nodes_dict:
                        sink_node = LineageNode(
                            node_id=sink_id,
                            label="Database Table Persistence",
                            category=LineageCategory.EGRESS,
                            source_type=LineageSourceType.DATABASE,
                            file_path=rel_path,
                            line_number=get_line(off),
                            details={"storage": "Relational/NoSQL Database", "retention": "Schema Defined"}
                        )
                        nodes_dict[sink_id] = sink_node
                        file_egress_nodes.append(sink_node)

        # Scan for Cryptographic Call-Sites (Nexus Nodes)
        for idx in range(n_tokens):
            val = tokens[idx][1]
            off = tokens[idx][2]

            is_crypto_sink = False
            call_label = ""
            arg_index = -1

            # Pattern JS: crypto.createCipheriv(arg0, ...)
            if val == "createCipheriv" and idx > 1 and tokens[idx - 1][1] == ".":
                is_crypto_sink = True
                call_label = "crypto.createCipheriv"
                arg_index = idx + 2  # token after '('

            # Pattern JS: crypto.generateKeyPair('rsa', ...) or ('ec', ...)
            elif val in {"generateKeyPair", "generateKeyPairSync"} and idx > 1 and tokens[idx - 1][1] == ".":
                is_crypto_sink = True
                call_label = f"crypto.{val}"
                arg_index = idx + 2

            # Pattern Forge RSA: forge.pki.rsa.generateKeyPair({ bits: ... })
            elif val == "generateKeyPair" and idx >= 6:
                if (tokens[idx - 1][1] == "." and tokens[idx - 2][1] == "rsa" and
                    tokens[idx - 3][1] == "." and tokens[idx - 4][1] == "pki" and
                    tokens[idx - 5][1] == "." and tokens[idx - 6][1] == "forge"):
                    is_crypto_sink = True
                    call_label = "forge.pki.rsa.generateKeyPair"
                    # Search for 'bits' argument inside curly braces
                    for k in range(idx + 1, min(n_tokens, idx + 20)):
                        if tokens[k][1] == "bits" and k + 2 < n_tokens and tokens[k + 1][1] == ":":
                            arg_index = k + 2
                            break
                        if tokens[k][1] == ")":
                            break

            # Pattern PQC: ml_dsa65.sign(msg, sk) or ml_dsa65.keygen()
            elif val in {"ml_dsa44", "ml_dsa65", "ml_dsa87", "ml_kem768", "ml_kem1024"}:
                if idx + 2 < n_tokens and tokens[idx + 1][1] == ".":
                    op = tokens[idx + 2][1]
                    if op in {"keygen", "sign", "verify", "encapsulate", "decapsulate"}:
                        is_crypto_sink = True
                        call_label = f"{val}.{op}"
                        arg_index = idx + 4 if idx + 3 < n_tokens and tokens[idx + 3][1] == "(" else -1

            # Pattern RSA Blind Service: rsaBlindService.signBlinded()
            elif val in {"rsaBlindService", "rsa_blind_service"} and idx + 2 < n_tokens:
                if tokens[idx + 1][1] == "." and tokens[idx + 2][1] in {"signBlinded", "verifyAsync"}:
                    is_crypto_sink = True
                    call_label = f"rsaBlindService.{tokens[idx + 2][1]}"
                    arg_index = idx + 4 if idx + 3 < n_tokens and tokens[idx + 3][1] == "(" else -1

            # Pattern Java: Cipher.getInstance(...), KeyGenerator.getInstance(...)
            elif val == "getInstance" and idx > 1 and tokens[idx - 1][1] == ".":
                receiver = tokens[idx - 2][1]
                if receiver in {"Cipher", "KeyGenerator", "SecretKeyFactory", "MessageDigest", "Signature", "Mac"}:
                    is_crypto_sink = True
                    call_label = f"{receiver}.getInstance"
                    arg_index = idx + 2

            if is_crypto_sink:
                line_no = get_line(off)
                nexus_id = f"NEXUS:{rel_path}:{line_no}"

                if nexus_id not in nodes_dict:
                    nexus_node = LineageNode(
                        node_id=nexus_id,
                        label=f"{call_label} [L{line_no}]",
                        category=LineageCategory.NEXUS,
                        source_type=LineageSourceType.CALLSITE,
                        file_path=rel_path,
                        line_number=line_no,
                        details={"call": call_label, "file": rel_path, "line": line_no}
                    )
                    nodes_dict[nexus_id] = nexus_node

                # Evaluate argument if present
                if arg_index > 0 and arg_index < n_tokens:
                    res, _ = CallSiteEvaluator.evaluate_argument_tokens(tokens, arg_index)

                    # BIFURCATION LOGIC:
                    # 1. StaticResolution (e.g. "A~ES".replace("~", "")) is CLOSED-WORLD -> CBOM ONLY.
                    #    It is SUPPRESSED from the Father Marko Lineage Graph!
                    # 2. DynamicIngress (e.g. process.env.VAR) is OPEN-WORLD -> FATHER MARKO ONLY.
                    if isinstance(res, DynamicIngress):
                        ingress_id = f"INGRESS:{res.source_type}:{res.key_name}"
                        if ingress_id not in nodes_dict:
                            ingress_type = LineageSourceType.ENV if res.source_type == "ENV" else (
                                LineageSourceType.CONFIG if res.source_type == "CONFIG" else (
                                    LineageSourceType.DATABASE if res.source_type == "DATABASE" else LineageSourceType.PARAMETER
                                )
                            )
                            nodes_dict[ingress_id] = LineageNode(
                                node_id=ingress_id,
                                label=f"{res.source_type}: {res.key_name}",
                                category=LineageCategory.INGRESS,
                                source_type=ingress_type,
                                file_path=rel_path,
                                line_number=line_no,
                                details={
                                    "key": res.key_name,
                                    "type": res.source_type,
                                    "fallback": res.fallback_value
                                }
                            )

                        edge_key = f"{ingress_id}->{nexus_id}"
                        if edge_key not in seen_edge_keys:
                            seen_edge_keys.add(edge_key)
                            edges_list.append(LineageEdge(
                                source_id=ingress_id,
                                target_id=nexus_id,
                                edge_type="BINDS_PARAMETER",
                                label=f"binds: {res.key_name}"
                            ))

                # Connect file-level ingress sources (.env, config) to this cryptographic nexus
                for ing_node in file_ingress_nodes:
                    edge_key = f"{ing_node.node_id}->{nexus_id}"
                    if edge_key not in seen_edge_keys:
                        seen_edge_keys.add(edge_key)
                        edges_list.append(LineageEdge(
                            source_id=ing_node.node_id,
                            target_id=nexus_id,
                            edge_type="BINDS_PARAMETER",
                            label=f"supplies: {ing_node.details.get('key', '')}"
                        ))

                # Connect Nexus to Egress Sinks in the same file/module
                for eg_node in file_egress_nodes:
                    edge_key = f"{nexus_id}->{eg_node.node_id}"
                    if edge_key not in seen_edge_keys:
                        seen_edge_keys.add(edge_key)
                        edges_list.append(LineageEdge(
                            source_id=nexus_id,
                            target_id=eg_node.node_id,
                            edge_type="CIPHERTEXT_EGRESS",
                            label="stores payload"
                        ))

    # Keep only nodes that participate in at least one edge (prunes orphan static calls)
    connected_node_ids = {e.source_id for e in edges_list} | {e.target_id for e in edges_list}
    active_nodes = [n for n in nodes_dict.values() if n.node_id in connected_node_ids]
    active_nodes_dict = {n.node_id: n for n in active_nodes}

    # Extract Hub & Spoke Provenance for Father Marko (.env, config, database -> consuming files)
    fm_hubs = []
    fm_spokes = []
    fm_edges = []
    seen_spoke_ids: Set[str] = set()

    for n in active_nodes:
        if n.category == LineageCategory.INGRESS and n.source_type in {
            LineageSourceType.ENV,
            LineageSourceType.CONFIG,
            LineageSourceType.DATABASE,
        }:
            connected_spoke_ids = [e.target_id for e in edges_list if e.source_id == n.node_id]
            badge_label = f".{n.source_type.value}" if n.source_type == LineageSourceType.ENV else n.source_type.value
            fm_hubs.append({
                "id": n.node_id,
                "label": n.details.get("key", n.label),
                "source_type": n.source_type.value,
                "badge": badge_label,
                "key": n.details.get("key", ""),
                "fallback": n.details.get("fallback", None),
                "file_path": n.file_path,
                "line_number": n.line_number,
                "consumer_count": len(connected_spoke_ids)
            })

            for s_id in connected_spoke_ids:
                s_node = active_nodes_dict.get(s_id)
                if s_node:
                    if s_id not in seen_spoke_ids:
                        seen_spoke_ids.add(s_id)
                        fm_spokes.append({
                            "id": s_node.node_id,
                            "label": f"{Path(s_node.file_path).name if s_node.file_path else 'AST'}:{s_node.line_number or ''}",
                            "file_path": s_node.file_path,
                            "line_number": s_node.line_number,
                            "call": s_node.details.get("call", s_node.label),
                            "hub_id": n.node_id
                        })
                    fm_edges.append({
                        "source": n.node_id,
                        "target": s_id,
                        "label": f"binds: {n.details.get('key', '')}"
                    })

    has_ingress = len(fm_hubs) > 0

    # Extract Granular Variable Flows for Contagion Micro Flow Drawer
    variable_flows = []
    nexus_nodes_active = [n for n in active_nodes if n.category == LineageCategory.NEXUS]

    for nex in nexus_nodes_active:
        in_edges = [e for e in edges_list if e.target_id == nex.node_id]
        out_edges = [e for e in edges_list if e.source_id == nex.node_id]

        input_node = active_nodes_dict.get(in_edges[0].source_id) if in_edges else None
        sink_nodes_list = [active_nodes_dict[e.target_id] for e in out_edges if e.target_id in active_nodes_dict]

        if input_node or sink_nodes_list:
            flow_item = {
                "id": f"FLOW:{nex.node_id}",
                "module": nex.file_path,
                "input": {
                    "id": input_node.node_id,
                    "label": input_node.details.get("key", input_node.label),
                    "source_type": input_node.source_type.value,
                    "badge": f".{input_node.source_type.value}" if input_node.source_type == LineageSourceType.ENV else input_node.source_type.value,
                    "fallback": input_node.details.get("fallback", None)
                } if input_node else None,
                "nexus": {
                    "id": nex.node_id,
                    "label": nex.label,
                    "call": nex.details.get("call", nex.label),
                    "file": nex.file_path,
                    "line": nex.line_number
                },
                "sinks": [
                    {
                        "id": s.node_id,
                        "label": s.label,
                        "source_type": s.source_type.value,
                        "storage": s.details.get("storage", s.label),
                        "retention": s.details.get("retention", "")
                    }
                    for s in sink_nodes_list
                ]
            }
            variable_flows.append(flow_item)

    # Format D3 stratified layout coordinates (x: column index, y: row index) for legacy compatibility
    ingress_nodes = [n for n in active_nodes if n.category == LineageCategory.INGRESS]
    nexus_nodes = [n for n in active_nodes if n.category == LineageCategory.NEXUS]
    egress_nodes = [n for n in active_nodes if n.category == LineageCategory.EGRESS]

    graph_nodes = []
    for idx, n in enumerate(ingress_nodes):
        d = n.model_dump() if hasattr(n, "model_dump") else n.dict()
        d["column"] = 0
        d["layer"] = "INGRESS"
        d["order"] = idx
        graph_nodes.append(d)

    for idx, n in enumerate(nexus_nodes):
        d = n.model_dump() if hasattr(n, "model_dump") else n.dict()
        d["column"] = 1
        d["layer"] = "NEXUS"
        d["order"] = idx
        graph_nodes.append(d)

    for idx, n in enumerate(egress_nodes):
        d = n.model_dump() if hasattr(n, "model_dump") else n.dict()
        d["column"] = 2
        d["layer"] = "EGRESS"
        d["order"] = idx
        graph_nodes.append(d)

    graph_links = [
        e.model_dump() if hasattr(e, "model_dump") else e.dict()
        for e in edges_list
        if e.source_id in active_nodes_dict and e.target_id in active_nodes_dict
    ]

    graph_json = {
        "nodes": graph_nodes,
        "links": graph_links,
        "has_ingress": has_ingress,
        "stats": {
            "ingress": len(fm_hubs),
            "nexus": len(fm_spokes),
            "egress": len(egress_nodes),
            "edges": len(graph_links),
            "has_ingress": has_ingress,
            "total_flows": len(variable_flows)
        },
        "father_marko": {
            "has_ingress": has_ingress,
            "hubs": fm_hubs,
            "spokes": fm_spokes,
            "edges": fm_edges,
            "stats": {
                "hubs": len(fm_hubs),
                "spokes": len(fm_spokes),
                "edges": len(fm_edges)
            }
        },
        "variable_flow": {
            "has_flows": len(variable_flows) > 0,
            "flows": variable_flows,
            "modules": sorted(list({f["module"] for f in variable_flows if f.get("module")})),
            "stats": {
                "total_flows": len(variable_flows),
                "modules_count": len({f["module"] for f in variable_flows if f.get("module")})
            }
        }
    }

    return LineageGraphResult(
        nodes=active_nodes,
        edges=[e for e in edges_list if e.source_id in active_nodes_dict and e.target_id in active_nodes_dict],
        ingress_count=len(fm_hubs),
        nexus_count=len(fm_spokes),
        egress_count=len(egress_nodes),
        graph_json=graph_json
    )
