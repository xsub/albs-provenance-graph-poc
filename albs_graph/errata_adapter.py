from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .graph import ProvenanceGraph
from .model import Node, NodeType, Relation


def attach_errata_file(graph: ProvenanceGraph, rpm_node_id: str, errata_path: str | Path) -> None:
    path = Path(errata_path)
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    errata_id = f"errata:{data.get('id', path.stem)}"
    graph.add_node(
        Node(
            errata_id,
            NodeType.ERRATA,
            str(data.get("id", path.stem)),
            {"type": data.get("type"), "severity": data.get("severity")},
        )
    )
    graph.add_edge(rpm_node_id, errata_id, Relation.FIXES)

    for cve in data.get("cves", []):
        cve_id = f"cve:{cve}"
        graph.add_node(Node(cve_id, NodeType.CVE, cve))
        graph.add_edge(errata_id, cve_id, Relation.FIXES)
