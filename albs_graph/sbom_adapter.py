from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .graph import ProvenanceGraph
from .model import Node, NodeType, Relation


def attach_cyclonedx_sbom(graph: ProvenanceGraph, rpm_node_id: str, sbom_path: str | Path) -> None:
    path = Path(sbom_path)
    data: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    sbom_id = f"sbom:{path.name}"
    graph.add_node(
        Node(
            sbom_id,
            NodeType.SBOM,
            path.name,
            {
                "format": "CycloneDX",
                "bomFormat": data.get("bomFormat"),
                "specVersion": data.get("specVersion"),
            },
        )
    )
    graph.add_edge(rpm_node_id, sbom_id, Relation.DESCRIBED_BY)

    for component in data.get("components", []):
        name = component.get("name")
        version = component.get("version", "unknown")
        if not name:
            continue
        component_id = f"sbom-component:{name}:{version}"
        graph.add_node(
            Node(
                component_id,
                NodeType.EXTERNAL_PACKAGE,
                f"{name} {version}",
                {"source": "CycloneDX", "component": component},
            )
        )
        graph.add_edge(sbom_id, component_id, Relation.DESCRIBED_BY)
