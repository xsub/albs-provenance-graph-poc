from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .graph import ProvenanceGraph


def graph_to_json(graph: ProvenanceGraph, pretty: bool = True) -> str:
    if pretty:
        return json.dumps(graph.to_dict(), indent=2, sort_keys=True)
    return json.dumps(graph.to_dict(), separators=(",", ":"), sort_keys=True)


def graph_to_dot(graph: ProvenanceGraph) -> str:
    lines = ["digraph albs_provenance {", "  rankdir=LR;", "  node [shape=box];"]
    for node in graph.nodes.values():
        label = f"{node.type}\\n{node.label}".replace('"', "'")
        lines.append(f'  "{node.id}" [label="{label}"];')
    for edge in graph.edges:
        relation = str(edge.relation).replace('"', "'")
        lines.append(f'  "{edge.source}" -> "{edge.target}" [label="{relation}"];')
    lines.append("}")
    return "\n".join(lines) + "\n"


def write_text(path: str | Path, content: str) -> None:
    Path(path).write_text(content, encoding="utf-8")


def as_interview_summary(graph: ProvenanceGraph) -> str:
    rpm_nodes = [node for node in graph.nodes.values() if node.type == "binary_rpm"]
    lines: list[str] = []
    for rpm in rpm_nodes:
        report: dict[str, Any] = graph.trust_report_for_rpm(rpm.id)
        lines.append(f"Package artifact: {rpm.label}")
        lines.append(f"Trust path complete: {report['complete']}")
        for name, value in report["checks"].items():
            lines.append(f"  - {name}: {value}")
    return "\n".join(lines) + "\n"
