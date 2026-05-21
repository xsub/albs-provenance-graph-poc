from __future__ import annotations

from collections import defaultdict, deque
from typing import Any

from .model import Edge, Node, Relation


class ProvenanceGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, Node] = {}
        self.edges: list[Edge] = []

    def add_node(self, node: Node) -> None:
        if node.id in self.nodes:
            existing = self.nodes[node.id]
            if existing != node:
                raise ValueError(f"Conflicting node definition for {node.id}")
        self.nodes[node.id] = node

    def add_edge(self, source: str, target: str, relation: str, **metadata: Any) -> None:
        if source not in self.nodes:
            raise ValueError(f"Missing source node: {source}")
        if target not in self.nodes:
            raise ValueError(f"Missing target node: {target}")
        self.edges.append(Edge(source=source, target=target, relation=relation, metadata=metadata))

    def outgoing(self, node_id: str) -> list[Edge]:
        return [edge for edge in self.edges if edge.source == node_id]

    def incoming(self, node_id: str) -> list[Edge]:
        return [edge for edge in self.edges if edge.target == node_id]

    def find_by_type(self, node_type: str) -> list[Node]:
        return [node for node in self.nodes.values() if node.type == node_type]

    def reachable(self, start_node_id: str) -> set[str]:
        if start_node_id not in self.nodes:
            raise ValueError(f"Unknown node: {start_node_id}")
        adjacency: dict[str, list[str]] = defaultdict(list)
        for edge in self.edges:
            adjacency[edge.source].append(edge.target)
        seen: set[str] = set()
        queue: deque[str] = deque([start_node_id])
        while queue:
            current = queue.popleft()
            if current in seen:
                continue
            seen.add(current)
            queue.extend(adjacency[current])
        return seen

    def has_relation_path(self, source: str, target: str) -> bool:
        return target in self.reachable(source)

    def trust_report_for_rpm(self, rpm_node_id: str) -> dict[str, Any]:
        if rpm_node_id not in self.nodes:
            raise ValueError(f"Unknown RPM node: {rpm_node_id}")

        incoming_relations = {edge.relation for edge in self.incoming(rpm_node_id)}
        outgoing_relations = {edge.relation for edge in self.outgoing(rpm_node_id)}
        all_relations = incoming_relations | outgoing_relations

        checks = {
            "has_build_task": Relation.PRODUCES in incoming_relations,
            "has_signature": Relation.SIGNED_AS in outgoing_relations,
            "has_release": Relation.RELEASED_TO in outgoing_relations,
            "has_sbom": Relation.DESCRIBED_BY in outgoing_relations,
            "has_errata_link": Relation.FIXES in outgoing_relations or Relation.AFFECTED_BY in outgoing_relations,
        }

        # A complete source provenance path is checked by walking backwards through the known chain.
        build_tasks = [edge.source for edge in self.incoming(rpm_node_id) if edge.relation == Relation.PRODUCES]
        has_notarized_source = False
        for build_task in build_tasks:
            incoming_to_build = self.incoming(build_task)
            notarized_refs = [edge.source for edge in incoming_to_build if edge.relation == Relation.USED_BY]
            for notary in notarized_refs:
                if any(edge.target == notary and edge.relation == Relation.NOTARIZED_AS for edge in self.edges):
                    has_notarized_source = True

        checks["has_notarized_source_ref"] = has_notarized_source

        return {
            "rpm": rpm_node_id,
            "complete": all(checks.values()),
            "checks": checks,
            "relations_seen": sorted(str(relation) for relation in all_relations),
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [node.to_dict() for node in self.nodes.values()],
            "edges": [edge.to_dict() for edge in self.edges],
        }
