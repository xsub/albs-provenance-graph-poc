from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class NodeType(StrEnum):
    SOURCE_PACKAGE = "source_package"
    GIT_REPOSITORY = "git_repository"
    GIT_COMMIT = "git_commit"
    NOTARIZED_REF = "notarized_ref"
    BUILD_TASK = "build_task"
    BUILD_ENVIRONMENT = "build_environment"
    SRPM = "srpm"
    BINARY_RPM = "binary_rpm"
    TEST_RESULT = "test_result"
    SIGNATURE = "signature"
    REPOSITORY_RELEASE = "repository_release"
    ERRATA = "errata"
    CVE = "cve"
    SBOM = "sbom"
    EXTERNAL_PACKAGE = "external_package"


class Relation(StrEnum):
    STORED_IN = "stored_in"
    POINTS_TO = "points_to"
    NOTARIZED_AS = "notarized_as"
    USED_BY = "used_by"
    BUILT_IN = "built_in"
    PRODUCES = "produces"
    TESTED_BY = "tested_by"
    SIGNED_AS = "signed_as"
    RELEASED_TO = "released_to"
    DESCRIBED_BY = "described_by"
    FIXES = "fixes"
    AFFECTED_BY = "affected_by"
    REQUIRES_RUNTIME = "requires_runtime"
    REQUIRES_BUILDTIME = "requires_buildtime"
    PROVIDES = "provides"
    SUPERSEDES = "supersedes"
    DERIVED_FROM = "derived_from"


@dataclass(frozen=True)
class Node:
    id: str
    type: str
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "type": self.type,
            "label": self.label,
            "metadata": self.metadata,
        }


@dataclass(frozen=True)
class Edge:
    source: str
    target: str
    relation: str
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "source": self.source,
            "target": self.target,
            "relation": self.relation,
            "metadata": self.metadata,
        }
