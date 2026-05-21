from __future__ import annotations

import argparse
import sys

from .export import as_interview_summary, graph_to_dot, graph_to_json, write_text
from .mock_data import build_mock_package_graph
from .rpm_adapter import RpmQueryError, graph_from_local_rpm


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="albs-graph",
        description="PoC CLI for ALBS-style provenance-aware dependency graphs",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    mock = sub.add_parser("mock", help="build a mock ALBS provenance graph")
    mock.add_argument("package", nargs="?", default="openssl")
    mock.add_argument("--format", choices=("summary", "json", "dot"), default="summary")
    mock.add_argument("--output", "-o")

    rpm = sub.add_parser("rpm", help="inspect a local RPM with rpm -qp")
    rpm.add_argument("path")
    rpm.add_argument("--format", choices=("json", "dot"), default="json")
    rpm.add_argument("--output", "-o")

    explain = sub.add_parser("explain", help="print interview-oriented explanation for the PoC")
    explain.add_argument("package", nargs="?", default="openssl")

    return parser


def emit(content: str, output: str | None) -> None:
    if output:
        write_text(output, content)
    else:
        print(content, end="")


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)

    try:
        if args.command == "mock":
            graph = build_mock_package_graph(args.package)
            if args.format == "json":
                emit(graph_to_json(graph), args.output)
            elif args.format == "dot":
                emit(graph_to_dot(graph), args.output)
            else:
                emit(as_interview_summary(graph), args.output)
            return 0

        if args.command == "rpm":
            graph = graph_from_local_rpm(args.path)
            if args.format == "dot":
                emit(graph_to_dot(graph), args.output)
            else:
                emit(graph_to_json(graph), args.output)
            return 0

        if args.command == "explain":
            text = f"""ALBS Provenance Graph PoC for package: {args.package}

This is a read-model, not a replacement for ALBS.
The point is to preserve the Enterprise Linux build provenance chain:
source package -> git repository -> exact commit -> notarized ref -> ALBS build task -> SRPM/RPM artifacts -> test/sign/release state -> SBOM/errata/CVE links.

The main engineering claim is that ELS/security dependency intelligence cannot be reduced to generic package-manager parsing. For AlmaLinux/RPM inputs, the graph must preserve ALBS context: source provenance, notarization, distro version, architecture, repository release and security metadata.
"""
            emit(text, None)
            return 0

    except (RpmQueryError, FileNotFoundError, ValueError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
