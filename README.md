# ALBS Provenance Graph PoC

Minimal Python proof of concept for an ALBS-style provenance-aware dependency graph.

This is not a replacement for AlmaLinux Build System. It is a read-model / graph projection showing how dependency intelligence for Enterprise Linux should preserve build provenance instead of treating RPM as just another generic package-manager adapter.

## Core idea

For ELS and security maintenance, the useful question is not only:

> Which package depends on which package?

The more important question is:

> Can this exact binary artifact be traced to trusted source refs, build tasks, signed release artifacts, SBOM metadata and errata/security context?

This PoC models the path:

```text
source package
  -> git repository
  -> exact git commit
  -> notarized source ref
  -> ALBS build task
  -> build environment
  -> SRPM / binary RPM
  -> test result
  -> signature
  -> repository release
  -> SBOM
  -> errata / CVE
```

## Why this matters

A generic dependency graph usually stores facts like:

```text
A requires B
```

That is insufficient for Enterprise Linux security work. ELS and RHEL-compatible distributions often rely on backported security fixes. Version-string comparison alone can be misleading. The graph needs package metadata, but it also needs provenance, release lineage and security metadata.

The Staff Engineer-level framing is:

> RPM dependencies are only one layer. For AlmaLinux/ELS inputs, ALBS provenance should be the backbone of the model.

## Repository layout

```text
albs-provenance-graph-poc/
  albs_graph/
    model.py          # Node/edge types
    graph.py          # Graph operations and trust checks
    mock_data.py      # Mock ALBS-style graph
    rpm_adapter.py    # Local rpm -qp adapter
    sbom_adapter.py   # Simple CycloneDX attachment helper
    errata_adapter.py # Simple errata/CVE attachment helper
    export.py         # JSON/DOT/interview summary exporters
    cli.py            # Command-line interface
  examples/
  tests/
  pyproject.toml
  README.md
```

## Install for development

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -e '.[dev]'
```

## Run mock graph

```bash
albs-graph mock openssl
```

Example output:

```text
Package artifact: openssl-libs-3.0.7-28.el9_4.x86_64.rpm
Trust path complete: True
  - has_build_task: True
  - has_signature: True
  - has_release: True
  - has_sbom: True
  - has_errata_link: True
  - has_notarized_source_ref: True
```

## Export JSON

```bash
albs-graph mock openssl --format json -o examples/openssl_graph.json
```

## Export DOT graph

```bash
albs-graph mock openssl --format dot -o examples/openssl_graph.dot
```

Render with Graphviz:

```bash
dot -Tsvg examples/openssl_graph.dot -o examples/openssl_graph.svg
```

## Inspect local RPM metadata

Requires local `rpm` tooling:

```bash
albs-graph rpm ./some-package.rpm --format json
```

This mode only extracts `Provides` and `Requires`. It intentionally does not claim full ALBS provenance. It demonstrates how plain RPM metadata is only a partial layer compared with ALBS-backed provenance.

## Interview explanation

```bash
albs-graph explain openssl
```

## Current scope

Implemented:

- canonical node and edge model
- mock ALBS-style provenance graph
- trust-path report for a binary RPM artifact
- JSON export
- DOT export
- simple local RPM adapter
- simple CycloneDX SBOM attachment helper
- simple errata/CVE attachment helper
- tests

Not implemented in this init version:

- live ALBS API ingestion
- live PULP ingestion
- live git.almalinux.org crawling
- real immudb verification
- real AlmaLinux errata API integration
- libsolv/dnf resolver validation

Those are deliberate next steps. The init version is meant to show the model, architecture and reasoning.

## Next engineering steps

1. Add live ingestion from public AlmaLinux/ALBS-facing metadata where available.
2. Add repository metadata parsing: primary.xml, filelists.xml, updateinfo.xml.
3. Add libsolv/dnf-based validation for runtime dependency resolution.
4. Add source package to binary package lineage validation.
5. Add SBOM ingestion from AlmaLinux SBOM service / generated CycloneDX files.
6. Add errata/CVE correlation.
7. Add graph queries for ELS questions:
   - Which released RPMs came from this source commit?
   - Which packages are affected by this CVE?
   - Which packages have a complete trusted provenance path?
   - Which packages depend on a vulnerable artifact at runtime?
   - Which ELS package has a fix backported despite an older upstream version string?
