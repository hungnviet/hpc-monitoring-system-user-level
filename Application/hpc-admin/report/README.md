# HPC Admin Web Application — Thesis Report

This folder contains the full thesis report for the `hpc-admin` Next.js web application. Each chapter is a separate Markdown file so it can be edited independently and later imported into the final thesis template (LaTeX / Word).

## Table of contents

| # | Chapter | File |
|---|---------|------|
| 1 | Introduction | [01-introduction.md](01-introduction.md) |
| 2 | System Analysis | [02-analysis.md](02-analysis.md) |
| 3 | Architecture and Design | [03-architecture-design.md](03-architecture-design.md) |
| 4 | Implementation | [04-implementation.md](04-implementation.md) |
| 5 | Testing | [05-testing.md](05-testing.md) |
| 6 | Conclusion and Future Work | [06-conclusion.md](06-conclusion.md) |

## Supporting material

| Topic | File |
|-------|------|
| All diagrams collected in one place | [diagrams.md](diagrams.md) |
| Appendix A — API endpoint catalogue | [appendix-a-api-catalog.md](appendix-a-api-catalog.md) |
| Appendix B — etcd key reference | [appendix-b-etcd-keys.md](appendix-b-etcd-keys.md) |
| Appendix C — Database DDL | [appendix-c-db-schema.md](appendix-c-db-schema.md) |
| Appendix D — Screenshots per page | [appendix-d-screenshots.md](appendix-d-screenshots.md) |

## Style guide for further edits

- **Scope:** only the Next.js web app `hpc-admin`. The Python pipeline (`compute-node-agent`, `collect-agent`, Kafka, etcd, TimescaleDB, Grafana) is treated as *environment* in Chapter 2 and referenced as external dependencies afterwards.
- **Language:** English, Bachelor thesis level.
- **File paths:** always cite real paths in the repository so the supervisor can verify every claim.
- **Diagrams:** all diagrams are authored in Mermaid inside [diagrams.md](diagrams.md) and re-used by reference from the chapters. When exporting to the final template, render them to SVG or PNG.
- **Code snippets:** keep them short (10–20 lines) and cite the file path + line range. Do not paste entire files.
