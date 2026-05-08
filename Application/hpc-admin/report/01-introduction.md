# Chapter 1 — Introduction

> **Estimated length:** 4–6 pages.
> **Purpose:** frame the problem and the work. No architecture, no code.

## 1.1 Context

High-performance computing (HPC) clusters are shared facilities that host large numbers of compute-intensive workloads — scientific simulations, machine learning training jobs, data-analysis pipelines — on behalf of many users simultaneously. To keep such a cluster healthy, administrators must continuously observe the resources it consumes: CPU load, memory pressure, GPU utilization, disk and network throughput. Continuous observation is necessary for three distinct reasons.

1. **Operational awareness.** Nodes fail, jobs crash, and collection agents lose connectivity. Without a live view of every node an administrator cannot react in time.
2. **Historical accountability.** To plan capacity, investigate anomalies, or bill user groups fairly, an administrator needs historical data per node, per application, and per user, stored at a resolution that supports drill-down.
3. **Configuration governance.** The data-collection pipeline itself must be tunable — sampling windows, heartbeat intervals, filtering and aggregation rules, alert thresholds — and every change must be auditable.

In the thesis project, the pipeline that *produces* the metrics (compute-node agents, collect agents, Kafka broker, TimescaleDB, etcd for live configuration, Grafana for visualization) is already built as a separate subsystem `monitor-data-pipeline`. This report documents the **administrative web application** that *consumes and controls* that pipeline: [Application/hpc-admin](../).

## 1.2 Problem statement

Before this application existed, administrators of the cluster had to:

- open Grafana directly to see real-time panels, with no higher-level context;
- run ad-hoc SQL against TimescaleDB to answer questions such as *"which user consumed the most GPU memory last week?"*;
- edit etcd keys by hand with `etcdctl` to change a collection window or an alert threshold;
- keep no record of *who* changed *what*, *when*, or *why*.

In other words, there was a functional data pipeline but no single pane of glass to operate it. The administrator's experience was fragmented and error-prone, and changes to pipeline configuration were neither validated nor auditable.

The goal of this thesis is therefore to design and build a web-based administrative console that unifies real-time monitoring, historical analytics, AI-assisted exploration, and dynamic configuration of the HPC monitoring pipeline, while being safe to operate and easy to extend.

## 1.3 Objectives

The application must deliver four product-level capabilities, each mapped to a chapter of requirements in Chapter 2:

1. **Real-time resource monitoring** at cluster and per-node level by embedding the existing Grafana panels inside the admin UI.
2. **Historical usage tracking** at three levels of aggregation — node, application, and user — over data already stored in TimescaleDB hypertables.
3. **AI-assisted charting**: accept a natural-language question from the administrator and return either a generated chart or an embedded Grafana panel, by delegating to a separate AI microservice built as part of the same thesis work.
4. **Dynamic pipeline configuration**: edit node cluster membership (which node reports to which collect agent), collection intervals, pre-processing rules (filter / aggregate / derive), and alert thresholds, with versioning, audit logs, and safe rollout to etcd.

Supporting (non-functional) objectives:

- Single administrator role for now, with an architecture that is straightforward to extend to RBAC later.
- Type-safe stack (TypeScript end to end) for maintainability.
- Honest handling of external failures (etcd or AI service down): the UI must degrade gracefully rather than crash.

## 1.4 Scope

**In scope** (documented in this report):

- The Next.js 16 application at `Application/hpc-admin`, including:
  - the front-end pages under `src/app/(auth)` and `src/app/(protected)`,
  - the API routes under `src/app/api`,
  - the database schema under `db/schema.sql` for the admin-owned tables,
  - the integration with TimescaleDB (read-only for analytics), etcd (read/write for live pipeline configuration), Grafana (iframe embedding), and the AI microservice.

**Out of scope** (mentioned only as context):

- The Python data pipeline (`monitor-data-pipeline/compute-node-agent`, `monitor-data-pipeline/collect-agent`, Kafka, etcd server setup). Its responsibilities are summarised in [Chapter 2 §2.1](02-analysis.md#21-environment-and-related-components) and otherwise treated as a black box.
- The internals of the AI microservice that the application calls at `http://localhost:5000/visualize`. It is also part of the author's thesis work but is documented elsewhere; this report describes only the integration contract (request/response, sequence) in [Chapter 3 §3.9](03-architecture-design.md#39-external-integrations-design) and [Chapter 4 §4.10](04-implementation.md#410-ai-chart-generator-integration).
- The Grafana dashboard design itself; the application only embeds existing panels.

## 1.5 Methodology

The application was developed iteratively in four phases that correspond one-to-one with the remaining chapters:

1. **Requirement analysis** — the environment, stakeholders, functional and non-functional requirements, and use cases were written down first. This produced the catalogue in Chapter 2.
2. **Design** — technology stack decisions, the high-level architecture, the data model, the etcd key schema, and the API contract were fixed before any code was written. This produced Chapter 3.
3. **Implementation** — the code was built module by module, with the order following the data-flow direction (data layer → API routes → pages). Commit history shows the incremental build. This produced Chapter 4.
4. **Testing** — the testing strategy (unit, integration, end-to-end, manual, non-functional) was designed around the use-case catalogue, with the intent to execute before defense. This produced Chapter 5.

No formal methodology framework (Scrum, Kanban) was imposed because the team size is one; however, the four phases mirror the analysis–design–implementation–testing loop of a classical waterfall plus the continuous small iterations typical of solo development.

## 1.6 Report structure

- **Chapter 2 — System Analysis.** Actors, environment, functional and non-functional requirements, use cases, requirements traceability.
- **Chapter 3 — Architecture and Design.** Technology stack choices, layered architecture, data model, etcd key schema, API design, security, external integrations, configuration governance.
- **Chapter 4 — Implementation.** Module-by-module walkthrough of the code: bootstrap, authentication, data layer, node registry, live pipeline configuration, analytics, real-time monitoring, configuration management, notifications, AI chart integration, chat, styling, cross-cutting concerns.
- **Chapter 5 — Testing.** Proposed test pyramid (unit, integration, end-to-end, manual, non-functional), tooling, environment, test case template, results template.
- **Chapter 6 — Conclusion and Future Work.** Summary of contributions, honest limitations, future work, personal reflection.
- **Appendices.** API endpoint catalogue, etcd key reference, database DDL, screenshots per page.
