# Chapter 6 — Conclusion and Future Work

> **Estimated length:** 3–5 pages.

## 6.1 Summary of contributions

This thesis delivers `hpc-admin`, a single-page Next.js 16 web application that gives HPC administrators a unified console over an existing monitoring pipeline. The four product goals stated in §1.3 map directly to the modules in Chapter 4:

| Goal | Delivered through |
|---|---|
| Real-time resource monitoring | Grafana solo-panel iframes on `/dashboard` and `/dashboard/nodes/[nodeId]` (§4.7), composed from a hard-coded URL template and time-range selector. |
| Historical usage tracking | TimescaleDB queries against `node_status_hourly` and `user_app_hourly` exposed through `/api/analytics/*` and `/api/nodes/*`, consumed by `/analytics` and the node detail page via Recharts (§4.4, §4.6). |
| AI-assisted charting | Integration with a separate AI microservice at `http://localhost:5000/visualize`, with on-the-fly host rewriting of returned Grafana URLs (§4.10). |
| Dynamic pipeline configuration | CRUD on DB-backed `pipeline_rules`, `alert_rules`, and `collection_settings`, plus push-to-etcd fan-out and a governance layer (snapshot, version, audit, rollout) in §4.8. |

Architecturally, the application stays deliberately thin: a single Next.js process, two singletons (`pg.Pool`, `Etcd3`), two data stores with well-defined responsibilities, two external systems the browser speaks to directly. Every module follows the same *page → fetch → route handler → pool/etcd* shape, which should make the codebase easy for a second developer to pick up.

## 6.2 Limitations

It is important to acknowledge the gaps that remain. Each one has a corresponding item in §6.3.

1. **Single admin account.** Authentication uses a credentials provider whose only user lives in environment variables ([src/auth.ts](../src/auth.ts)). There is no role-based access control, no SSO, no account self-service.
2. **API routes are not protected by the proxy matcher.** The current matcher in [src/proxy.ts](../src/proxy.ts) excludes `/api/auth` but also leaves every other `/api/*` route unguarded. HTML pages are safe; JSON endpoints are not.
3. **AI chart and chat contracts are inconsistent.**
   - The AI chart page calls the external microservice directly and does **not** use the in-repo `/api/analytics/ai-chart` stub — the stub is dead code.
   - The chat page sends `{ messages: [...] }` while `/api/chat` reads `{ message }`, so the stub cannot see the latest user message.
4. **Custom dashboards are still mocked.** `/analytics/custom` reads from [src/lib/mockData/analytics.ts](../src/lib/mockData/analytics.ts) even though a `custom_dashboards` table exists in the DB schema. There is no persistence, so saved panels do not survive reloads.
5. **Grafana URLs are hardcoded in several pages.** Dashboard and node detail pages assemble iframe URLs from literal strings such as `http://10.1.8.155:3000/d-solo/adtfbh4/h6-monitoring?…`. Moving a cluster to a new host requires editing multiple files. `GrafanaPanel` even references an env var `GRAFANA_BASE_URL` in its placeholder text that is not actually read anywhere.
6. **Schema drift between the admin app and the collect agent.** The collect agent reads three distinct keys — `pipeline_stages`, `process_fields`, `comm_prefixes` — while the admin application still writes a single legacy `pipeline_rules` array. `threshold_rules` is consumed by both sides but the admin code uses the older JSON key `gpu_max_utilization_percent` whereas the agent expects `gpu_utilization_percent`. As a result, pushing configuration through the web UI does not fully reach the agent today.
6. **Observability is minimal.** Server-side `console.error` only. There are no metrics, no traces, no structured logs.
7. **No automated tests yet.** Chapter 5 proposes a full pyramid but execution is pending. The risk of regression on any refactor is therefore high.
8. **Known bug in `POST /api/nodes`.** Inserting a duplicate primary key returns a generic `500` instead of `409 Conflict`; the error payload does not describe the cause. Low priority but worth noting.

## 6.3 Future work

Grouped by effort and risk.

### Short term (1–2 weeks)

- **Protect `/api/*` by default.** Add a small wrapper that calls `await auth()` at the top of each handler and returns `401` when no session exists; alternatively extend the proxy matcher to cover `/api/*` with an exception list. Once protected, run the Chapter 5 security tests.
- **Extract `GRAFANA_BASE_URL`.** Read the value from `process.env.GRAFANA_BASE_URL` in a single `src/lib/grafana.ts` helper; every page composes URLs through `buildSoloPanelUrl({ panelId, nodeId, from, to })`. Removes hardcoded IPs.
- **Harmonise the chat contract.** Pick one shape (`{ messages: [...] }`) and fix the stub to read the latest entry.
- **Delete the `/api/analytics/ai-chart` stub** or rewire it to call the real microservice server-side so the browser does not need direct access to `http://localhost:5000`.
- **Align the pipeline push with the agent schema.** Replace the single `pipeline_rules` array write with three separate writes to `pipeline_stages`, `process_fields`, and `comm_prefixes`, matching the keys the collect agent actually reads (documented in [Appendix B](appendix-b-etcd-keys.md)). This also requires a small schema change in the admin DB so the three arrays can be edited independently. Fix the threshold-rules JSON key for GPU (`gpu_max_utilization_percent` → `gpu_utilization_percent`) at the same time.
- **Wire real `custom_dashboards` CRUD.** Replace the mock imports on `/analytics/custom` with `fetch('/api/analytics/custom-dashboards')`.
- **Return `409` on duplicate node inserts** with a helpful error body.

### Medium term (1–2 months)

- **Role-based access control.** Introduce `users` and `user_roles` tables; switch from credentials to Auth.js OIDC with an identity provider. Expose roles as JWT claims and add `requireRole()` helpers.
- **JSON schema validation on every write.** Each `POST`/`PUT` handler validates its body with Zod before touching the DB or etcd. Returns a structured `400` with field-level errors.
- **Structured logging with pino + OpenTelemetry.** A shared `src/lib/logger.ts` emits JSON logs; a wrapper emits spans around DB and etcd calls.
- **Automated test execution in CI.** GitHub Actions (or similar) runs the Chapter 5 suites on every push; Docker Compose fixtures run as services.
- **Rate limiting and CSRF protection on state-changing API routes.** `upstash/ratelimit` or `iron-session` + standard CSRF tokens on form posts.

### Long term (research-flavoured)

- **Replace the AI chart stub with a first-class planner.** The microservice currently returns either SVG or a Grafana URL. A more ambitious design would return a structured chart specification (Vega-Lite) that the admin app renders natively, so every AI-generated chart becomes savable as a custom dashboard.
- **Real-time push instead of poll.** The dashboard currently refreshes iframes and polls API endpoints on an interval. WebSocket (or Server-Sent Events) feeds from the collect agent would let the UI update the instant metrics arrive.
- **Multi-cluster support.** Today the application assumes a single HPC cluster (one Grafana, one etcd, one TimescaleDB). Extending the schema to include a `cluster_id` everywhere — and letting the admin switch between clusters at the top of the UI — would make the application useful to multi-site operators.

## 6.4 Reflection

Building the application was as much about deciding what *not* to add as it was about writing code. Three decisions mattered most:

1. **Do not reimplement Grafana.** Grafana already renders beautiful real-time charts; embedding solo panels behind a single URL builder removes an entire category of work.
2. **Do not hide the existing pipeline's data model behind an ORM.** TimescaleDB hypertables and etcd keys have opinionated schemas; `pg` and `etcd3` let the application talk to them directly, keep queries readable, and move faster.
3. **Commit durable state before live state.** The governance module writes to the database transactionally, then fans out to etcd on a best-effort basis. If etcd is down, the admin still has a versioned, audited snapshot she can push later.

Technically, the project was the author's first encounter with Next.js 16 (the renamed proxy file), Tailwind CSS v4 (theme-in-CSS rather than `tailwind.config.ts`), and Auth.js v5 (`auth()` instead of `getServerSession()`); each of the three frameworks had breaking changes relative to the majority of tutorials still online. Recording those pitfalls in Chapter 4 was a deliberate effort to save the next developer the same debugging.

The work has revealed that, at the admin-console level, the *hardest* problems are neither performance nor scale — the dataset is bounded by cluster size — but **trust and auditability**: when an administrator presses *push to etcd*, she must believe the system did what it said. The governance layer in §4.8 is the author's attempt to answer that need; making it richer (preview, diff, dry-run) is the most interesting direction for future work.
