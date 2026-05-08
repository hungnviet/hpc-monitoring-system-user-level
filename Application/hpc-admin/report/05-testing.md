# Chapter 5 — Testing

> **Estimated length:** 8–12 pages.
> **Purpose:** present a testing strategy for the admin application. As of the submission of this chapter no automated tests are implemented yet; this chapter describes the test architecture and concrete suites that will be added before the defence. Where results will be filled in later, a placeholder table is provided.

## 5.1 Testing strategy

The application is small (≈30 API handlers, ≈15 pages, two singletons) and integrates with three external dependencies (TimescaleDB, etcd, Grafana) plus one HTTP microservice (the AI endpoint). A classic test pyramid is therefore both tractable and meaningful:

```
             ┌──────────────────────────┐
             │   Manual exploratory     │
             ├──────────────────────────┤
             │  End-to-end (Playwright) │
             ├──────────────────────────┤
             │  API / integration       │
             ├──────────────────────────┤
             │  Unit (Vitest + RTL)     │
             └──────────────────────────┘
```

Principles:

1. **Every functional requirement in §2.3 must be covered by at least one automated test and one manual test case.**
2. **Integration over mocking.** The API tier is tested against a real TimescaleDB and a real etcd container so that SQL bugs and etcd3 client mismatches surface early.
3. **External services are stubbed, not called.** The Grafana iframe and the AI microservice are replaced by local HTTP stubs in the e2e tier.
4. **Test data is deterministic.** A single SQL seed file produces reproducible `node_status_hourly` and `user_app_hourly` buckets for assertion.

## 5.2 Unit tests

### Scope

Unit tests cover pure functions and presentational components. The aim is speed (tens of milliseconds per test) so they can run on every commit.

### Tooling

- **Vitest** (faster than Jest, first-class TypeScript, works with Vite's module resolver).
- **@testing-library/react** for component rendering.
- **@testing-library/jest-dom** for custom matchers.

### Candidate targets

| Unit | Test |
|---|---|
| `parseNodes` / `parseHeartbeats` in [src/app/api/etcd/nodes/route.ts](../src/app/api/etcd/nodes/route.ts) | flatten etcd KV map, ignore malformed entries |
| `nextVersion` in [src/app/api/config/governance/snapshot-and-push/route.ts](../src/app/api/config/governance/snapshot-and-push/route.ts) | `undefined` → `1.0.0`, invalid → `1.0.0`, `1.2.3` → `1.2.4` |
| heartbeat staleness logic (extract to a helper) | alive within threshold, stale outside, missing heartbeat = stopped |
| `RESOURCE_TO_ETCD_KEY` mapping (alerts push) | known resources map, unknown skipped |
| URL host-rewrite in [src/app/(protected)/analytics/ai-chart/page.tsx](../src/app/(protected)/analytics/ai-chart/page.tsx) | remote URL with port preserved; URL without port defaults to no port; null remains null |
| `GrafanaPanel` component | loading placeholder then iframe after `onLoad`; empty placeholder when `src` not set |
| `NodeStatusBadge` | colours match `running`, `stopped`, `degraded` |

### Target metric

≥ 80 % line coverage on pure helpers. Coverage of full React pages is not a goal at this tier — they are covered by e2e.

## 5.3 API / integration tests

### Scope

Each API handler is called end-to-end against a spun-up Next.js server, with real TimescaleDB and real etcd running in Docker. The goal is to catch SQL errors, schema drift, and etcd key-format mistakes.

### Tooling

- **Vitest** as the runner.
- **Docker Compose** test fixture: TimescaleDB image, etcd image, optional Grafana stub.
- **supertest** (or `fetch` against a bound port) for HTTP.
- Seed SQL applied before each suite (transactional teardown where possible, `TRUNCATE` between suites otherwise).

### Coverage matrix (one row per API route)

| Group | Endpoint | Positive | Negative |
|---|---|---|---|
| nodes | `GET /api/nodes` | returns seeded rows sorted by name | empty table returns `[]` |
| nodes | `POST /api/nodes` | inserts and returns `201` | duplicate id returns `500` (documented pitfall) |
| nodes | `GET /api/nodes/[id]/hourly?range=24h` | returns 24 buckets per node | invalid range falls back to `24h` |
| etcd | `GET /api/etcd/nodes` | includes derived `running`/`stopped` | etcd unreachable returns `503` |
| etcd | `POST /api/etcd/nodes` | creates four keys under the prefix | missing `nodeId` returns `400` |
| etcd | `PUT /api/etcd/nodes/[id]/status` | flips `status` key | unknown node still writes (documented behaviour) |
| analytics | `GET /api/analytics/cluster-stats?range=6h` | returns 6-hour aggregates | invalid range falls back to `1h` |
| analytics | `GET /api/analytics/user-usage?mode=summary` | all users appear (LEFT JOIN) | empty range returns rows with `NULL` totals |
| analytics | `mode=timeseries&uid=...&resource=cpu` | hourly rows | invalid `resource` returns `[]` |
| config/collection | `PUT /api/config/collection/[id]` | UPSERT in DB + three etcd writes | etcd failure does not fail DB write |
| config/pipeline | `POST /api/config/pipeline/push-to-etcd` | enabled rules land on every agent | no agents returns `404` |
| config/alerts | `POST /api/config/alerts/push-to-etcd` | most-restrictive wins; skipped list populated for `net` | no syncable rules returns `422` |
| config/governance | `POST /api/config/governance/snapshot-and-push` | new version active; others deactivated; audit entry; etcd keys written | etcd down: `etcd_errors` populated, DB still committed |
| config/governance | `POST /api/config/governance/rollout` | selected version active; snapshot replayed | unknown version returns `404` |
| notifications | `PUT /api/notifications/[id]` | `acknowledged = true` | unknown id returns `404` |

### Representative test (pseudocode)

```ts
import { describe, it, beforeAll, expect } from "vitest"
import { setupDb, teardownDb } from "./fixtures/db"
import { setupEtcd, teardownEtcd, etcdClient } from "./fixtures/etcd"

describe("POST /api/config/alerts/push-to-etcd", () => {
  beforeAll(async () => {
    await setupDb()  // seeds alert_rules + discovers 2 agents
    await setupEtcd()
  })

  it("writes the most-restrictive threshold to every agent", async () => {
    const res = await fetch("http://localhost:3000/api/config/alerts/push-to-etcd", { method: "POST" })
    expect(res.status).toBe(200)
    const body = await res.json()
    expect(body.pushed_to.sort()).toEqual(["agent_a", "agent_b"])

    const kvA = await etcdClient.get("/config/collect_agent/agent_a/threshold_rules").string()
    expect(JSON.parse(kvA!)).toMatchObject({
      cpu_usage_percent: { max: 75 },   // min of 75 and 90
    })
  })
})
```

## 5.4 End-to-end UI tests

### Scope

Each use case from §2.5 has an end-to-end scenario that clicks through the real UI. The goal is to catch integration bugs across the page + API + DB layers.

### Tooling

- **Playwright** (Chromium, Firefox, WebKit for cross-browser where it matters).
- Fixtures: the same Docker Compose bundle as the API tier, plus a stub Grafana server and a stub AI server (simple Node HTTP servers returning canned responses keyed by query string).

### Scenario list (one per use case)

| UC | Scenario |
|---|---|
| UC-01 | Log in with valid credentials → land on `/dashboard`. Log in with invalid → stay on `/login` with an error. |
| UC-02 | Dashboard shows node counts matching seeded data; time-range selector changes `from`/`to` on every Grafana iframe `src`. |
| UC-03 | Clicking a node row opens `/dashboard/nodes/[id]`; start/stop button flips `status` key in etcd (asserted through the API). |
| UC-04 | Toggling collection updates the UI indicator; Grafana panels reload with `var-node=...`. |
| UC-05 | Analytics page with date range produces summary; selecting a user shows time-series. |
| UC-06 | AI chart page: type question → stub AI server returns a prepared SVG → chart is rendered. |
| UC-07 | Create node form → row appears in list; delete → row disappears. |
| UC-08 | Create pipeline rule → click "push to etcd" → stub etcd recorded the JSON array. |
| UC-09 | Create alert → push → etcd recorded threshold JSON. |
| UC-10 | Governance snapshot → version list increases; etcd keys refreshed. |
| UC-11 | Rollout → selected version becomes active; new audit entry. |
| UC-12 | Audit log lists actions chronologically. |
| UC-13 | Acknowledge notification → disappears from unacknowledged list. |

## 5.5 Manual / exploratory tests

For features that are too dynamic or visual to automate meaningfully (Grafana iframes, AI chart rendering), a manual test plan complements the automated tiers.

### Template (to reproduce per case)

| Field | Value |
|---|---|
| ID | MT-XX |
| Use case | UC-XX |
| Preconditions | e.g. "at least one registered node and one running agent" |
| Steps | numbered list |
| Expected result | single paragraph |
| Actual result | to fill |
| Pass / fail | to fill |
| Notes | screenshots, logs |

### Proposed case list (25–30 cases)

The manual suite duplicates UC-01 … UC-13 and adds variants for:

- Cross-browser rendering of the dashboard (Chrome, Firefox, Safari).
- Behaviour when etcd is unreachable (banner appears, other pages still usable).
- Behaviour when the AI microservice is unreachable (inline error, form stays usable).
- Behaviour when TimescaleDB is slow (loading placeholders visible; no UI freeze).

## 5.6 Non-functional tests

### Performance

- Tool: **k6** (JavaScript DSL, easy to plug in CI).
- Targets: the three analytics endpoints (`cluster-stats`, `user-usage?mode=summary`, `nodes/metrics/latest`) against a seeded year of hourly buckets.
- Pass criterion: p95 < 500 ms at 10 RPS; no errors at 50 RPS.

### Security

- **Dependency audit:** `npm audit --production` must report zero high severity.
- **Authentication bypass:** manual attempt to call every `/api/*` route without a session cookie. Currently expected to succeed (known gap); after the Chapter 6 fix, every call must return `401`.
- **SQL injection:** send crafted `resource=`, `uid=`, `range=` values to the analytics endpoints. Expected: allow-list mismatches return `[]` or `400`, never an SQL error.
- **Iframe sandboxing:** verify that the Grafana iframe `sandbox` attribute (added as part of future hardening) does not break authenticated dashboards.

### Reliability

- With etcd down, `/dashboard` must render with a visible warning but no JavaScript error.
- With the AI microservice down, `/analytics/ai-chart` must display an inline error without unmounting the page.

## 5.7 Test environment and data

### Docker Compose bundle

```yaml
# tests/docker-compose.yml (proposed)
services:
  timescale:
    image: timescale/timescaledb:latest-pg16
    environment:
      POSTGRES_PASSWORD: admin123
      POSTGRES_DB: hpc_monitoring_test
    ports: ["5433:5432"]
  etcd:
    image: quay.io/coreos/etcd:latest
    command: >
      etcd --name s1
           --listen-client-urls http://0.0.0.0:2379
           --advertise-client-urls http://etcd:2379
    ports: ["2380:2379"]
  grafana-stub:
    build: ./stubs/grafana
    ports: ["3001:3000"]
  ai-stub:
    build: ./stubs/ai
    ports: ["5001:5000"]
```

### Seed SQL

A single file `tests/fixtures/seed.sql` applies:

- two `nodes` rows (`node_a`, `node_b`) with two different `collect_agent` values;
- five `hpc_users` rows;
- 30 days of `node_status_hourly` buckets for each node with a known sine wave for CPU and constant values for memory/GPU;
- 30 days of `user_app_hourly` rows, with one user heavy on GPU, one on CPU, one idle.

Seeding is deterministic (no `now()`, explicit `bucket_time`) so assertions like *"CPU average for the last 24 hours is 52.3 ± 0.1"* are stable.

## 5.8 Results template

The table below is left with placeholders. Fill in after the suites are executed; a screenshot of the CI dashboard will replace the placeholder columns in the final thesis.

| Tier | Tool | Test count | Passed | Failed | Coverage |
|---|---|---|---|---|---|
| Unit | Vitest + RTL | _TBD_ | _TBD_ | _TBD_ | _TBD_ |
| Integration | Vitest + supertest | _TBD_ | _TBD_ | _TBD_ | — |
| E2E | Playwright | _TBD_ | _TBD_ | _TBD_ | — |
| Manual | — | ~30 | _TBD_ | _TBD_ | — |
| Performance | k6 | 3 scenarios | _TBD_ | _TBD_ | — |

### Known gaps carried into Chapter 6

- The admin application runs as a single Next.js process; there is no load-balancer test.
- Authentication is a single-user credentials provider; there is no OIDC flow to test end to end.
- Browser compatibility with Safari 17+ and Firefox 128+ is manually verified only.
