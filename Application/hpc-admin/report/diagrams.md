# Diagrams

> All diagrams are authored in Mermaid so they can be reviewed in the browser. Before the final thesis submission, render each one to SVG or PNG and place it in the thesis template.

## System context

Shows how the admin application sits inside the wider HPC monitoring system. Referenced from Chapter 2 §2.1.

```mermaid
flowchart LR
    subgraph nodes [Compute nodes]
        agent[Compute-node agent]
    end
    subgraph server [Server hosts]
        collect[Collect agent]
        kafka[(Kafka)]
        tsdb[(TimescaleDB)]
        etcd[(etcd)]
        grafana[Grafana]
        admin[hpc-admin<br/>Next.js]
        ai[AI microservice]
    end
    browser[Admin browser]

    agent -->|gRPC metrics| collect
    agent -->|heartbeat, status| etcd
    agent -->|reads config| etcd

    collect -->|records| kafka
    kafka -->|consumer| tsdb
    collect -->|reads config| etcd

    grafana -->|SQL| tsdb

    browser -->|HTTPS| admin
    browser -->|iframe| grafana
    browser -->|fetch| ai

    admin -->|SQL| tsdb
    admin -->|gRPC| etcd
```

## High-level architecture

Referenced from Chapter 3 §3.2.

```mermaid
flowchart LR
    Browser[Admin browser] -->|HTTPS pages + JSON| Next[Next.js process<br/>App Router + API handlers]
    Next -->|pg pool| TSDB[(TimescaleDB)]
    Next -->|etcd3 client| Etcd[(etcd)]
    Browser -->|iframe solo panel| Grafana[Grafana]
    Browser -->|POST /visualize| AI[AI microservice<br/>:5000]
    Pipeline[Pipeline agents] -->|via Kafka| TSDB
    Pipeline -->|heartbeat + config| Etcd
```

## Layered decomposition

Referenced from Chapter 3 §3.3.

```mermaid
flowchart TB
    subgraph presentation [Presentation]
        pages[src/app/\(auth\) + \(protected\)]
        comps[src/components]
    end
    subgraph api [API layer]
        handlers[src/app/api/**/route.ts]
    end
    subgraph integration [Integration]
        db[src/lib/db.ts]
        etcd[src/lib/etcd.ts]
        types[src/types/index.ts]
    end
    subgraph data [Data]
        adminTables[nodes, users, rules, versions, audit]
        hyper[node_status_hourly<br/>user_app_hourly]
    end

    pages -->|fetch JSON| handlers
    comps -->|props| pages
    handlers -->|pool.connect| db
    handlers -->|etcd3| etcd
    handlers -.types.-> types
    db --> adminTables
    db --> hyper
    etcd --> etcdStore[(etcd keys)]
```

## Route tree

Referenced from Chapter 3 §3.4.

```mermaid
flowchart LR
    root["/"] --> login["/login"]
    root --> dashboard["/dashboard"]
    dashboard --> nodesList["/dashboard/nodes"]
    nodesList --> nodeDetail["/dashboard/nodes/[nodeId]"]
    root --> analytics["/analytics"]
    analytics --> custom["/analytics/custom"]
    analytics --> aiChart["/analytics/ai-chart"]
    root --> chat["/chat"]
    root --> config["/config"]
    config --> collection["/config/collection"]
    config --> pipeline["/config/pipeline"]
    config --> alerts["/config/alerts"]
    config --> governance["/config/governance"]
```

## Entity-relationship diagram

Admin-owned tables plus the two pipeline-owned hypertables. Referenced from Chapter 3 §3.5.

```mermaid
erDiagram
    nodes ||--o| collection_settings : "1:0..1"
    nodes ||--o{ notifications : "0..N"
    alert_rules ||--o{ notifications : "0..N"
    hpc_users ||--o{ user_app_hourly : "0..N"
    nodes ||--o{ node_status_hourly : "0..N"
    nodes ||--o{ user_app_hourly : "0..N"

    nodes {
      TEXT id PK
      TEXT name
      TEXT ip
      TEXT group_name
      TEXT collect_agent
      TIMESTAMPTZ created_at
    }
    hpc_users {
      INT uid PK
      TEXT username
      TEXT email
      TEXT group_name
    }
    collection_settings {
      TEXT node_id PK_FK
      INT interval_seconds
      INT window_seconds
      TEXT collect_agent
      TIMESTAMPTZ updated_at
    }
    pipeline_rules {
      TEXT id PK
      TEXT name
      TEXT type
      TEXT resource
      TEXT condition
      BOOLEAN enabled
    }
    alert_rules {
      TEXT id PK
      TEXT name
      TEXT node_group
      TEXT resource
      TEXT operator
      DOUBLE threshold
      TEXT severity
      BOOLEAN enabled
    }
    notifications {
      TEXT id PK
      TEXT rule_id FK
      TEXT severity
      TEXT message
      TEXT node_id FK
      BOOLEAN acknowledged
      TIMESTAMPTZ created_at
    }
    config_versions {
      TEXT id PK
      TEXT version
      TEXT author
      TEXT description
      JSONB config_snapshot
      BOOLEAN active
      TIMESTAMPTZ created_at
    }
    audit_logs {
      TEXT id PK
      TEXT actor
      TEXT action
      TEXT target
      TEXT detail
      TIMESTAMPTZ created_at
    }
    custom_dashboards {
      TEXT id PK
      TEXT title
      INT_ARRAY user_uids
      TEXT resource
      TEXT chart_type
      BOOLEAN pinned
    }
    node_status_hourly {
      TIMESTAMPTZ bucket_time
      TEXT node_id
      DOUBLE avg_cpu_usage_percent
      DOUBLE avg_gpu_utilization
      DOUBLE avg_mem_usage_percent
      BIGINT max_mem_used_bytes
      BIGINT total_disk_read_bytes
      BIGINT total_disk_write_bytes
      BIGINT total_net_rx_bytes
      BIGINT total_net_tx_bytes
      BOOLEAN is_active
    }
    user_app_hourly {
      TIMESTAMPTZ bucket_time
      TEXT node_id
      INT uid
      TEXT comm
      DOUBLE total_cpu_time_seconds
      BIGINT max_rss_memory_bytes
      INT max_gpu_memory_mib
      BIGINT total_read_bytes
      BIGINT total_write_bytes
      BIGINT total_net_rx_bytes
      BIGINT total_net_tx_bytes
      INT process_count
    }
```

## Use case diagram

Referenced from Chapter 2 §2.5.

```mermaid
flowchart LR
    admin((HPC administrator))

    subgraph monitoring [Monitoring]
        UC02[UC-02 View cluster dashboard]
        UC03[UC-03 View node detail]
        UC05[UC-05 View user analytics]
    end

    subgraph configUC [Configuration]
        UC04[UC-04 Start or stop collection]
        UC07[UC-07 Manage nodes]
        UC08[UC-08 Edit pipeline rules]
        UC09[UC-09 Edit alert rules]
        UC10[UC-10 Snapshot and push]
        UC11[UC-11 Rollout previous version]
    end

    subgraph others [Others]
        UC01[UC-01 Log in]
        UC06[UC-06 Generate AI chart]
        UC12[UC-12 Review audit log]
        UC13[UC-13 Acknowledge notification]
    end

    admin --> UC01
    admin --> UC02
    admin --> UC03
    admin --> UC04
    admin --> UC05
    admin --> UC06
    admin --> UC07
    admin --> UC08
    admin --> UC09
    admin --> UC10
    admin --> UC11
    admin --> UC12
    admin --> UC13
```

## Login sequence

Referenced from Chapter 2 §2.5 UC-01.

```mermaid
sequenceDiagram
    participant Browser
    participant Proxy as proxy.ts matcher
    participant Layout as ProtectedLayout
    participant Login as /login page
    participant Auth as Auth.js v5

    Browser->>Proxy: GET /dashboard
    Proxy->>Layout: matched, forward
    Layout->>Auth: auth()
    Auth-->>Layout: null session
    Layout-->>Browser: redirect /login
    Browser->>Login: GET /login
    Login-->>Browser: form
    Browser->>Auth: signIn credentials (email, password)
    Auth-->>Browser: JWT cookie
    Browser->>Proxy: GET /dashboard
    Layout->>Auth: auth()
    Auth-->>Layout: session
    Layout-->>Browser: Sidebar + Header + page
```

## AI chart generation sequence

Referenced from Chapter 3 §3.9.2 and Chapter 4 §4.10.

```mermaid
sequenceDiagram
    participant Browser as AI chart page
    participant AI as AI microservice :5000
    participant Grafana as Grafana :3000

    Browser->>AI: POST /visualize { question }
    AI-->>Browser: { reasoning, pipeline, code_render_svg, panel_embed_url }
    alt SVG pipeline
        Browser->>Browser: render inline SVG
    else Grafana pipeline
        Browser->>Browser: rewrite host to localhost (keep port)
        Browser->>Grafana: iframe src = rewritten URL
        Grafana-->>Browser: panel HTML
    end
```

## Snapshot-and-push sequence

Referenced from Chapter 3 §3.10 and Chapter 4 §4.8.

```mermaid
sequenceDiagram
    participant UI as /config/governance
    participant API as snapshot-and-push handler
    participant DB as TimescaleDB (admin tables)
    participant Etcd as etcd

    UI->>API: POST /api/config/governance/snapshot-and-push
    API->>DB: SELECT collection_settings, pipeline_rules, alert_rules, latest version
    API->>API: derive next version + build threshold_rules
    API->>DB: BEGIN
    API->>DB: UPDATE config_versions SET active = FALSE
    API->>DB: INSERT INTO config_versions (active = TRUE)
    API->>DB: INSERT INTO audit_logs
    API->>DB: COMMIT

    API->>Etcd: getAll /config/compute_node/ prefix
    API->>Etcd: getAll /config/collect_agent/ prefix
    API->>Etcd: PUT window, heartbeat_interval, target_collect_agent per node
    API->>Etcd: PUT pipeline_rules JSON per agent
    API->>Etcd: PUT threshold_rules JSON per agent
    API-->>UI: version + pushed_to_nodes + pushed_to_agents + etcd_errors
```

## Push-alerts-to-etcd sequence

Referenced from Chapter 4 §4.8.

```mermaid
sequenceDiagram
    participant UI as /config/alerts
    participant API as push-to-etcd handler
    participant DB as alert_rules
    participant Etcd as etcd

    UI->>API: POST /api/config/alerts/push-to-etcd
    API->>DB: SELECT name, resource, operator, threshold WHERE enabled AND operator IN ('>', '>=')
    API->>API: fold into { resource: { max: min(threshold) } }
    API->>Etcd: getAll /config/collect_agent/ prefix
    API->>Etcd: PUT threshold_rules JSON per agent (parallel)
    API-->>UI: { pushed_to, thresholds, skipped }
```

## Deployment diagram

Single-host deployment used for the thesis demo. Referenced from Chapter 4 §4.1 and Chapter 6 §6.3.

```mermaid
flowchart TB
    subgraph workstation [Admin workstation]
        browser[Chromium]
        ai[AI microservice :5000]
    end
    subgraph app [Application host]
        next[Next.js :3000]
    end
    subgraph infra [Monitoring infrastructure]
        grafana[Grafana :3000]
        tsdb[TimescaleDB :5432]
        etcd[etcd :2379]
    end
    subgraph cluster [HPC cluster]
        agents[Compute-node + collect agents]
    end

    browser -->|HTTPS| next
    browser -->|iframe| grafana
    browser -->|HTTP| ai
    next --> tsdb
    next --> etcd
    grafana --> tsdb
    agents --> etcd
    agents --> tsdb
```
