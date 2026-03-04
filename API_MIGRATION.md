# AdminOS API Migration Guide — v1 → v2

> **Status:** In Review &nbsp;|&nbsp; **Target Release:** 2026-Q2 &nbsp;|&nbsp; **Owner:** pradeep.k@corp.io

## Overview

This document describes all API changes between AdminOS v1 and v2. Each endpoint is shown
side-by-side with its current and proposed contract, including request/response examples.

### Change Classification

| Label | Meaning |
|---|---|
| 🔴 **Breaking** | Clients **must** update before migrating |
| 🟢 **Non-breaking** | Backward-compatible addition — no client changes needed |
| 🟡 **Deprecated** | v1 endpoint still works; migrate to v2 equivalent |
| 🔵 **New** | Net-new endpoint with no v1 equivalent |

### Summary

| Tag | Breaking | Non-breaking | Deprecated | New |
|---|---|---|---|---|
| Tasks | 1 | 1 | — | — |
| Requests | 1 | — | — | — |
| Dashboard | — | — | 1 | 1 |

---

## Endpoints

---

### 1. List Tasks 🔴 Breaking

> **Pagination changed from offset-based to cursor-based. Breaking for any client using `page`/`limit` offsets.**

#### Current — `GET /api/tasks`

**Request**

```
GET /api/tasks?page=1&limit=20&category=infra
Authorization: Bearer <token>
```

| Query Param | Type | Description |
|---|---|---|
| `page` | integer | Page number (1-based) |
| `limit` | integer | Results per page (default 20) |
| `category` | string | Filter by category |

**Response — 200 OK**

```json
{
  "data": [
    {
      "id": "t01",
      "name": "Sync Azure Subscriptions",
      "category": "infra",
      "last_run": "5m ago",
      "run_count": 842
    },
    {
      "id": "t02",
      "name": "Deploy to UAT",
      "category": "deploy",
      "last_run": "1h ago",
      "run_count": 231
    }
  ],
  "total": 9,
  "page": 1,
  "limit": 20
}
```

---

#### Proposed — `GET /api/v2/tasks`

**Request**

```
GET /api/v2/tasks?cursor=eyJpZCI6InQwMSJ9&limit=20&category=infra
Authorization: Bearer <token>
X-API-Version: 2
```

| Query Param | Type | Description |
|---|---|---|
| `cursor` | string | Base64 opaque cursor from previous response |
| `limit` | integer | Results per page (default 20) |
| `category` | string | Filter by category |

> ⚠️ `page` is **removed**. Use `next_cursor` from the response to paginate forward.

**Response — 200 OK**

```json
{
  "data": [
    {
      "id": "t01",
      "name": "Sync Azure Subscriptions",
      "category": "infra",
      "last_run": "5m ago",
      "run_count": 842,
      "is_enabled": true
    }
  ],
  "next_cursor": "eyJpZCI6InQwMyJ9",
  "has_more": true
}
```

**What changed:**

| Field | v1 | v2 |
|---|---|---|
| Pagination | `page` / `limit` / `total` | `cursor` / `next_cursor` / `has_more` |
| Task object | No `is_enabled` field | `is_enabled: boolean` added |

**Migration steps:**

1. Replace `?page=N` with `?cursor=` (start with no cursor for first page)
2. Store `next_cursor` from response and pass it as `cursor` on next call
3. Stop using `total` for UI — use `has_more` instead

---

### 2. Invoke Task 🟢 Non-breaking

> **SSE streaming added via `Accept: text/event-stream` header. Old JSON response still works if you omit the header.**

#### Current — `POST /api/tasks/:id/invoke`

**Request**

```
POST /api/tasks/t01/invoke
Authorization: Bearer <token>
Content-Type: application/json

{
  "environment": "uat",
  "params": {
    "filter": "*",
    "dry_run": false
  }
}
```

**Response — 202 Accepted**

```json
{
  "run_id": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued"
}
```

Client must then poll `/api/tasks/:id/runs/:run_id` to check status.

---

#### Proposed — `POST /api/v2/tasks/:id/invoke`

**Request (streaming)**

```
POST /api/v2/tasks/t01/invoke
Authorization: Bearer <token>
Content-Type: application/json
Accept: text/event-stream

{
  "environment": "uat",
  "params": {
    "filter": "*",
    "dry_run": false
  },
  "stream": true
}
```

**Response — 200 OK (SSE stream)**

```
data: {"seq":1,"level":"ok","message":"▶ Starting task…"}

data: {"seq":2,"level":"ok","message":"✔ Auth acquired (Azure AD)"}

data: {"seq":3,"level":"","message":"↺ Fetching subscriptions…"}

data: {"seq":4,"level":"ok","message":"✔ 104 subscriptions synced"}

data: {"seq":5,"level":"ok","message":"✔ Task complete  elapsed=21.4s"}

data: [DONE]
```

**Request (non-streaming — backward compatible)**

```
POST /api/v2/tasks/t01/invoke
Authorization: Bearer <token>
Content-Type: application/json

{
  "environment": "uat",
  "params": { "filter": "*", "dry_run": false }
}
```

Response is identical to v1: `{"run_id": "...", "status": "queued"}`.

**What changed:**

| Behaviour | v1 | v2 |
|---|---|---|
| Default response | 202 + run_id | Same |
| Streaming option | Not available | Send `Accept: text/event-stream` |
| Log access | Separate polling endpoint | Inline via SSE |

---

### 3. List Requests 🔴 Breaking

> **`user` field restructured from a flat string to a nested object. All clients parsing `user` must update.**

#### Current — `GET /api/requests`

**Request**

```
GET /api/requests?status=error&limit=50
Authorization: Bearer <token>
```

**Response — 200 OK**

```json
{
  "data": [
    {
      "id": "req-00179",
      "method": "POST",
      "path": "/api/tasks/invoke",
      "status": "error",
      "latency_ms": 4012,
      "user": "scheduler",
      "ts": "8m ago"
    }
  ],
  "total": 128
}
```

---

#### Proposed — `GET /api/v2/requests`

**Request**

```
GET /api/v2/requests?status=error&limit=50&from=2026-03-01T00:00:00Z
Authorization: Bearer <token>
X-API-Version: 2
```

| Query Param | Type | Description |
|---|---|---|
| `q` | string | Full-text search (path, user) |
| `status` | string | Filter: `success` / `error` / `pending` / `running` |
| `limit` | integer | Max results |
| `from` | ISO 8601 | Filter requests after this timestamp |

**Response — 200 OK**

```json
{
  "data": [
    {
      "id": "req-00179",
      "method": "POST",
      "path": "/api/tasks/invoke",
      "status": "error",
      "latency_ms": 4012,
      "user": {
        "id": "u-003",
        "username": "scheduler",
        "role": "operator"
      },
      "created_at": "2026-03-04T10:12:00Z"
    }
  ],
  "total": 128,
  "next_cursor": "eyJ0cyI6IjIwMjYtMDMtMDQifQ"
}
```

**What changed:**

| Field | v1 | v2 |
|---|---|---|
| `user` | `"scheduler"` (string) | `{ id, username, role }` (object) |
| `ts` | `"8m ago"` (relative string) | `created_at` (ISO 8601) |
| Pagination | `total` only | `total` + `next_cursor` |
| New filter | — | `from` (date range) |

**Migration steps:**

1. Update `user` parsing: `request.user` → `request.user.username`
2. Replace relative `ts` display with formatted `created_at`

---

### 4. Dashboard Stats 🟡 Deprecated → Replaced

> **`/api/dashboard/stats` still works but is deprecated. Migrate to `/api/v2/metrics/snapshots` for richer data.**

#### Current — `GET /api/dashboard/stats`

**Request**

```
GET /api/dashboard/stats
Authorization: Bearer <token>
```

**Response — 200 OK**

```json
{
  "total_requests": 2847,
  "success_rate": 99.2,
  "avg_latency_ms": 84,
  "error_count": 23
}
```

---

#### Proposed — `GET /api/v2/metrics/snapshots`

**Request**

```
GET /api/v2/metrics/snapshots?period=24h&bucket=1h
Authorization: Bearer <token>
X-API-Version: 2
```

| Query Param | Type | Description |
|---|---|---|
| `period` | string | `1h` / `24h` / `7d` / `30d` |
| `bucket` | string | Aggregation granularity: `1m` / `5m` / `1h` |

**Response — 200 OK**

```json
{
  "period": "24h",
  "summary": {
    "total_requests": 2847,
    "success_rate_pct": 99.2,
    "p50_latency_ms": 42,
    "p95_latency_ms": 310,
    "p99_latency_ms": 840,
    "error_count": 23
  },
  "buckets": [
    {
      "hour": "2026-03-04T00:00:00Z",
      "total": 48,
      "errors": 0,
      "p95_ms": 88
    },
    {
      "hour": "2026-03-04T01:00:00Z",
      "total": 32,
      "errors": 1,
      "p95_ms": 112
    }
  ]
}
```

**What's added:**

- `p50` / `p95` / `p99` latency percentiles in `summary`
- `buckets` array for time-series chart data — eliminates separate chart endpoints
- `period` and `bucket` params replace hardcoded 24h window

---

## Migration Checklist

### For API Consumers

- [ ] Update task list pagination: replace `page`/`limit` with cursor pattern
- [ ] Update `user` field parsing in requests response (`string` → `object`)
- [ ] Replace relative `ts` fields with ISO 8601 `created_at`
- [ ] Optionally adopt SSE streaming for task invocation
- [ ] Switch dashboard stats fetch to `/api/v2/metrics/snapshots`

### For the Backend (FastAPI)

- [ ] Add `X-API-Version` header check middleware
- [ ] Implement cursor encoder/decoder (`models/cursor.py`)
- [ ] Add `is_enabled` to task serializer
- [ ] Restructure `RequestSchema.user` to nested object
- [ ] Implement SSE stream route for `/api/v2/tasks/:id/invoke`
- [ ] Build `/api/v2/metrics/snapshots` from `metrics_snapshots` table

---

## Versioning Strategy

All v2 routes are prefixed with `/api/v2/`. The v1 routes remain active until **2026-Q3** to allow
a migration window. After that, v1 routes will return `410 Gone`.

Clients may also send `X-API-Version: 2` on existing paths as an alternative to the URL prefix —
the middleware will route accordingly.

```
Deprecated route sunset timeline:

GET /api/tasks             →  deprecated 2026-Q2, sunset 2026-Q3
GET /api/requests          →  deprecated 2026-Q2, sunset 2026-Q3
GET /api/dashboard/stats   →  deprecated now,     sunset 2026-Q2
```

---

## Questions / Review

Open questions to resolve before approval:

1. Should cursor tokens be signed (HMAC) to prevent tampering, or is opacity enough?
2. Should `GET /api/v2/requests` support `to` param in addition to `from`?
3. Agree on SSE heartbeat interval to prevent proxy timeouts (suggest 15s)?

> Raise issues in the team channel or open a PR against this document.
