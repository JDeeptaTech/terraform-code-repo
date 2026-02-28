# Application Configuration — DB Schema
> Single-table approach · PostgreSQL + JSONB · Internal Engineering Reference

---

## Overview

This document describes the database schema for storing application configurations across multiple environments (`dev`, `test`, `uat`, `prod`). The design uses a **single PostgreSQL table** with a `JSONB` column to store hierarchical config values — keeping the solution simple, flexible, and easy to maintain.

---

## Design Principles

- **Single table** — minimal operational overhead, easy to reason about
- **JSONB config column** — flexible schema, no migrations when config structure changes
- **Secrets-safe** — sensitive values are never stored; Azure Key Vault URIs stored in `secret_refs` instead
- **Full audit trail** — version counter tracks every change for rollback and compliance
- **Scoped overrides** — optional `subscription_id` column supports per-Azure-subscription config

---

## Schema Definition

```sql
CREATE TABLE configurations (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    app_name        VARCHAR(100) NOT NULL,
    environment     VARCHAR(50)  NOT NULL,   -- 'dev', 'test', 'uat', 'prod'
    subscription_id VARCHAR(100),            -- optional: Azure subscription override

    config          JSONB        NOT NULL DEFAULT '{}',
    secret_refs     JSONB        NOT NULL DEFAULT '{}', -- Key Vault URIs only

    version         INTEGER      NOT NULL DEFAULT 1,
    is_active       BOOLEAN      NOT NULL DEFAULT TRUE,
    created_by      VARCHAR(100) NOT NULL,
    updated_by      VARCHAR(100),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    UNIQUE (app_name, environment, subscription_id)
);

-- Indexes
CREATE INDEX idx_conf_app_env ON configurations (app_name, environment);
CREATE INDEX idx_conf_sub     ON configurations (subscription_id) WHERE subscription_id IS NOT NULL;
CREATE INDEX idx_conf_gin     ON configurations USING GIN (config);
```

---

## Column Reference

| Column | Type | Description |
|--------|------|-------------|
| `id` | UUID | Auto-generated primary key |
| `app_name` | VARCHAR(100) | Application identifier (e.g. `trading-engine`, `api-gateway`) |
| `environment` | VARCHAR(50) | Target environment: `dev`, `test`, `uat`, `prod` |
| `subscription_id` | VARCHAR(100) | Optional Azure subscription override. `NULL` = applies to all subscriptions |
| `config` | JSONB | Full config as nested JSON (database, cache, feature_flags, etc.) |
| `secret_refs` | JSONB | Parallel structure to `config`. Stores Azure Key Vault URIs — **never plaintext secrets** |
| `version` | INTEGER | Incremented on every update. Used for optimistic locking and history correlation |
| `is_active` | BOOLEAN | Soft-delete flag. Inactive rows are ignored by applications |
| `created_by` / `updated_by` | VARCHAR(100) | Identity of who created or last modified the config |
| `created_at` / `updated_at` | TIMESTAMPTZ | Timestamps with timezone for all environments |

---

## Sample Data

```sql
INSERT INTO configurations (app_name, environment, config, secret_refs, created_by)
VALUES (
    'trading-engine', 'prod',
    '{
        "database": { "host": "db-prod.example.com", "port": 5432, "max_connections": 100 },
        "cache":    { "host": "redis-prod.example.com", "ttl_seconds": 300 },
        "feature_flags": { "new_dashboard": true, "dark_mode": false }
    }',
    '{
        "database": { "password": "https://myvault.vault.azure.net/secrets/db-password" }
    }',
    'pradeep'
);
```

---

## Common Query Patterns

### Fetch full config for an app/env
```sql
SELECT config, secret_refs
FROM   configurations
WHERE  app_name    = 'trading-engine'
  AND  environment = 'prod'
  AND  is_active   = TRUE;
```

### Read a single nested value
```sql
SELECT config -> 'database' ->> 'host' AS db_host
FROM   configurations
WHERE  app_name = 'trading-engine' AND environment = 'prod';
```

### Update a single key (non-destructive)
```sql
UPDATE configurations
SET    config     = jsonb_set(config, '{database, max_connections}', '200'),
       updated_by = 'pradeep',
       updated_at = NOW(),
       version    = version + 1
WHERE  app_name = 'trading-engine' AND environment = 'prod';
```

### Merge / patch a top-level section
```sql
UPDATE configurations
SET    config = config || '{"feature_flags": {"dark_mode": true}}'::jsonb
WHERE  app_name = 'trading-engine' AND environment = 'prod';

-- Note: || does shallow merge at top level.
-- Use jsonb_set() for deep nested updates.
```

### Find apps with a specific feature flag enabled
```sql
SELECT app_name, environment
FROM   configurations
WHERE  config -> 'feature_flags' ->> 'new_dashboard' = 'true';
```

---

## PostgreSQL JSONB Operator Reference

| Operator | Example | Description |
|----------|---------|-------------|
| `->` | `config -> 'database'` | Returns JSON object for key |
| `->>` | `config ->> 'app_mode'` | Returns text value for key |
| `-> ->` | `config -> 'db' -> 'host'` | Nested object navigation |
| `\|\|` | `config \|\| '{...}'::jsonb` | Shallow merge (top-level keys) |
| `jsonb_set()` | `jsonb_set(config, '{a,b}', '5')` | Deep nested update without overwrite |
| `@>` | `config @> '{"flag": true}'` | Contains check (GIN-indexed) |
| `?` | `config ? 'database'` | Key existence check |

---

## Secret Handling

Sensitive values (passwords, API keys, connection strings) **must never** be stored in the `config` column. Use `secret_refs` to store Azure Key Vault URIs. Applications resolve the URI at startup or runtime via the Azure SDK.

```jsonc
// ✅ Correct — Key Vault URI in secret_refs
{
  "database": {
    "password": "https://myvault.vault.azure.net/secrets/db-password"
  }
}

// ❌ Wrong — plaintext secret in config
{
  "database": {
    "password": "Sup3rS3cret!@#"
  }
}
```

---

## FastAPI Integration

JSONB columns are returned as Python `dict` objects by `asyncpg` — no manual JSON parsing required.

```python
from fastapi import FastAPI, HTTPException
import asyncpg, json

app = FastAPI()

@app.get("/config/{app_name}/{environment}")
async def get_config(app_name: str, environment: str):
    row = await conn.fetchrow(
        """SELECT config FROM configurations
           WHERE app_name=$1 AND environment=$2 AND is_active=TRUE""",
        app_name, environment
    )
    if not row:
        raise HTTPException(status_code=404, detail="Config not found")
    return row["config"]   # asyncpg returns JSONB as dict directly


@app.patch("/config/{app_name}/{environment}")
async def patch_config(app_name: str, environment: str, patch: dict):
    await conn.execute(
        """UPDATE configurations
           SET config     = config || $1::jsonb,
               updated_by = $2,
               updated_at = NOW(),
               version    = version + 1
           WHERE app_name = $3 AND environment = $4""",
        json.dumps(patch), "api", app_name, environment
    )
```

---

## Design Decisions & Trade-offs

| Decision | Benefit | Trade-off |
|----------|---------|-----------|
| Single table | Zero joins, simple queries, easy ops | No enforced per-key schema |
| JSONB `config` column | No migrations when structure changes | Requires app-level validation |
| `secret_refs` separate column | Secrets never stored, Key Vault enforced | App must resolve URIs at runtime |
| `version` counter | Optimistic locking, audit correlation | App must increment on every update |
| GIN index on `config` | Fast JSONB key/value lookups | Slightly larger index size |
| `subscription_id` column | Per-Azure-subscription config overrides | `UNIQUE` constraint includes `NULL` |

---

## Future Extensions

When the simple solution needs to grow, consider adding:

- **`config_change_history` table** — append-only audit log storing `old_config` / `new_config` JSONB snapshots with ServiceNow ticket reference
- **`config_snapshots` table** — point-in-time tagged snapshots linked to ADO pipeline run IDs for rollback
- **JSON Schema validation** — store a `schema` JSONB column and validate at the application or trigger level
- **Redis cache layer** — cache resolved configs with short TTL to reduce DB reads at scale
- **Feature flags table** — promote `feature_flags` out of JSONB into a dedicated table once rollout percentage or user-segment rules are needed

---

*Internal use only · Infrastructure & Platform Engineering*
