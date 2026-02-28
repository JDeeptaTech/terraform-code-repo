# Application Configuration — DB Schema
> Single-table approach · PostgreSQL + JSONB · Azure Key Vault integration · v2.0

---

## What's new in v2.0

| | v1.0 | v2.0 |
|---|---|---|
| Config lookup | `app_name + environment` | `app_name + config_name + environment` |
| Secret storage | Separate `secret_refs` column | Key Vault URIs live **inside `config` JSONB** |
| Secret detection | Explicit column | Auto-scan any value containing `vault.azure.net` |

---

## Overview

Single PostgreSQL table for storing application configurations across multiple environments
(`dev`, `test`, `uat`, `prod`). The `config_name` column separates configs into logical
groups — each row stays small and focused rather than one large blob per app/env.

Azure Key Vault URIs are stored directly inside the `config` JSONB alongside regular values
and resolved at runtime by the application or Ansible.

---

## Design Principles

- **Single table** — no joins, minimal ops overhead, easy to reason about
- **`config_name` grouping** — one row per concern: `database`, `cache`, `feature-flags`, `integrations`
- **JSONB config column** — flexible, schema-free, no DB migrations when structures change
- **Vault URIs in-place** — Key Vault URIs coexist with regular values; resolved at startup
- **Version counter** — incremented on every update, supports optimistic locking and audit trail
- **Azure-native auth** — Managed Identity for Key Vault, no credentials stored anywhere

---

## Schema Definition

```sql
CREATE TABLE configurations (
    id              UUID         PRIMARY KEY DEFAULT gen_random_uuid(),
    app_name        VARCHAR(150) NOT NULL,
    config_name     VARCHAR(150) NOT NULL,   -- 'database', 'cache', 'feature-flags', 'integrations'
    environment     VARCHAR(50)  NOT NULL,   -- 'dev', 'test', 'uat', 'prod'
    config          JSONB        NOT NULL DEFAULT '{}',
                                             -- Key Vault URIs stored inline alongside regular values

    version         INTEGER      NOT NULL DEFAULT 1,
    is_active       BOOLEAN      NOT NULL DEFAULT TRUE,
    created_by      VARCHAR(150) NOT NULL,
    updated_by      VARCHAR(150),
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW(),

    UNIQUE (app_name, config_name, environment)
);

-- Indexes
CREATE INDEX idx_conf_app_env  ON configurations (app_name, environment);
CREATE INDEX idx_conf_app_name ON configurations (app_name, config_name, environment);
CREATE INDEX idx_conf_gin      ON configurations USING GIN (config);
```

---

## Using `config_name`

`config_name` splits each app's configuration into logical groups. Each row is small,
independently versioned, and easy to audit or rotate.

```
app_name = "trading-engine"  |  environment = "prod"
─────────────────────────────────────────────────────────────────────
config_name = "database"       config_name = "cache"
  host                           host
  port                           port
  name                           ttl_seconds
  max_connections                max_retries
  password 🔑 (vault URI)

config_name = "feature-flags"  config_name = "integrations"
  new_dashboard                  ig_markets.base_url
  dark_mode                      ig_markets.account_id
  live_price_stream              ig_markets.api_key 🔑 (vault URI)
  beta_analytics                 ig_markets.password 🔑 (vault URI)
```

> **Naming convention** — use lowercase kebab-case: `database`, `cache`, `feature-flags`,
> `integrations`, `observability`. Avoid a catch-all `default` — named groups are easier
> to own and rotate independently.

---

## Column Reference

| Column | Type | Nullable | Description |
|--------|------|----------|-------------|
| `id` | UUID | auto | Auto-generated primary key |
| `app_name` | VARCHAR(150) | ✖ | Application identifier — e.g. `trading-engine`, `api-gateway` |
| `config_name` | VARCHAR(150) | ✖ | Logical config group — e.g. `database`, `cache`, `feature-flags` |
| `environment` | VARCHAR(50) | ✖ | Target environment: `dev`, `test`, `uat`, `prod` |
| `config` | JSONB | ✖ | Config as nested JSON. Regular values and Key Vault URIs coexist — URIs resolved at runtime |
| `version` | INTEGER | ✖ | Incremented on every update. Supports optimistic locking and audit correlation |
| `is_active` | BOOLEAN | ✖ | Soft-delete flag. Inactive rows are ignored at query time |
| `created_by` / `updated_by` | VARCHAR(150) | mixed | Service account or user identity |
| `created_at` / `updated_at` | TIMESTAMPTZ | ✖ | Timestamps with timezone for all environments |

---

## Sample Data

Four rows for `trading-engine / prod` — one per config group:

```sql
-- Database config (password = Key Vault URI)
INSERT INTO configurations (app_name, config_name, environment, config, created_by)
VALUES ('trading-engine', 'database', 'prod', '{
    "host":            "db-prod.internal.example.com",
    "port":            5432,
    "name":            "trading",
    "max_connections": 100,
    "password":        "https://myvault.vault.azure.net/secrets/trading-db-password"
}', 'pradeep');

-- Cache config (no secrets)
INSERT INTO configurations (app_name, config_name, environment, config, created_by)
VALUES ('trading-engine', 'cache', 'prod', '{
    "host":        "redis-prod.internal.example.com",
    "port":        6379,
    "ttl_seconds": 300
}', 'pradeep');

-- Feature flags (no secrets)
INSERT INTO configurations (app_name, config_name, environment, config, created_by)
VALUES ('trading-engine', 'feature-flags', 'prod', '{
    "new_dashboard":     true,
    "dark_mode":         false,
    "live_price_stream": true
}', 'pradeep');

-- Integrations (multiple Key Vault URIs)
INSERT INTO configurations (app_name, config_name, environment, config, created_by)
VALUES ('trading-engine', 'integrations', 'prod', '{
    "ig_markets": {
        "base_url":   "https://api.ig.com/gateway/deal",
        "account_id": "Z12345",
        "api_key":    "https://myvault.vault.azure.net/secrets/ig-api-key",
        "password":   "https://myvault.vault.azure.net/secrets/ig-password"
    }
}', 'pradeep');
```

---

## Common Query Patterns

### List all config names for an app
```sql
SELECT config_name, environment, version, updated_at
FROM   configurations
WHERE  app_name  = 'trading-engine'
  AND  is_active = TRUE
ORDER BY environment, config_name;
```

### Fetch a specific config at runtime
```sql
SELECT config, version
FROM   configurations
WHERE  app_name    = 'trading-engine'
  AND  config_name = 'database'
  AND  environment = 'prod'
  AND  is_active   = TRUE;
```

### Update a single key (non-destructive)
```sql
UPDATE configurations
SET    config     = jsonb_set(config, '{max_connections}', '200'),
       updated_by = 'pradeep',
       updated_at = NOW(),
       version    = version + 1
WHERE  app_name    = 'trading-engine'
  AND  config_name = 'database'
  AND  environment = 'prod';
```

### Merge / patch a top-level section
```sql
UPDATE configurations
SET    config = config || '{"ttl_seconds": 600}'::jsonb
WHERE  app_name    = 'trading-engine'
  AND  config_name = 'cache'
  AND  environment = 'prod';

-- Note: || does shallow merge at top level.
-- Use jsonb_set() for deep nested updates.
```

### Rotate a secret — point to new Key Vault version
```sql
UPDATE configurations
SET    config     = jsonb_set(
                       config,
                       '{password}',
                       '"https://myvault.vault.azure.net/secrets/trading-db-password/newversion123"'
                   ),
       updated_by = 'pradeep',
       updated_at = NOW(),
       version    = version + 1
WHERE  app_name    = 'trading-engine'
  AND  config_name = 'database'
  AND  environment = 'prod';
```

### Audit — find all configs containing a vault URI
```sql
SELECT app_name, config_name, environment
FROM   configurations
WHERE  config::text LIKE '%vault.azure.net%'
  AND  is_active = TRUE;
```

---

## PostgreSQL JSONB Operator Reference

| Operator | Example | Description |
|----------|---------|-------------|
| `->` | `config -> 'database'` | Returns JSON object for key |
| `->>` | `config ->> 'host'` | Returns text value for key |
| `-> ->` | `config -> 'ig_markets' -> 'base_url'` | Nested object navigation |
| `\|\|` | `config \|\| '{...}'::jsonb` | Shallow merge — top-level keys only |
| `jsonb_set()` | `jsonb_set(config, '{a,b}', '"v"')` | Deep nested update without overwrite |
| `@>` | `config @> '{"dark_mode": true}'` | Contains check (GIN-indexed) |
| `::text LIKE` | `config::text LIKE '%vault%'` | Full-text scan — use for auditing |
| `?` | `config ? 'host'` | Key existence check |

---

## Secret Handling

> ⚠️ **Never store plaintext secrets in the `config` column.** Use Azure Key Vault URIs as
> the value. The application and Ansible automatically detect and resolve any string
> containing `vault.azure.net` at startup.

```jsonc
// ✅ Correct — Key Vault URI as value
{
  "host": "db-prod.example.com",
  "port": 5432,
  "password": "https://myvault.vault.azure.net/secrets/db-password"
}

// ❌ Wrong — plaintext secret in config
{
  "host": "db-prod.example.com",
  "port": 5432,
  "password": "Sup3rS3cret!@#"
}
```

### How resolution works

| Step | FastAPI (startup) | Ansible / AAP |
|------|-------------------|---------------|
| 1 | Load `config` JSONB from DB | Query `configurations` table |
| 2 | Recursively scan all string values for `vault.azure.net` | Inline Python script flattens URIs |
| 3 | Fetch secrets in parallel via Azure SDK (Managed Identity) | `az keyvault secret show --id <uri>` |
| 4 | Inject plaintext values back at same JSON paths | Inject into config dict, template to `.env` / YAML |
| 5 | Store in `app.state.config` — never logged | Written to file with `mode: 0640`, `no_log: true` |

### Auth methods

| Method | How to configure |
|--------|------------------|
| **Managed Identity** ✅ recommended | Assign VM/AAP instance `Key Vault Secrets User` role — zero config needed |
| **Service Principal** | Create AAP Custom Credential Type injecting `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`, `AZURE_CLIENT_SECRET` as env vars |
| **Local dev** | Run `az login` — `DefaultAzureCredential` picks it up automatically |

---

## FastAPI Integration

Set `APP_NAME`, `CONFIG_NAME`, and `ENVIRONMENT` as env vars. Config is loaded, secrets
resolved, and everything cached before the app accepts any traffic. Call
`POST /config/reload` after a Key Vault rotation — no restart needed.

```python
# ENV VARS: APP_NAME, CONFIG_NAME, ENVIRONMENT, DATABASE_URL

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.db = await asyncpg.create_pool(DATABASE_URL)

    row = await conn.fetchrow(
        """SELECT config, version FROM configurations
           WHERE app_name=$1 AND config_name=$2 AND environment=$3 AND is_active=TRUE""",
        APP_NAME, CONFIG_NAME, ENVIRONMENT
    )

    raw_config        = dict(row["config"])   # asyncpg returns JSONB as dict
    app.state.config  = await resolve_secrets(raw_config)
    # resolve_secrets() scans all string values for vault.azure.net,
    # fetches in parallel, injects plaintext back at the same JSON paths

    yield  # app is ready


@app.post("/config/reload")
async def reload_config():
    """Hot-reload after Key Vault secret rotation — no restart needed."""
    row              = await _fetch_config(...)
    app.state.config = await resolve_secrets(dict(row["config"]))
    return {"status": "reloaded", "version": row["version"]}
```

### Requirements

```
fastapi>=0.111.0
uvicorn[standard]>=0.29.0
asyncpg>=0.29.0
azure-identity>=1.16.0
azure-keyvault-secrets>=4.8.0
```

---

## Ansible / AAP Integration

```bash
ansible-playbook fetch_and_apply_config_secrets.yml \
  -e "app_name=trading-engine config_name=database environment=prod"
```

The playbook queries the DB, scans for vault URIs, resolves each using
`az keyvault secret show`, and templates the resolved config to `.env` or YAML files.

> ⚠️ **AAP activity stream warning** — never include resolved secret values in `set_stats`.
> They appear in the activity stream in plaintext. Only pass non-secret values
> (hostnames, feature flags, versions) downstream to other job templates.

---

## Design Decisions & Trade-offs

| Decision | Benefit | Trade-off |
|----------|---------|-----------|
| Single table | Zero joins, simple queries, easy ops | No enforced per-key schema |
| `config_name` column | Separates concerns, independent versioning per group | App needs to know which `config_name` to load |
| Vault URIs inside `config` JSONB | No separate column — one place to look | App/Ansible must always scan for URIs before use |
| `version` counter | Optimistic locking, audit correlation | App must increment on every update |
| GIN index on `config` | Fast JSONB key/value lookups | Slightly larger index size |
| Managed Identity auth | No credentials stored anywhere | Requires Azure-hosted deployment or AAP on Azure |

---

## Future Extensions

Start with this single-table solution. Add the following only when a specific need arises:

- **`config_change_history` table** — append-only audit log with `old_config` / `new_config` JSONB snapshots and ServiceNow ticket reference
- **`config_snapshots` table** — point-in-time rollback tied to ADO pipeline run IDs or git tags
- **JSON Schema validation** — store a `schema` JSONB column and validate at app or trigger level
- **Redis cache layer** — short-TTL cache to reduce DB reads at scale
- **`subscription_id` column** — per-Azure-subscription config overrides across 100+ subscriptions

---

*Internal use only · Infrastructure & Platform Engineering · v2.0 · Feb 2026*
