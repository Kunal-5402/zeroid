<p align="center">
  <h1 align="center">ZeroID</h1>
  <p align="center"><strong>Identity for the agent stack.</strong></p>
  <p align="center">
    Issue credentials, delegate between agents, attest, revoke in real-time — with a clean human-to-agent handoff built in.
    <br/>
    OAuth 2.1 &middot; WIMSE/SPIFFE &middot; One binary, one Postgres.
  </p>
</p>

---

## Why ZeroID?

Every system deploying AI agents hits the same wall: **"How do we securely identify, authorize, and audit what these agents do?"**

Existing auth systems were built for humans clicking buttons. ZeroID is built for agents calling agents — with short-lived credentials, scoped delegation, trust levels, real-time revocation, and a full audit trail.

## Features

- **Agent Identity Registry** — Register agents, applications, MCP servers, and services with typed classifications, trust levels, and lifecycle management
- **OAuth 2.1 Token Issuance** — `client_credentials`, `jwt_bearer` (RFC 7523), `token_exchange` (RFC 8693), `api_key`, `authorization_code` (PKCE), `refresh_token`
- **Agent-to-Agent Delegation** — RFC 8693 token exchange with scope intersection, delegation depth tracking, and cascade revocation
- **WIMSE/SPIFFE URIs** — Every identity gets a stable `spiffe://{domain}/{account}/{project}/{type}/{id}` URI as its JWT subject
- **Attestation Framework** — Software, platform, and hardware attestation to elevate trust levels
- **Continuous Access Evaluation (CAE)** — Real-time risk signals trigger automatic credential revocation
- **Credential Policies** — Governance templates controlling TTL, allowed grants, required trust levels, max delegation depth
- **WIMSE Proof Tokens** — Single-use, nonce-bound proof tokens for service-to-service identity verification
- **Refresh Token Rotation** — Family-based rotation with reuse detection (RFC best practices)
- **Multi-Tenant** — Every resource scoped by `(account_id, project_id)`
- **Extensible** — Custom grant types and JWT claims via hooks

## Quick Start

### Docker (30 seconds)

```bash
docker compose up -d
```

ZeroID starts on `http://localhost:8899` with Postgres provisioned automatically.

### From Source

```bash
# Generate signing keys
make setup-keys

# Start Postgres (or point ZEROID_DATABASE_URL to your own)
docker compose up -d postgres

# Run
make run
```

### Verify it's running

```bash
curl http://localhost:8899/health
# {"status":"ok"}

curl http://localhost:8899/.well-known/jwks.json
# {"keys":[{"kty":"EC","crv":"P-256",...}]}
```

## 5-Minute Tutorial

### 1. Register an Agent Identity

```bash
curl -X POST http://localhost:8899/api/v1/identities \
  -H "Content-Type: application/json" \
  -H "X-Account-ID: acme" \
  -H "X-Project-ID: prod" \
  -d '{
    "external_id": "orchestrator-1",
    "name": "Task Orchestrator",
    "identity_type": "agent",
    "sub_type": "orchestrator",
    "trust_level": "first_party",
    "owner_user_id": "user-1",
    "allowed_scopes": ["data:read", "data:write", "agents:delegate"]
  }'
```

### 2. Register an OAuth2 Client

The `external_id` must match the identity's `external_id` from step 1. ZeroID auto-generates a secure `client_secret` — save it, it's shown only once.

```bash
curl -X POST http://localhost:8899/api/v1/oauth/clients \
  -H "Content-Type: application/json" \
  -H "X-Account-ID: acme" \
  -H "X-Project-ID: prod" \
  -d '{
    "name": "Orchestrator Client",
    "external_id": "orchestrator-1",
    "grant_types": ["client_credentials", "token_exchange"],
    "scopes": ["data:read", "data:write", "agents:delegate"]
  }'
# Returns: {"client": {"client_id": "orchestrator-1", ...}, "client_secret": "<save-this>"}
```

### 3. Get an Agent Token (client_credentials)

```bash
curl -X POST http://localhost:8899/oauth2/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "client_credentials",
    "client_id": "orchestrator-1",
    "client_secret": "<client_secret_from_step_2>",
    "scope": "data:read data:write"
  }'
# Returns: {"access_token": "eyJ...", "token_type": "Bearer", "expires_in": 3600}
```

### 4. Delegate to a Sub-Agent (token_exchange)

```bash
# Register a sub-agent with a public key for jwt_bearer
curl -X POST http://localhost:8899/api/v1/identities \
  -H "Content-Type: application/json" \
  -H "X-Account-ID: acme" \
  -H "X-Project-ID: prod" \
  -d '{
    "owner_user_id": "user-1",
    "external_id": "data-fetcher",
    "name": "Data Fetcher",
    "identity_type": "agent",
    "sub_type": "tool_agent",
    "trust_level": "first_party",
    "allowed_scopes": ["data:read"],
    "public_key_pem": "<agent_ec_p256_public_key>"
  }'

# Sub-agent self-signs a JWT assertion, then orchestrator delegates:
curl -X POST http://localhost:8899/oauth2/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "subject_token": "<orchestrator_jwt>",
    "actor_token": "<sub_agent_self_signed_assertion>",
    "scope": "data:read"
  }'
# Returns JWT with:
#   sub = spiffe://zeroid.dev/acme/prod/agent/data-fetcher
#   act = {"sub": "spiffe://zeroid.dev/acme/prod/agent/orchestrator-1"}
#   scopes = ["data:read"]  (intersection of all three scope sets)
```

### 5. Introspect & Revoke

```bash
# Introspect
curl -X POST http://localhost:8899/oauth2/token/introspect \
  -H "Content-Type: application/json" \
  -d '{"token": "<jwt>"}'
# {"active": true, "sub": "spiffe://...", "scopes": [...]}

# Revoke
curl -X POST http://localhost:8899/oauth2/token/revoke \
  -H "Content-Type: application/json" \
  -d '{"token": "<jwt>"}'
# 200 OK (always succeeds per RFC 7009)
```

## Architecture

```mermaid
graph TD
    subgraph ZEROID ["🔐 ZeroID"]
        direction TB
        IR[Identity Registry] --> CS[Credential Service<br/><i>ES256 signing · Policy enforcement · Audit</i>]
        OG[OAuth2 Grants<br/><i>client_credentials · jwt_bearer · api_key<br/>authorization_code · refresh_token</i>] --> CS
        DL[Delegation Engine<br/><i>RFC 8693 token_exchange</i>] --> CS

        CS --> AT[Attestation]
        CS --> CAE[CAE Signals<br/><i>Real-time revocation</i>]
        CS --> WPT[WIMSE Proof Tokens<br/><i>Single-use, nonce-bound</i>]

        AT --> DB[(PostgreSQL)]
        CAE --> DB
        WPT --> DB
        CS --> DB
    end

    Agent([AI Agent]) -- "jwt_bearer / client_credentials" --> OG
    Orchestrator([Orchestrator]) -- "token_exchange" --> DL
    SDK([SDK / CLI]) -- "api_key / authorization_code" --> OG
    Downstream([Downstream Services]) -- "verify" --> WPT

    style ZEROID fill:#1a1a2e,stroke:#e94560,stroke-width:3px,color:#fff
    style CS fill:#2d6a4f,color:#fff
    style DB fill:#264653,color:#fff
    style Agent fill:#e76f51,color:#fff
    style Orchestrator fill:#e76f51,color:#fff
    style SDK fill:#e9c46a,color:#000
    style Downstream fill:#457b9d,color:#fff
```

**Tokens issued:**

| Flow | Algorithm | Default TTL | Subject |
|------|-----------|-------------|---------|
| Agent (NHI) | ES256 | 1 hour | WIMSE URI (`spiffe://{domain}/...`) |
| SDK / CLI | RS256 (optional) | Configurable | User ID or WIMSE URI |
| Delegated | ES256 | 1 hour | Sub-agent WIMSE URI + `act` claim |

## Standards

| Standard | RFC | Used For |
|----------|-----|----------|
| OAuth 2.0 Client Credentials | 6749 §4.4 | Machine-to-machine auth |
| JWT Profile for OAuth 2.0 | 7523 | Agent JWT assertions |
| OAuth 2.0 Token Exchange | 8693 | Agent-to-agent delegation |
| Token Introspection | 7662 | Credential status check |
| Token Revocation | 7009 | Credential revocation |
| PKCE | 7636 | Authorization code flow |
| JSON Web Tokens | 7519 | Issued token format |
| JSON Web Key Sets | 7517 | Public key distribution |
| WIMSE/SPIFFE | Draft/SPIFFE | Agent identity URIs |
| CAEP | OpenID CAEP | Real-time revocation signals |

## Configuration

ZeroID is configured via YAML file and/or environment variables.

```yaml
server:
  port: "8899"

database:
  url: "postgres://zeroid:zeroid@localhost:5432/zeroid?sslmode=disable"

keys:
  ecdsa_private_key_path: "keys/private.pem"
  ecdsa_public_key_path: "keys/public.pem"
  # Optional RSA keys for RS256 signing (SDK/CLI tokens)
  # rsa_private_key_path: "keys/rsa_private.pem"
  # rsa_public_key_path: "keys/rsa_public.pem"

token:
  issuer: "https://auth.zeroid.dev"
  default_ttl: 3600
  max_ttl: 7776000

wimse_domain: "zeroid.dev"
```

Environment variables override YAML (prefix: `ZEROID_`):

```bash
ZEROID_DATABASE_URL=postgres://...
ZEROID_ECDSA_PRIVATE_KEY_PATH=keys/private.pem
ZEROID_ECDSA_PUBLIC_KEY_PATH=keys/public.pem
ZEROID_TOKEN_ISSUER=https://auth.example.com
ZEROID_WIMSE_DOMAIN=example.com
```

## Using as a Library

ZeroID can be imported as a Go module for embedding in your own service:

```go
package main

import (
    "log"
    "net/http"
    zeroid "github.com/zeroid-dev/zeroid"
    "github.com/zeroid-dev/zeroid/domain"
)

func main() {
    cfg, _ := zeroid.LoadConfig("")
    srv, _ := zeroid.NewServer(cfg)

    // Optional: protect admin routes with custom auth
    srv.AdminAuth(func(next http.Handler) http.Handler {
        return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
            if r.Header.Get("X-Admin-Key") != "my-secret" {
                http.Error(w, "unauthorized", 401)
                return
            }
            next.ServeHTTP(w, r)
        })
    })

    // Add custom JWT claims
    srv.OnClaimsIssue(func(claims map[string]any, id *domain.Identity, gt domain.GrantType) {
        claims["gateway_id"] = "gw-123"
    })

    log.Fatal(srv.Start())
}
```

## API Reference

### Public Endpoints (No Auth)

| Method | Path | Description |
|--------|------|-------------|
| GET | `/health` | Health check |
| GET | `/ready` | Readiness check |
| GET | `/.well-known/jwks.json` | JWKS public keys |
| GET | `/.well-known/oauth-authorization-server` | OAuth2 server metadata |
| POST | `/oauth2/token` | Issue token (6 grant types) |
| POST | `/oauth2/token/introspect` | Token introspection (RFC 7662) |
| POST | `/oauth2/token/revoke` | Token revocation (RFC 7009) |

### Admin Endpoints (/api/v1/* — protect at network layer)

| Method | Path | Description |
|--------|------|-------------|
| POST | `/api/v1/identities` | Register identity |
| GET | `/api/v1/identities/{id}` | Get identity |
| PATCH | `/api/v1/identities/{id}` | Update identity |
| DELETE | `/api/v1/identities/{id}` | Deactivate identity |
| GET | `/api/v1/identities` | List identities |
| POST | `/api/v1/agents/register` | Register agent (atomic: identity + API key) |
| POST | `/api/v1/oauth/clients` | Register OAuth2 client |
| POST | `/api/v1/credentials/{id}/revoke` | Revoke credential |
| POST | `/api/v1/api-keys` | Create API key |
| POST | `/api/v1/signals/ingest` | Ingest CAE signal |
| GET | `/api/v1/signals/stream` | SSE signal stream |

*See full API documentation at `GET /docs` when running.*

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

Apache License 2.0 — see [LICENSE](LICENSE) for details.
