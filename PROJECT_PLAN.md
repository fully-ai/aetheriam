# AetherIAM — Architecture & Implementation Plan

## 1. Executive Summary
**AetherIAM** is a self-hosted Identity & Access Management (IAM), OAuth2/OIDC Token Issuer, Hybrid RBAC/ABAC Policy Evaluation Engine, Scoped API Key Manager, and Tamper-Evident Hash-Chained Audit Governance Platform written in pure Go.

## 2. Core Architectural Pillars
1. **Zero-CGo Transactional WAL Storage Engine (`internal/store`)**
   - Append-only JSON Write-Ahead Log (`wal.log`) paired with atomic point-in-time state snapshots (`snapshot.json`).
   - In-memory B-tree/Hash indexes protected by `sync.RWMutex` for sub-millisecond reads and serialized ACID writes.
   - Built-in schema migration tracking (`migrations`), online JSON snapshot backup (`/api/v1/admin/backup`), and hot state restoration (`/api/v1/admin/restore`).
2. **Cryptographic & OIDC Core (`internal/crypto`)**
   - Salted PBKDF2-HMAC-SHA256 password key derivation (60,000 iterations, 16-byte cryptographic random salt, constant-time comparison).
   - Dual-algorithm JWT issuance and verification supporting `RS256` (RSA-2048 SHA-256) and `HS256` (HMAC-SHA256).
   - RFC 7517 JSON Web Key Set (`/.well-known/jwks.json`) and OpenID Connect Discovery 1.0 (`/.well-known/openid-configuration`).
   - Scoped API keys prefixed with `aiam_` stored exclusively via SHA-256 digests.
   - SHA-256 cryptographic hash-chaining across every audit ledger record (`H_n = SHA256(H_{n-1} || timestamp || actor || action || resource || outcome || details)`).
3. **Hybrid RBAC + ABAC Policy Engine (`internal/policy`)**
   - Deterministic zero-trust policy evaluation (`Default Deny`, `Explicit Deny Overrides Allow`).
   - Combines role permission wildcards (`*:*`, `service:*`) with fine-grained attribute conditions: IPv4/IPv6 CIDR blocks, Department, Environment (`production`, `staging`, `development`), MFA verification status, Resource Ownership (`OwnerMatch`), UTC Time Windows (`HH:MM`), and custom key-value tags.
   - Emits a structured step-by-step evaluation trace for live auditing and policy simulation.
4. **REST API v1 & Governance Runtime (`internal/api`)**
   - Per-client Token Bucket rate limiter middleware, structured JSON access logs, Prometheus metrics (`/metrics`), health probes (`/healthz`), and full CRUD endpoints.
5. **AetherIAM Security & Identity Console (`internal/web`)**
   - Embedded single-binary Web UI featuring an Indigo/Violet/Emerald security palette, Dark/Light mode toggle, live metric telemetry, user/role/policy management modals, interactive RBAC/ABAC Policy Simulator with step trace visualization, OAuth2 Client & API Key issuance, and hash-chain integrity verification.

## 3. Directory Layout
```text
aetheriam/
├── cmd/aetheriam/main.go
├── internal/
│   ├── api/
│   │   ├── server.go
│   │   └── server_test.go
│   ├── crypto/
│   │   ├── crypto.go
│   │   └── crypto_test.go
│   ├── policy/
│   │   ├── engine.go
│   │   └── engine_test.go
│   ├── store/
│   │   └── store.go
│   └── web/
│       ├── embed.go
│       └── static/
│           ├── index.html
│           ├── styles.css
│           └── app.js
├── Dockerfile
├── docker-compose.yml
├── .github/workflows/ci.yml
├── CHANGELOG.md
├── LICENSE
└── README.md
```
