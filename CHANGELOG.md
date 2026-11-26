# Changelog

All notable changes to **AetherIAM** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [v0.1.0] - 2026-11-26

### Added
- **Cryptographic Identity Core (`internal/crypto`)**:
  - Salted PBKDF2-HMAC-SHA256 password hashing with constant-time verification (`HashPassword`, `VerifyPassword`).
  - Dual RSA-SHA256 (`RS256`) and HMAC-SHA256 (`HS256`) JWT token signing and validation.
  - Standards-compliant OIDC Discovery (`/.well-known/openid-configuration`) and RFC 7517 JSON Web Key Set (`/.well-known/jwks.json`).
  - Scoped API key generator with `aiam_` prefix and SHA-256 fingerprint storage.
  - Cryptographic SHA-256 hash-chaining for tamper-evident audit trails.
- **Hybrid RBAC + ABAC Policy Evaluation Engine (`internal/policy`)**:
  - Combined Role-Based Access Control (wildcard & scoped resource-action permissions) and Attribute-Based Access Control (IP CIDR blocks, department, environment, MFA verification requirement, resource owner matching, UTC time windows, custom attribute tags).
  - Deterministic explicit-deny overrides allow evaluation with granular step-by-step explanation trace.
- **Transactional WAL Storage Engine (`internal/store`)**:
  - Zero-CGo persistent JSON Write-Ahead Log (`wal.log`) and atomic state snapshot (`snapshot.json`) storage with automatic schema migrations, indexed collections (`users`, `roles`, `policies`, `oauth_clients`, `api_keys`, `sessions`, `audit_logs`), and hot JSON backup/restore endpoints.
- **REST API v1 & Observability (`internal/api`)**:
  - OAuth2 token issuance (`client_credentials` and `password` grants) + live JWT verification endpoint (`/api/v1/auth/verify`).
  - Full CRUD endpoints for Users, Roles, Policies, OAuth2 Clients, and Scoped API Keys.
  - Interactive Policy Simulator endpoint (`POST /api/v1/policies/evaluate`).
  - Tamper-evident Audit Ledger endpoint (`GET /api/v1/audit`) with search, severity filtering, and live cryptographic chain integrity verification.
  - Token-bucket rate limiting middleware, Prometheus metrics (`GET /metrics`), and health probe (`GET /healthz`).
- **AetherIAM Security & Identity Console (`internal/web`)**:
  - Embedded zero-dependency dark/light Web UI for managing users, roles, ABAC policies, running live policy simulations, provisioning OAuth2 clients & API keys, inspecting hash-chained audit logs, and performing live state backup/restore.
