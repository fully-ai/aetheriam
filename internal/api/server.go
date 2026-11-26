package api

import (
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fully-ai/aetheriam/internal/crypto"
	"github.com/fully-ai/aetheriam/internal/policy"
	"github.com/fully-ai/aetheriam/internal/store"
)

// tokenBucket implements per-IP token bucket rate limiting.
type tokenBucket struct {
	tokens     float64
	lastRefill time.Time
}

// RateLimiter enforces per-IP token bucket limits.
type RateLimiter struct {
	mu      sync.Mutex
	rps     float64
	burst   float64
	buckets map[string]*tokenBucket
}

// NewRateLimiter creates a token bucket rate limiter with rps refill rate and burst capacity.
func NewRateLimiter(rps, burst float64) *RateLimiter {
	if rps <= 0 {
		rps = 50
	}
	if burst <= 0 {
		burst = 100
	}
	return &RateLimiter{
		rps:     rps,
		burst:   burst,
		buckets: make(map[string]*tokenBucket),
	}
}

// Allow checks if the client IP has at least 1 token available.
func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, exists := rl.buckets[ip]
	if !exists {
		rl.buckets[ip] = &tokenBucket{
			tokens:     rl.burst - 1,
			lastRefill: now,
		}
		return true
	}
	elapsed := now.Sub(b.lastRefill).Seconds()
	b.tokens += elapsed * rl.rps
	if b.tokens > rl.burst {
		b.tokens = rl.burst
	}
	b.lastRefill = now
	if b.tokens < 1.0 {
		return false
	}
	b.tokens -= 1.0
	return true
}

// Server wires the storage engine, cryptographic key manager, policy evaluator, metrics, and embedded web UI.
type Server struct {
	store       *store.Store
	keys        *crypto.KeyManager
	limiter     *RateLimiter
	webFS       fs.FS
	startedAt   time.Time
	mux         *http.ServeMux

	// Atomic Prometheus metrics counters
	totalRequests     atomic.Int64
	tokensIssued      atomic.Int64
	tokensVerified    atomic.Int64
	policyEvalsTotal  atomic.Int64
	policyEvalsAllow  atomic.Int64
	policyEvalsDeny   atomic.Int64
	rateLimitDrops    atomic.Int64
}

// Config holds server configuration parameters.
type Config struct {
	Store          *store.Store
	Keys           *crypto.KeyManager
	WebFS          fs.FS
	RateLimitRPS   float64
	RateLimitBurst float64
}

// NewServer constructs and registers all AetherIAM REST API v1, OIDC Discovery, Prometheus, and Web Console routes.
func NewServer(cfg Config) *Server {
	s := &Server{
		store:     cfg.Store,
		keys:      cfg.Keys,
		limiter:   NewRateLimiter(cfg.RateLimitRPS, cfg.RateLimitBurst),
		webFS:     cfg.WebFS,
		startedAt: time.Now().UTC(),
		mux:       http.NewServeMux(),
	}
	s.routes()
	return s
}

// Handler returns the root HTTP handler wrapped with logging, security headers, CORS, and rate limiting.
func (s *Server) Handler() http.Handler {
	return s.withMiddleware(s.mux)
}

func (s *Server) routes() {
	// Health & Prometheus Observability
	s.mux.HandleFunc("/healthz", s.handleHealthz)
	s.mux.HandleFunc("/metrics", s.handleMetrics)

	// OIDC Discovery & JWKS Public Key Endpoints
	s.mux.HandleFunc("/.well-known/openid-configuration", s.handleOIDCDiscovery)
	s.mux.HandleFunc("/.well-known/jwks.json", s.handleJWKS)

	// Overview Telemetry & Audit Chain Status
	s.mux.HandleFunc("/api/v1/stats", s.handleStats)

	// OAuth2 Token Issuance & JWT Introspection/Verification
	s.mux.HandleFunc("/api/v1/auth/token", s.handleAuthToken)
	s.mux.HandleFunc("/api/v1/auth/verify", s.handleAuthVerify)

	// Identity & User Management
	s.mux.HandleFunc("/api/v1/users", s.handleUsers)
	s.mux.HandleFunc("/api/v1/users/", s.handleUserByID)

	// RBAC Roles CRUD
	s.mux.HandleFunc("/api/v1/roles", s.handleRoles)
	s.mux.HandleFunc("/api/v1/roles/", s.handleRoleByID)

	// RBAC + ABAC Policies CRUD & Live Policy Simulator
	s.mux.HandleFunc("/api/v1/policies", s.handlePolicies)
	s.mux.HandleFunc("/api/v1/policies/", s.handlePolicyByID)
	s.mux.HandleFunc("/api/v1/policies/evaluate", s.handlePolicyEvaluate)

	// OAuth2 Client Registration CRUD
	s.mux.HandleFunc("/api/v1/clients", s.handleClients)
	s.mux.HandleFunc("/api/v1/clients/", s.handleClientByID)

	// Scoped API Keys CRUD
	s.mux.HandleFunc("/api/v1/apikeys", s.handleAPIKeys)
	s.mux.HandleFunc("/api/v1/apikeys/", s.handleAPIKeyByID)

	// Tamper-Evident Hash-Chained Audit Ledger
	s.mux.HandleFunc("/api/v1/audit", s.handleAudit)

	// Online Atomic State Backup & Hot Restore
	s.mux.HandleFunc("/api/v1/admin/backup", s.handleBackup)
	s.mux.HandleFunc("/api/v1/admin/restore", s.handleRestore)

	// Embedded AetherIAM Security Console UI
	if s.webFS != nil {
		fileServer := http.FileServer(http.FS(s.webFS))
		s.mux.Handle("/", fileServer)
	} else {
		s.mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			writeJSON(w, http.StatusOK, map[string]string{
				"service": "AetherIAM Identity & Policy Engine",
				"status":  "operational",
			})
		})
	}
}

func (s *Server) withMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		s.totalRequests.Add(1)

		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "SAMEORIGIN")
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Actor")

		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}

		ip := clientIP(r)
		if strings.HasPrefix(r.URL.Path, "/api/") && !s.limiter.Allow(ip) {
			s.rateLimitDrops.Add(1)
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusTooManyRequests, map[string]any{
				"error":   "rate_limit_exceeded",
				"message": "Token bucket rate limit exceeded for client IP",
			})
			return
		}

		next.ServeHTTP(w, r)

		if strings.HasPrefix(r.URL.Path, "/api/") {
			log.Printf(`{"ts":"%s","method":"%s","path":"%s","ip":"%s","duration_us":%d}`,
				time.Now().UTC().Format(time.RFC3339),
				r.Method,
				r.URL.Path,
				ip,
				time.Since(start).Microseconds(),
			)
		}
	})
}

func (s *Server) resolveActor(r *http.Request) string {
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		token := strings.TrimPrefix(auth, "Bearer ")
		if strings.HasPrefix(token, crypto.APIKeyPrefix) {
			if k, ok := s.store.VerifyAPIKey(token); ok {
				return "apikey:" + k.Name
			}
		} else if claims, _, err := s.keys.VerifyJWT(token); err == nil {
			if claims.Username != "" {
				return claims.Username
			}
			return claims.Subject
		}
	}
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		if k, ok := s.store.VerifyAPIKey(apiKey); ok {
			return "apikey:" + k.Name
		}
	}
	if actor := strings.TrimSpace(r.Header.Get("X-Actor")); actor != "" {
		return actor
	}
	return "admin@console"
}

func (s *Server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	validChain, verifiedEntries, _ := s.store.VerifyAuditChain()
	writeJSON(w, http.StatusOK, map[string]any{
		"status":               "healthy",
		"service":              "aetheriam",
		"version":              "v0.1.0",
		"uptime_seconds":       int64(time.Since(s.startedAt).Seconds()),
		"active_key_id":        s.keys.KeyID(),
		"audit_chain_verified": validChain,
		"audit_entries":        verifiedEntries,
	})
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	stats := s.store.Stats()
	validChain, _, _ := s.store.VerifyAuditChain()
	chainVal := 0
	if validChain {
		chainVal = 1
	}

	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	fmt.Fprintf(w, "# HELP aetheriam_http_requests_total Total HTTP requests handled by AetherIAM.\n")
	fmt.Fprintf(w, "# TYPE aetheriam_http_requests_total counter\n")
	fmt.Fprintf(w, "aetheriam_http_requests_total %d\n", s.totalRequests.Load())

	fmt.Fprintf(w, "# HELP aetheriam_oauth_tokens_issued_total Total OAuth2/OIDC JWT tokens issued.\n")
	fmt.Fprintf(w, "# TYPE aetheriam_oauth_tokens_issued_total counter\n")
	fmt.Fprintf(w, "aetheriam_oauth_tokens_issued_total %d\n", s.tokensIssued.Load())

	fmt.Fprintf(w, "# HELP aetheriam_jwt_verifications_total Total JWT verification requests processed.\n")
	fmt.Fprintf(w, "# TYPE aetheriam_jwt_verifications_total counter\n")
	fmt.Fprintf(w, "aetheriam_jwt_verifications_total %d\n", s.tokensVerified.Load())

	fmt.Fprintf(w, "# HELP aetheriam_policy_evaluations_total Total RBAC/ABAC policy evaluations.\n")
	fmt.Fprintf(w, "# TYPE aetheriam_policy_evaluations_total counter\n")
	fmt.Fprintf(w, "aetheriam_policy_evaluations_total{decision=\"ALLOW\"} %d\n", s.policyEvalsAllow.Load())
	fmt.Fprintf(w, "aetheriam_policy_evaluations_total{decision=\"DENY\"} %d\n", s.policyEvalsDeny.Load())

	fmt.Fprintf(w, "# HELP aetheriam_rate_limit_drops_total Total requests dropped by token bucket rate limiter.\n")
	fmt.Fprintf(w, "# TYPE aetheriam_rate_limit_drops_total counter\n")
	fmt.Fprintf(w, "aetheriam_rate_limit_drops_total %d\n", s.rateLimitDrops.Load())

	fmt.Fprintf(w, "# HELP aetheriam_users_total Total registered IAM users.\n")
	fmt.Fprintf(w, "# TYPE aetheriam_users_total gauge\n")
	fmt.Fprintf(w, "aetheriam_users_total %v\n", stats["users_total"])

	fmt.Fprintf(w, "# HELP aetheriam_policies_total Total active RBAC/ABAC policies.\n")
	fmt.Fprintf(w, "# TYPE aetheriam_policies_total gauge\n")
	fmt.Fprintf(w, "aetheriam_policies_total %v\n", stats["policies_total"])

	fmt.Fprintf(w, "# HELP aetheriam_audit_chain_valid Cryptographic SHA-256 audit chain integrity (1=valid, 0=tampered).\n")
	fmt.Fprintf(w, "# TYPE aetheriam_audit_chain_valid gauge\n")
	fmt.Fprintf(w, "aetheriam_audit_chain_valid %d\n", chainVal)
}

func (s *Server) handleOIDCDiscovery(w http.ResponseWriter, r *http.Request) {
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	baseURL := s.keys.Issuer()
	if r.Host != "" {
		baseURL = scheme + "://" + r.Host
	}
	writeJSON(w, http.StatusOK, s.keys.OIDCDiscovery(baseURL))
}

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.keys.JWKS())
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	stats := s.store.Stats()
	validChain, verifiedCount, brokenAt := s.store.VerifyAuditChain()
	stats["audit_chain_valid"] = validChain
	stats["audit_verified_count"] = verifiedCount
	stats["audit_broken_at"] = brokenAt
	stats["active_kid"] = s.keys.KeyID()
	stats["issuer"] = s.keys.Issuer()
	stats["tokens_issued"] = s.tokensIssued.Load()
	stats["policy_evals_total"] = s.policyEvalsTotal.Load()
	stats["policy_evals_allow"] = s.policyEvalsAllow.Load()
	stats["policy_evals_deny"] = s.policyEvalsDeny.Load()
	writeJSON(w, http.StatusOK, stats)
}

func (s *Server) handleAuthToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}

	var req struct {
		GrantType    string `json:"grant_type"`
		ClientID     string `json:"client_id"`
		ClientSecret string `json:"client_secret"`
		Username     string `json:"username"`
		Password     string `json:"password"`
		Scope        string `json:"scope"`
		SigningAlg   string `json:"signing_alg"`
		TTLSeconds   int64  `json:"ttl_seconds"`
	}

	contentType := r.Header.Get("Content-Type")
	if strings.Contains(contentType, "application/x-www-form-urlencoded") {
		_ = r.ParseForm()
		req.GrantType = r.FormValue("grant_type")
		req.ClientID = r.FormValue("client_id")
		req.ClientSecret = r.FormValue("client_secret")
		req.Username = r.FormValue("username")
		req.Password = r.FormValue("password")
		req.Scope = r.FormValue("scope")
		req.SigningAlg = r.FormValue("signing_alg")
	} else {
		_ = json.NewDecoder(r.Body).Decode(&req)
	}

	if basicUser, basicPass, ok := r.BasicAuth(); ok {
		if req.ClientID == "" {
			req.ClientID = basicUser
		}
		if req.ClientSecret == "" {
			req.ClientSecret = basicPass
		}
	}

	if req.GrantType == "" {
		req.GrantType = "password"
	}
	if req.TTLSeconds <= 0 || req.TTLSeconds > 86400 {
		req.TTLSeconds = 3600
	}

	now := time.Now().UTC()
	exp := now.Add(time.Duration(req.TTLSeconds) * time.Second).Unix()
	ip := clientIP(r)

	var claims crypto.Claims
	alg := strings.ToUpper(strings.TrimSpace(req.SigningAlg))
	if alg != "RS256" && alg != "HS256" {
		alg = "RS256"
	}

	switch req.GrantType {
	case "password":
		user, exists := s.store.GetUserByUsername(req.Username)
		if !exists || !crypto.VerifyPassword(req.Password, user.PasswordHash) {
			s.store.AppendAuditLog(req.Username, "oauth.token.password", "auth", "warn", "DENY", ip, "Invalid username or password credentials")
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":             "invalid_grant",
				"error_description": "Invalid resource owner username or password credentials",
			})
			return
		}
		if user.Status != "active" {
			s.store.AppendAuditLog(user.Username, "oauth.token.password", user.ID, "warn", "DENY", ip, "User account is not active")
			writeJSON(w, http.StatusForbidden, map[string]string{
				"error":             "account_inactive",
				"error_description": "Identity account status is " + user.Status,
			})
			return
		}
		s.store.TouchUserLogin(user.ID)
		scope := req.Scope
		if scope == "" {
			scope = "openid profile email iam:read policy:evaluate"
		}
		claims = crypto.Claims{
			Subject:    user.ID,
			Audience:   firstNonEmpty(req.ClientID, "aether-console"),
			ExpiresAt:  exp,
			IssuedAt:   now.Unix(),
			Scope:      scope,
			Roles:      user.Roles,
			Department: user.Department,
			Email:      user.Email,
			Username:   user.Username,
			ClientID:   firstNonEmpty(req.ClientID, "aether-console-client"),
			GrantType:  "password",
			TokenType:  "access_token",
			MFA:        user.MFAEnabled,
		}

	case "client_credentials":
		client, exists := s.store.GetOAuthClientByClientID(req.ClientID)
		if !exists || !client.Active {
			s.store.AppendAuditLog(req.ClientID, "oauth.token.client_credentials", "auth", "warn", "DENY", ip, "Unknown or inactive OAuth2 client_id")
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":             "invalid_client",
				"error_description": "Unknown or inactive OAuth2 client_id",
			})
			return
		}
		if crypto.HashAPIKey(req.ClientSecret) != client.ClientSecretHash {
			s.store.AppendAuditLog(req.ClientID, "oauth.token.client_credentials", client.ID, "warn", "DENY", ip, "Invalid OAuth2 client_secret")
			writeJSON(w, http.StatusUnauthorized, map[string]string{
				"error":             "invalid_client",
				"error_description": "Client secret authentication failed",
			})
			return
		}
		if req.SigningAlg == "" && client.SigningAlg != "" {
			alg = client.SigningAlg
		}
		scope := req.Scope
		if scope == "" {
			scope = strings.Join(client.Scopes, " ")
		}
		claims = crypto.Claims{
			Subject:    client.ClientID,
			Audience:   "aetheriam-api",
			ExpiresAt:  exp,
			IssuedAt:   now.Unix(),
			Scope:      scope,
			Roles:      client.DefaultRoles,
			Department: "Machine-Workload",
			Username:   client.ClientID,
			ClientID:   client.ClientID,
			GrantType:  "client_credentials",
			TokenType:  "access_token",
			MFA:        true,
		}

	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{
			"error":             "unsupported_grant_type",
			"error_description": "Supported grant_types: password, client_credentials",
		})
		return
	}

	accessToken, err := s.keys.SignJWT(claims, alg)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}

	refreshClaims := claims
	refreshClaims.TokenType = "refresh_token"
	refreshClaims.ExpiresAt = now.Add(24 * time.Hour).Unix()
	refreshToken, _ := s.keys.SignJWT(refreshClaims, alg)

	s.tokensIssued.Add(1)
	s.store.RecordSession(store.Session{
		SubjectID:  claims.Subject,
		ClientID:   claims.ClientID,
		GrantType:  claims.GrantType,
		Scope:      claims.Scope,
		JWTID:      claims.JWTID,
		SigningAlg: alg,
		IPAddress:  ip,
		ExpiresAt:  time.Unix(exp, 0).UTC().Format(time.RFC3339),
	})
	s.store.AppendAuditLog(claims.Username, "oauth.token.issue", claims.Subject, "info", "ALLOW", ip, fmt.Sprintf("Issued %s JWT via %s grant (roles=%v)", alg, claims.GrantType, claims.Roles))

	writeJSON(w, http.StatusOK, map[string]any{
		"access_token":  accessToken,
		"refresh_token": refreshToken,
		"token_type":    "Bearer",
		"expires_in":    req.TTLSeconds,
		"scope":         claims.Scope,
		"signing_alg":   alg,
		"kid":           s.keys.KeyID(),
		"claims":        claims,
	})
}

func (s *Server) handleAuthVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost && r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}

	var tokenStr string
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		tokenStr = strings.TrimPrefix(auth, "Bearer ")
	}
	if r.Method == http.MethodPost {
		var body struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body.Token != "" {
			tokenStr = body.Token
		}
	}

	tokenStr = strings.TrimSpace(tokenStr)
	if tokenStr == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{
			"active": false,
			"valid":  false,
			"error":  "missing token",
		})
		return
	}

	s.tokensVerified.Add(1)

	// Support verifying both JWT tokens and `aiam_` API keys
	if strings.HasPrefix(tokenStr, crypto.APIKeyPrefix) {
		key, ok := s.store.VerifyAPIKey(tokenStr)
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]any{
				"active": false,
				"valid":  false,
				"error":  "invalid or revoked api key",
			})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"active":     true,
			"valid":      true,
			"token_kind": "api_key",
			"api_key":    key,
		})
		return
	}

	claims, alg, err := s.keys.VerifyJWT(tokenStr)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]any{
			"active":      false,
			"valid":       false,
			"signing_alg": alg,
			"error":       err.Error(),
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"active":      true,
		"valid":       true,
		"token_kind":  "jwt",
		"signing_alg": alg,
		"kid":         s.keys.KeyID(),
		"claims":      claims,
	})
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		users := s.store.ListUsers()
		q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
		dept := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("department")))
		if q != "" || dept != "" {
			filtered := make([]store.User, 0, len(users))
			for _, u := range users {
				if dept != "" && dept != "all" && !strings.EqualFold(u.Department, dept) {
					continue
				}
				if q != "" {
					hay := strings.ToLower(u.Username + " " + u.Email + " " + u.FullName + " " + u.Department + " " + strings.Join(u.Roles, " "))
					if !strings.Contains(hay, q) {
						continue
					}
				}
				filtered = append(filtered, u)
			}
			users = filtered
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"items": users,
			"total": len(users),
		})

	case http.MethodPost:
		var req struct {
			Username   string   `json:"username"`
			Email      string   `json:"email"`
			FullName   string   `json:"full_name"`
			Password   string   `json:"password"`
			Department string   `json:"department"`
			Status     string   `json:"status"`
			MFAEnabled bool     `json:"mfa_enabled"`
			Roles      []string `json:"roles"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json payload"})
			return
		}
		created, err := s.store.CreateUser(store.User{
			Username:   req.Username,
			Email:      req.Email,
			FullName:   req.FullName,
			Department: req.Department,
			Status:     req.Status,
			MFAEnabled: req.MFAEnabled,
			Roles:      req.Roles,
		}, req.Password, s.resolveActor(r), clientIP(r))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, created)

	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing id query parameter"})
			return
		}
		if err := s.store.DeleteUser(id, s.resolveActor(r), clientIP(r)); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"deleted": id})

	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
	}
}

func (s *Server) handleUserByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/users/")
	if id == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "missing user id"})
		return
	}
	switch r.Method {
	case http.MethodGet:
		u, ok := s.store.GetUserByID(id)
		if !ok {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
			return
		}
		writeJSON(w, http.StatusOK, u.Sanitize())
	case http.MethodDelete:
		if err := s.store.DeleteUser(id, s.resolveActor(r), clientIP(r)); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
	}
}

func (s *Server) handleRoles(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		roles := s.store.ListRoles()
		writeJSON(w, http.StatusOK, map[string]any{
			"items": roles,
			"total": len(roles),
		})
	case http.MethodPost:
		var role policy.Role
		if err := json.NewDecoder(r.Body).Decode(&role); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json payload"})
			return
		}
		created, err := s.store.CreateRole(role, s.resolveActor(r), clientIP(r))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, created)
	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if err := s.store.DeleteRole(id, s.resolveActor(r), clientIP(r)); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
	}
}

func (s *Server) handleRoleByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/roles/")
	if r.Method == http.MethodDelete {
		if err := s.store.DeleteRole(id, s.resolveActor(r), clientIP(r)); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
		return
	}
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
}

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		policies := s.store.ListPolicies()
		effect := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("effect")))
		if effect != "" && effect != "all" {
			filtered := make([]policy.Policy, 0, len(policies))
			for _, p := range policies {
				if strings.EqualFold(p.Effect, effect) {
					filtered = append(filtered, p)
				}
			}
			policies = filtered
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"items": policies,
			"total": len(policies),
		})
	case http.MethodPost:
		var pol policy.Policy
		if err := json.NewDecoder(r.Body).Decode(&pol); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json payload"})
			return
		}
		if !pol.Enabled {
			pol.Enabled = true
		}
		created, err := s.store.CreatePolicy(pol, s.resolveActor(r), clientIP(r))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, created)
	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if err := s.store.DeletePolicy(id, s.resolveActor(r), clientIP(r)); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
	}
}

func (s *Server) handlePolicyByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/policies/")
	if id == "evaluate" {
		s.handlePolicyEvaluate(w, r)
		return
	}
	if r.Method == http.MethodDelete {
		if err := s.store.DeletePolicy(id, s.resolveActor(r), clientIP(r)); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
		return
	}
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
}

func (s *Server) handlePolicyEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	var req policy.EvalRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid evaluation request payload"})
		return
	}

	// If Username or SubjectID is provided, enrich missing Roles/Department/MFA from stored User
	if req.Username != "" {
		if u, ok := s.store.GetUserByUsername(req.Username); ok {
			if req.SubjectID == "" {
				req.SubjectID = u.ID
			}
			if len(req.Roles) == 0 {
				req.Roles = u.Roles
			}
			if req.Department == "" {
				req.Department = u.Department
			}
		}
	} else if req.SubjectID != "" {
		if u, ok := s.store.GetUserByID(req.SubjectID); ok {
			req.Username = u.Username
			if len(req.Roles) == 0 {
				req.Roles = u.Roles
			}
			if req.Department == "" {
				req.Department = u.Department
			}
		}
	}
	if req.IPAddress == "" {
		req.IPAddress = clientIP(r)
	}

	roles := s.store.ListRoles()
	policies := s.store.ListPolicies()
	result := policy.Evaluate(req, roles, policies)

	s.policyEvalsTotal.Add(1)
	if result.Allowed {
		s.policyEvalsAllow.Add(1)
	} else {
		s.policyEvalsDeny.Add(1)
	}

	actor := firstNonEmpty(req.Username, req.SubjectID, s.resolveActor(r))
	severity := "info"
	if !result.Allowed {
		severity = "warn"
	}
	s.store.AppendAuditLog(
		actor,
		"policy.evaluate:"+req.Action,
		req.Resource,
		severity,
		result.Decision,
		req.IPAddress,
		result.Reason,
	)

	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleClients(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		clients := s.store.ListOAuthClients()
		writeJSON(w, http.StatusOK, map[string]any{
			"items": clients,
			"total": len(clients),
		})
	case http.MethodPost:
		var req struct {
			ClientID     string   `json:"client_id"`
			ClientSecret string   `json:"client_secret"`
			Name         string   `json:"name"`
			Description  string   `json:"description"`
			GrantTypes   []string `json:"grant_types"`
			Scopes       []string `json:"scopes"`
			RedirectURIs []string `json:"redirect_uris"`
			DefaultRoles []string `json:"default_roles"`
			SigningAlg   string   `json:"signing_alg"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json payload"})
			return
		}
		created, rawSecret, err := s.store.CreateOAuthClient(store.OAuthClient{
			ClientID:     req.ClientID,
			Name:         req.Name,
			Description:  req.Description,
			GrantTypes:   req.GrantTypes,
			Scopes:       req.Scopes,
			RedirectURIs: req.RedirectURIs,
			DefaultRoles: req.DefaultRoles,
			SigningAlg:   req.SigningAlg,
		}, req.ClientSecret, s.resolveActor(r), clientIP(r))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"client":        created,
			"client_secret": rawSecret,
		})
	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if err := s.store.DeleteOAuthClient(id, s.resolveActor(r), clientIP(r)); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
	}
}

func (s *Server) handleClientByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/clients/")
	if r.Method == http.MethodDelete {
		if err := s.store.DeleteOAuthClient(id, s.resolveActor(r), clientIP(r)); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
		return
	}
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
}

func (s *Server) handleAPIKeys(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		keys := s.store.ListAPIKeys()
		writeJSON(w, http.StatusOK, map[string]any{
			"items": keys,
			"total": len(keys),
		})
	case http.MethodPost:
		var req struct {
			Name         string   `json:"name"`
			OwnerUserID  string   `json:"owner_user_id"`
			Scopes       []string `json:"scopes"`
			Roles        []string `json:"roles"`
			RateLimitRPS int      `json:"rate_limit_rps"`
			ExpiresAt    string   `json:"expires_at"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid json payload"})
			return
		}
		created, rawKey, err := s.store.CreateAPIKey(store.APIKey{
			Name:         req.Name,
			OwnerUserID:  req.OwnerUserID,
			Scopes:       req.Scopes,
			Roles:        req.Roles,
			RateLimitRPS: req.RateLimitRPS,
			ExpiresAt:    req.ExpiresAt,
		}, "", s.resolveActor(r), clientIP(r))
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"api_key": created,
			"raw_key": rawKey,
		})
	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if err := s.store.DeleteAPIKey(id, s.resolveActor(r), clientIP(r)); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
	default:
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
	}
}

func (s *Server) handleAPIKeyByID(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/api/v1/apikeys/")
	if r.Method == http.MethodDelete {
		if err := s.store.DeleteAPIKey(id, s.resolveActor(r), clientIP(r)); err != nil {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"deleted": id})
		return
	}
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
}

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	q := r.URL.Query().Get("q")
	severity := r.URL.Query().Get("severity")
	outcome := r.URL.Query().Get("outcome")
	entries := s.store.ListAuditLogs(q, severity, outcome, 250)
	validChain, verifiedCount, brokenAt := s.store.VerifyAuditChain()

	writeJSON(w, http.StatusOK, map[string]any{
		"items":                entries,
		"total":                len(entries),
		"chain_integrity":      validChain,
		"chain_verified_count": verifiedCount,
		"chain_broken_at":      brokenAt,
	})
}

func (s *Server) handleBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	raw, err := s.store.ExportBackup()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="aetheriam-backup.json"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(raw)
}

func (s *Server) handleRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "failed to read restore body"})
		return
	}
	if err := s.store.RestoreBackup(raw, s.resolveActor(r), clientIP(r)); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "restored",
		"stats":   s.store.Stats(),
		"message": "Transactional snapshot restored and indexes rebuilt",
	})
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(payload)
}

func clientIP(r *http.Request) string {
	if xff := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); xff != "" {
		parts := strings.Split(xff, ",")
		return strings.TrimSpace(parts[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return host
	}
	if r.RemoteAddr != "" {
		return r.RemoteAddr
	}
	return "127.0.0.1"
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
