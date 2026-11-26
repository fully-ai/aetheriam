package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/fully-ai/aetheriam/internal/crypto"
	"github.com/fully-ai/aetheriam/internal/policy"
	"github.com/fully-ai/aetheriam/internal/store"
)

func setupTestServer(t *testing.T, rps, burst float64) (*Server, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(dir)
	if err != nil {
		t.Fatalf("store.Open failed: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if err := st.SeedDemo(); err != nil {
		t.Fatalf("SeedDemo failed: %v", err)
	}
	km, err := crypto.NewKeyManager(dir, "http://localhost:8080", "test-secret")
	if err != nil {
		t.Fatalf("NewKeyManager failed: %v", err)
	}
	mockWeb := fstest.MapFS{
		"index.html": &fstest.MapFile{Data: []byte("<html><title>AetherIAM Security & Identity Console</title></html>")},
	}
	srv := NewServer(Config{
		Store:          st,
		Keys:           km,
		WebFS:          mockWeb,
		RateLimitRPS:   rps,
		RateLimitBurst: burst,
	})
	return srv, st
}

func TestEndToEndAPIWorkflows(t *testing.T) {
	srv, _ := setupTestServer(t, 500, 500)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	// 1. Healthz & Metrics & Web UI Serving
	resp, err := http.Get(ts.URL + "/healthz")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /healthz failed: status=%v err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	resp, err = http.Get(ts.URL + "/metrics")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /metrics failed: %v", err)
	}
	_ = resp.Body.Close()

	resp, err = http.Get(ts.URL + "/")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET / web console failed: %v", err)
	}
	_ = resp.Body.Close()

	// 2. OIDC Discovery & JWKS
	resp, err = http.Get(ts.URL + "/.well-known/openid-configuration")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("OIDC discovery failed: %v", err)
	}
	_ = resp.Body.Close()

	resp, err = http.Get(ts.URL + "/.well-known/jwks.json")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("JWKS discovery failed: %v", err)
	}
	_ = resp.Body.Close()

	// 3. OAuth2 Password Grant & Token Verification
	tokenReq := map[string]any{
		"grant_type": "password",
		"username":   "elena.vance",
		"password":   "ElenaSRE!2026",
	}
	bodyBytes, _ := json.Marshal(tokenReq)
	resp, err = http.Post(ts.URL+"/api/v1/auth/token", "application/json", bytes.NewReader(bodyBytes))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/v1/auth/token password grant failed: status=%d err=%v", resp.StatusCode, err)
	}
	var tokenResp struct {
		AccessToken string `json:"access_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&tokenResp)
	_ = resp.Body.Close()
	if tokenResp.AccessToken == "" {
		t.Fatalf("expected non-empty access_token")
	}

	verifyPayload, _ := json.Marshal(map[string]string{"token": tokenResp.AccessToken})
	resp, err = http.Post(ts.URL+"/api/v1/auth/verify", "application/json", bytes.NewReader(verifyPayload))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/v1/auth/verify failed: status=%d err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	// 4. OAuth2 Client Credentials Grant
	ccReq, _ := json.Marshal(map[string]string{
		"grant_type":    "client_credentials",
		"client_id":     "aether-console-client",
		"client_secret": "acs_demo_console_secret_2026",
	})
	resp, err = http.Post(ts.URL+"/api/v1/auth/token", "application/json", bytes.NewReader(ccReq))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("client_credentials grant failed: status=%d err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	// 5. Live Policy Simulator (/api/v1/policies/evaluate)
	evalReq, _ := json.Marshal(policy.EvalRequest{
		Username:    "elena.vance",
		Roles:       []string{"sre_lead"},
		Department:  "Platform",
		MFAVerified: true,
		IPAddress:   "10.12.0.5",
		Environment: "production",
		Action:      "infra:deploy",
		Resource:    "arn:aether:prod:cluster-eu",
	})
	resp, err = http.Post(ts.URL+"/api/v1/policies/evaluate", "application/json", bytes.NewReader(evalReq))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("policy evaluate failed: %v", err)
	}
	var evalRes policy.EvalResult
	_ = json.NewDecoder(resp.Body).Decode(&evalRes)
	_ = resp.Body.Close()
	if !evalRes.Allowed || evalRes.Decision != "ALLOW" {
		t.Fatalf("expected policy simulator to ALLOW SRE production deployment, got: %+v", evalRes)
	}

	// 6. Create User, API Key, Verify Hash-Chained Audit Log, Backup & Restore
	newUserReq, _ := json.Marshal(map[string]any{
		"username":   "devon.miles",
		"email":      "devon@aetheriam.io",
		"full_name":  "Devon Miles",
		"password":   "DevonPass!2026",
		"department": "Engineering",
		"mfa_enabled": true,
		"roles":      []string{"developer"},
	})
	resp, err = http.Post(ts.URL+"/api/v1/users", "application/json", bytes.NewReader(newUserReq))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/v1/users failed: status=%d err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()

	newKeyReq, _ := json.Marshal(map[string]any{
		"name":   "Test Scanner Key",
		"scopes": []string{"iam:read"},
		"roles":  []string{"security_auditor"},
	})
	resp, err = http.Post(ts.URL+"/api/v1/apikeys", "application/json", bytes.NewReader(newKeyReq))
	if err != nil || resp.StatusCode != http.StatusCreated {
		t.Fatalf("POST /api/v1/apikeys failed: status=%d err=%v", resp.StatusCode, err)
	}
	var keyResp struct {
		RawKey string `json:"raw_key"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&keyResp)
	_ = resp.Body.Close()
	if !strings.HasPrefix(keyResp.RawKey, "aiam_") {
		t.Fatalf("expected raw_key to start with aiam_, got %s", keyResp.RawKey)
	}

	// Verify Audit Chain
	resp, err = http.Get(ts.URL + "/api/v1/audit")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/audit failed: %v", err)
	}
	var auditResp struct {
		ChainIntegrity     bool `json:"chain_integrity"`
		ChainVerifiedCount int  `json:"chain_verified_count"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&auditResp)
	_ = resp.Body.Close()
	if !auditResp.ChainIntegrity || auditResp.ChainVerifiedCount < 5 {
		t.Fatalf("expected intact audit hash chain, got: %+v", auditResp)
	}

	// Backup & Restore round-trip
	resp, err = http.Get(ts.URL + "/api/v1/admin/backup")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /api/v1/admin/backup failed: %v", err)
	}
	var backupBuf bytes.Buffer
	_, _ = backupBuf.ReadFrom(resp.Body)
	_ = resp.Body.Close()

	resp, err = http.Post(ts.URL+"/api/v1/admin/restore", "application/json", bytes.NewReader(backupBuf.Bytes()))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("POST /api/v1/admin/restore failed: status=%d err=%v", resp.StatusCode, err)
	}
	_ = resp.Body.Close()
}

func TestRateLimitingMiddleware(t *testing.T) {
	srv, _ := setupTestServer(t, 1, 2) // burst of 2 requests
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	got429 := false
	for i := 0; i < 6; i++ {
		resp, err := http.Get(ts.URL + "/api/v1/users")
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode == http.StatusTooManyRequests {
			got429 = true
			break
		}
	}
	if !got429 {
		t.Fatalf("expected rate limiter to return HTTP 429 Too Many Requests when burst exceeded")
	}
}
