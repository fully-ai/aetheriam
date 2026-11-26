package crypto

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordHashingAndVerification(t *testing.T) {
	hash, err := HashPassword("CorrectHorseBatteryStaple!42")
	if err != nil {
		t.Fatalf("HashPassword failed: %v", err)
	}
	if !strings.HasPrefix(hash, "$pbkdf2-sha256$i=60000$") {
		t.Fatalf("unexpected hash format: %s", hash)
	}
	if !VerifyPassword("CorrectHorseBatteryStaple!42", hash) {
		t.Fatalf("expected VerifyPassword to succeed for matching password")
	}
	if VerifyPassword("WrongPassword!42", hash) {
		t.Fatalf("expected VerifyPassword to reject wrong password")
	}
	if VerifyPassword("CorrectHorseBatteryStaple!42", "invalid-hash") {
		t.Fatalf("expected VerifyPassword to reject malformed hash")
	}
}

func TestJWTSigningVerificationAndJWKS(t *testing.T) {
	km, err := NewKeyManager(t.TempDir(), "https://iam.aether.local", "test-hmac-secret-123")
	if err != nil {
		t.Fatalf("NewKeyManager failed: %v", err)
	}

	claims := Claims{
		Subject:    "usr_admin",
		Audience:   "aether-console",
		Scope:      "openid profile iam:admin",
		Roles:      []string{"super_admin", "secops"},
		Department: "Security",
		Email:      "admin@aether.local",
		ExpiresAt:  time.Now().UTC().Add(10 * time.Minute).Unix(),
	}

	// Test RS256
	rsToken, err := km.SignJWT(claims, "RS256")
	if err != nil {
		t.Fatalf("SignJWT RS256 failed: %v", err)
	}
	parsedRS, alg, err := km.VerifyJWT(rsToken)
	if err != nil {
		t.Fatalf("VerifyJWT RS256 failed: %v", err)
	}
	if alg != "RS256" || parsedRS.Subject != "usr_admin" || len(parsedRS.Roles) != 2 {
		t.Fatalf("unexpected parsed RS256 claims: %+v (alg=%s)", parsedRS, alg)
	}

	// Test HS256
	hsToken, err := km.SignJWT(claims, "HS256")
	if err != nil {
		t.Fatalf("SignJWT HS256 failed: %v", err)
	}
	parsedHS, alg, err := km.VerifyJWT(hsToken)
	if err != nil {
		t.Fatalf("VerifyJWT HS256 failed: %v", err)
	}
	if alg != "HS256" || parsedHS.Department != "Security" {
		t.Fatalf("unexpected parsed HS256 claims: %+v (alg=%s)", parsedHS, alg)
	}

	// Test Tampered Signature rejection
	tampered := rsToken[:len(rsToken)-4] + "AAAA"
	if _, _, err := km.VerifyJWT(tampered); err == nil {
		t.Fatalf("expected tampered JWT to be rejected")
	}

	// Test Expired Token rejection
	expiredClaims := claims
	expiredClaims.ExpiresAt = time.Now().UTC().Add(-10 * time.Second).Unix()
	expiredToken, err := km.SignJWT(expiredClaims, "RS256")
	if err != nil {
		t.Fatalf("SignJWT expired failed: %v", err)
	}
	if _, _, err := km.VerifyJWT(expiredToken); err == nil {
		t.Fatalf("expected expired JWT to be rejected")
	}

	// Test JWKS & OIDC Discovery
	jwks := km.JWKS()
	if len(jwks.Keys) != 1 || jwks.Keys[0].Kty != "RSA" || jwks.Keys[0].Kid != km.KeyID() {
		t.Fatalf("unexpected JWKS output: %+v", jwks)
	}
	oidc := km.OIDCDiscovery("https://iam.aether.local")
	if oidc["jwks_uri"] != "https://iam.aether.local/.well-known/jwks.json" {
		t.Fatalf("unexpected oidc jwks_uri: %v", oidc["jwks_uri"])
	}
}

func TestAPIKeyGenerationAndAuditHashChain(t *testing.T) {
	raw, prefix, hash, err := GenerateAPIKey()
	if err != nil {
		t.Fatalf("GenerateAPIKey failed: %v", err)
	}
	if !strings.HasPrefix(raw, APIKeyPrefix) || !strings.HasPrefix(prefix, APIKeyPrefix) {
		t.Fatalf("expected API key prefix %s, got raw=%s prefix=%s", APIKeyPrefix, raw, prefix)
	}
	if HashAPIKey(raw) != hash {
		t.Fatalf("HashAPIKey mismatch")
	}

	h1 := ComputeAuditHash("GENESIS", "2026-11-26T10:00:00Z", "admin", "user.create", "usr_1", "ALLOW", "created")
	h2 := ComputeAuditHash(h1, "2026-11-26T10:01:00Z", "admin", "policy.evaluate", "pol_1", "ALLOW", "matched")
	if h1 == h2 || len(h1) != 64 || len(h2) != 64 {
		t.Fatalf("unexpected audit hash chain digests: h1=%s h2=%s", h1, h2)
	}
}
