package crypto

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

const (
	pbkdf2Iterations = 60000
	pbkdf2SaltBytes  = 16
	pbkdf2KeyBytes   = 32
	APIKeyPrefix     = "aiam_"
)

// HashPassword derives a salted PBKDF2-HMAC-SHA256 hash formatted as:
// $pbkdf2-sha256$i=60000$<base64-salt>$<base64-dk>
func HashPassword(password string) (string, error) {
	if strings.TrimSpace(password) == "" {
		return "", errors.New("password cannot be empty")
	}
	salt := make([]byte, pbkdf2SaltBytes)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate salt: %w", err)
	}
	dk := pbkdf2SHA256([]byte(password), salt, pbkdf2Iterations, pbkdf2KeyBytes)
	return fmt.Sprintf(
		"$pbkdf2-sha256$i=%d$%s$%s",
		pbkdf2Iterations,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(dk),
	), nil
}

// VerifyPassword validates a plaintext password against an encoded PBKDF2-HMAC-SHA256 hash in constant time.
func VerifyPassword(password, encodedHash string) bool {
	parts := strings.Split(encodedHash, "$")
	if len(parts) != 5 || parts[1] != "pbkdf2-sha256" {
		return false
	}
	iterPart := strings.TrimPrefix(parts[2], "i=")
	iterations, err := strconv.Atoi(iterPart)
	if err != nil || iterations < 1000 {
		return false
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || len(salt) == 0 {
		return false
	}
	expectedDK, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(expectedDK) == 0 {
		return false
	}
	actualDK := pbkdf2SHA256([]byte(password), salt, iterations, len(expectedDK))
	return subtle.ConstantTimeCompare(actualDK, expectedDK) == 1
}

// pbkdf2SHA256 implements RFC 2898 / PKCS #5 v2.0 PBKDF2 using HMAC-SHA256 with zero external dependencies.
func pbkdf2SHA256(password, salt []byte, iter, keyLen int) []byte {
	prf := hmac.New(sha256.New, password)
	hashLen := prf.Size()
	numBlocks := (keyLen + hashLen - 1) / hashLen

	var buf [4]byte
	dk := make([]byte, 0, numBlocks*hashLen)
	u := make([]byte, hashLen)

	for block := 1; block <= numBlocks; block++ {
		prf.Reset()
		prf.Write(salt)
		buf[0] = byte(block >> 24)
		buf[1] = byte(block >> 16)
		buf[2] = byte(block >> 8)
		buf[3] = byte(block)
		prf.Write(buf[:4])
		dk = prf.Sum(dk)
		T := dk[len(dk)-hashLen:]
		copy(u, T)

		for n := 2; n <= iter; n++ {
			prf.Reset()
			prf.Write(u)
			u = u[:0]
			u = prf.Sum(u)
			for i := 0; i < hashLen; i++ {
				T[i] ^= u[i]
			}
		}
	}
	return dk[:keyLen]
}

// GenerateAPIKey creates a new random API key with prefix "aiam_", a display prefix, and a SHA-256 hex fingerprint.
func GenerateAPIKey() (rawKey string, displayPrefix string, sha256Hex string, err error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", "", "", fmt.Errorf("generate api key entropy: %w", err)
	}
	secretPart := hex.EncodeToString(b)
	rawKey = APIKeyPrefix + secretPart
	displayPrefix = rawKey[:13] + "..."
	sha256Hex = HashAPIKey(rawKey)
	return rawKey, displayPrefix, sha256Hex, nil
}

// HashAPIKey computes the hex-encoded SHA-256 digest of an API key or client secret.
func HashAPIKey(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

// GenerateClientSecret generates an OAuth2 client secret with prefix "acs_".
func GenerateClientSecret() (string, error) {
	b := make([]byte, 20)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "acs_" + hex.EncodeToString(b), nil
}

// ComputeAuditHash produces a deterministic tamper-evident SHA-256 hash linked to prevHash.
func ComputeAuditHash(prevHash, timestamp, actor, action, resource, outcome, details string) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write([]byte("|"))
	h.Write([]byte(timestamp))
	h.Write([]byte("|"))
	h.Write([]byte(actor))
	h.Write([]byte("|"))
	h.Write([]byte(action))
	h.Write([]byte("|"))
	h.Write([]byte(resource))
	h.Write([]byte("|"))
	h.Write([]byte(outcome))
	h.Write([]byte("|"))
	h.Write([]byte(details))
	return hex.EncodeToString(h.Sum(nil))
}

// Claims represents standard OIDC/OAuth2 JWT claims plus AetherIAM RBAC/ABAC identity metadata.
type Claims struct {
	Issuer     string   `json:"iss"`
	Subject    string   `json:"sub"`
	Audience   string   `json:"aud"`
	ExpiresAt  int64    `json:"exp"`
	IssuedAt   int64    `json:"iat"`
	JWTID      string   `json:"jti"`
	Scope      string   `json:"scope,omitempty"`
	Roles      []string `json:"roles,omitempty"`
	Department string   `json:"department,omitempty"`
	Email      string   `json:"email,omitempty"`
	Username   string   `json:"username,omitempty"`
	ClientID   string   `json:"client_id,omitempty"`
	GrantType  string   `json:"grant_type,omitempty"`
	TokenType  string   `json:"token_type,omitempty"`
	MFA        bool     `json:"mfa,omitempty"`
}

// JWK represents an RFC 7517 JSON Web Key entry.
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKSet represents an RFC 7517 JSON Web Key Set.
type JWKSet struct {
	Keys []JWK `json:"keys"`
}

// KeyManager holds the active RSA-2048 keypair and HMAC-SHA256 shared secret for signing & verifying tokens.
type KeyManager struct {
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	keyID      string
	hmacSecret []byte
	issuer     string
}

// NewKeyManager loads or generates an RSA-2048 signing keypair in dataDir (if non-empty) and initializes HMAC secret.
func NewKeyManager(dataDir, issuer, hmacSecret string) (*KeyManager, error) {
	if issuer == "" {
		issuer = "http://localhost:8080"
	}
	if hmacSecret == "" {
		hmacSecret = "aetheriam-default-hmac-sha256-signing-secret-key"
	}

	var priv *rsa.PrivateKey
	if dataDir != "" {
		if err := os.MkdirAll(dataDir, 0o755); err != nil {
			return nil, fmt.Errorf("create key dir: %w", err)
		}
		keyPath := filepath.Join(dataDir, "jwt_rsa_key.pem")
		if pemBytes, err := os.ReadFile(keyPath); err == nil {
			block, _ := pem.Decode(pemBytes)
			if block != nil {
				if parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
					priv = parsed
				}
			}
		}
		if priv == nil {
			generated, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				return nil, fmt.Errorf("generate rsa key: %w", err)
			}
			priv = generated
			pemBytes := pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(priv),
			})
			_ = os.WriteFile(keyPath, pemBytes, 0o600)
		}
	} else {
		generated, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("generate ephemeral rsa key: %w", err)
		}
		priv = generated
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	kidHash := sha256.Sum256(pubDER)
	kid := "aether-rs256-" + hex.EncodeToString(kidHash[:6])

	return &KeyManager{
		privateKey: priv,
		publicKey:  &priv.PublicKey,
		keyID:      kid,
		hmacSecret: []byte(hmacSecret),
		issuer:     strings.TrimRight(issuer, "/"),
	}, nil
}

// KeyID returns the active RSA key identifier (kid).
func (km *KeyManager) KeyID() string {
	return km.keyID
}

// Issuer returns the configured OIDC issuer URL.
func (km *KeyManager) Issuer() string {
	return km.issuer
}

// SignJWT signs the provided Claims using either "RS256" (default) or "HS256".
func (km *KeyManager) SignJWT(claims Claims, alg string) (string, error) {
	if alg == "" {
		alg = "RS256"
	}
	alg = strings.ToUpper(alg)
	if alg != "RS256" && alg != "HS256" {
		return "", fmt.Errorf("unsupported jwt signing algorithm: %s", alg)
	}

	now := time.Now().UTC().Unix()
	if claims.Issuer == "" {
		claims.Issuer = km.issuer
	}
	if claims.IssuedAt == 0 {
		claims.IssuedAt = now
	}
	if claims.ExpiresAt == 0 {
		claims.ExpiresAt = now + 3600
	}
	if claims.JWTID == "" {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		claims.JWTID = "jti_" + hex.EncodeToString(b)
	}

	header := map[string]string{
		"alg": alg,
		"typ": "JWT",
		"kid": km.keyID,
	}
	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	enc := base64.RawURLEncoding
	signingInput := enc.EncodeToString(headerJSON) + "." + enc.EncodeToString(claimsJSON)

	var sig []byte
	switch alg {
	case "RS256":
		digest := sha256.Sum256([]byte(signingInput))
		sig, err = rsa.SignPKCS1v15(rand.Reader, km.privateKey, crypto.SHA256, digest[:])
		if err != nil {
			return "", fmt.Errorf("rsa sign jwt: %w", err)
		}
	case "HS256":
		mac := hmac.New(sha256.New, km.hmacSecret)
		mac.Write([]byte(signingInput))
		sig = mac.Sum(nil)
	}

	return signingInput + "." + enc.EncodeToString(sig), nil
}

// VerifyJWT parses and validates a signed JWT token (RS256 or HS256) and checks expiration.
func (km *KeyManager) VerifyJWT(tokenStr string) (*Claims, string, error) {
	parts := strings.Split(strings.TrimSpace(tokenStr), ".")
	if len(parts) != 3 {
		return nil, "", errors.New("malformed jwt: expected 3 dot-separated segments")
	}

	enc := base64.RawURLEncoding
	headerBytes, err := enc.DecodeString(parts[0])
	if err != nil {
		return nil, "", fmt.Errorf("invalid jwt header encoding: %w", err)
	}
	var header struct {
		Alg string `json:"alg"`
		Typ string `json:"typ"`
		Kid string `json:"kid"`
	}
	if err := json.Unmarshal(headerBytes, &header); err != nil {
		return nil, "", fmt.Errorf("invalid jwt header json: %w", err)
	}

	sig, err := enc.DecodeString(parts[2])
	if err != nil {
		return nil, "", fmt.Errorf("invalid jwt signature encoding: %w", err)
	}

	signingInput := parts[0] + "." + parts[1]
	switch header.Alg {
	case "RS256":
		digest := sha256.Sum256([]byte(signingInput))
		if err := rsa.VerifyPKCS1v15(km.publicKey, crypto.SHA256, digest[:], sig); err != nil {
			return nil, header.Alg, errors.New("invalid RS256 signature")
		}
	case "HS256":
		mac := hmac.New(sha256.New, km.hmacSecret)
		mac.Write([]byte(signingInput))
		expected := mac.Sum(nil)
		if subtle.ConstantTimeCompare(sig, expected) != 1 {
			return nil, header.Alg, errors.New("invalid HS256 signature")
		}
	default:
		return nil, header.Alg, fmt.Errorf("unsupported jwt algorithm: %s", header.Alg)
	}

	claimsBytes, err := enc.DecodeString(parts[1])
	if err != nil {
		return nil, header.Alg, fmt.Errorf("invalid jwt claims encoding: %w", err)
	}
	var claims Claims
	if err := json.Unmarshal(claimsBytes, &claims); err != nil {
		return nil, header.Alg, fmt.Errorf("invalid jwt claims json: %w", err)
	}

	now := time.Now().UTC().Unix()
	if claims.ExpiresAt > 0 && now > claims.ExpiresAt {
		return nil, header.Alg, errors.New("jwt token has expired")
	}
	return &claims, header.Alg, nil
}

// JWKS returns the RFC 7517 JSON Web Key Set for public key discovery.
func (km *KeyManager) JWKS() JWKSet {
	nBytes := km.publicKey.N.Bytes()
	eBytes := big.NewInt(int64(km.publicKey.E)).Bytes()
	enc := base64.RawURLEncoding
	return JWKSet{
		Keys: []JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Alg: "RS256",
				Kid: km.keyID,
				N:   enc.EncodeToString(nBytes),
				E:   enc.EncodeToString(eBytes),
			},
		},
	}
}

// OIDCDiscovery returns the OpenID Connect Discovery 1.0 configuration document.
func (km *KeyManager) OIDCDiscovery(baseURL string) map[string]any {
	iss := strings.TrimRight(baseURL, "/")
	if iss == "" {
		iss = km.issuer
	}
	return map[string]any{
		"issuer":                                iss,
		"authorization_endpoint":                iss + "/api/v1/auth/authorize",
		"token_endpoint":                        iss + "/api/v1/auth/token",
		"token_introspection_endpoint":          iss + "/api/v1/auth/verify",
		"userinfo_endpoint":                     iss + "/api/v1/auth/verify",
		"jwks_uri":                              iss + "/.well-known/jwks.json",
		"response_types_supported":              []string{"token", "id_token", "code"},
		"grant_types_supported":                 []string{"client_credentials", "password", "refresh_token"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256", "HS256"},
		"scopes_supported":                      []string{"openid", "profile", "email", "iam:admin", "iam:read", "iam:write", "policy:evaluate"},
		"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic"},
		"claims_supported":                      []string{"iss", "sub", "aud", "exp", "iat", "jti", "scope", "roles", "department", "email", "username", "mfa"},
	}
}
