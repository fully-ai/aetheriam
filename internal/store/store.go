package store

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/fully-ai/aetheriam/internal/crypto"
	"github.com/fully-ai/aetheriam/internal/policy"
)

// MigrationRecord tracks schema migrations applied to the persistent WAL store.
type MigrationRecord struct {
	Version   int    `json:"version"`
	Name      string `json:"name"`
	AppliedAt string `json:"applied_at"`
}

// User represents an IAM identity with salted PBKDF2 hash, department, MFA state, and assigned RBAC roles.
type User struct {
	ID           string   `json:"id"`
	Username     string   `json:"username"`
	Email        string   `json:"email"`
	FullName     string   `json:"full_name"`
	PasswordHash string   `json:"password_hash,omitempty"`
	Department   string   `json:"department"`
	Status       string   `json:"status"` // "active", "suspended", "locked"
	MFAEnabled   bool     `json:"mfa_enabled"`
	Roles        []string `json:"roles"`
	LastLoginAt  string   `json:"last_login_at,omitempty"`
	CreatedAt    string   `json:"created_at"`
}

// Sanitize returns a copy of User with PasswordHash stripped for public API responses.
func (u User) Sanitize() User {
	u.PasswordHash = ""
	return u
}

// OAuthClient represents a registered OAuth2/OIDC client application.
type OAuthClient struct {
	ID                  string   `json:"id"`
	ClientID            string   `json:"client_id"`
	ClientSecretHash    string   `json:"client_secret_hash,omitempty"`
	ClientSecretPreview string   `json:"client_secret_preview"`
	Name                string   `json:"name"`
	Description         string   `json:"description"`
	GrantTypes          []string `json:"grant_types"`
	Scopes              []string `json:"scopes"`
	RedirectURIs        []string `json:"redirect_uris"`
	DefaultRoles        []string `json:"default_roles"`
	SigningAlg          string   `json:"signing_alg"` // "RS256" or "HS256"
	Active              bool     `json:"active"`
	CreatedAt           string   `json:"created_at"`
}

// Sanitize strips ClientSecretHash for API listings.
func (c OAuthClient) Sanitize() OAuthClient {
	c.ClientSecretHash = ""
	return c
}

// APIKey represents a scoped programmatic API token prefixed with "aiam_".
type APIKey struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	OwnerUserID  string   `json:"owner_user_id"`
	KeyPrefix    string   `json:"key_prefix"`
	KeyHash      string   `json:"key_hash,omitempty"`
	Scopes       []string `json:"scopes"`
	Roles        []string `json:"roles"`
	RateLimitRPS int      `json:"rate_limit_rps"`
	ExpiresAt    string   `json:"expires_at,omitempty"`
	LastUsedAt   string   `json:"last_used_at,omitempty"`
	Active       bool     `json:"active"`
	CreatedAt    string   `json:"created_at"`
}

// Sanitize hides KeyHash for public API responses.
func (k APIKey) Sanitize() APIKey {
	k.KeyHash = ""
	return k
}

// Session tracks issued OAuth2/OIDC tokens.
type Session struct {
	ID        string `json:"id"`
	SubjectID string `json:"subject_id"`
	ClientID  string `json:"client_id"`
	GrantType string `json:"grant_type"`
	Scope     string `json:"scope"`
	JWTID     string `json:"jti"`
	SigningAlg string `json:"signing_alg"`
	IPAddress string `json:"ip_address"`
	ExpiresAt string `json:"expires_at"`
	CreatedAt string `json:"created_at"`
}

// AuditEntry represents an immutable, SHA-256 hash-chained governance event.
type AuditEntry struct {
	ID        string `json:"id"`
	Sequence  int64  `json:"sequence"`
	Timestamp string `json:"timestamp"`
	Actor     string `json:"actor"`
	Action    string `json:"action"`
	Resource  string `json:"resource"`
	Severity  string `json:"severity"` // "info", "warn", "critical"
	Outcome   string `json:"outcome"`  // "ALLOW", "DENY", "SUCCESS", "FAILURE"
	IPAddress string `json:"ip_address"`
	Details   string `json:"details"`
	PrevHash  string `json:"prev_hash"`
	Hash      string `json:"hash"`
}

// Snapshot represents the complete serializable database state for atomic persistence and backup/restore.
type Snapshot struct {
	SchemaVersion int                       `json:"schema_version"`
	SnapshotAt    string                    `json:"snapshot_at"`
	WALSequence   int64                     `json:"wal_sequence"`
	Migrations    []MigrationRecord         `json:"migrations"`
	Users         map[string]User           `json:"users"`
	Roles         map[string]policy.Role    `json:"roles"`
	Policies      map[string]policy.Policy  `json:"policies"`
	OAuthClients  map[string]OAuthClient    `json:"oauth_clients"`
	APIKeys       map[string]APIKey         `json:"api_keys"`
	Sessions      map[string]Session        `json:"sessions"`
	AuditLogs     []AuditEntry              `json:"audit_logs"`
	Checksum      string                    `json:"checksum,omitempty"`
}

type walRecord struct {
	Sequence  int64  `json:"seq"`
	Timestamp string `json:"ts"`
	Operation string `json:"op"`
	Entity    string `json:"entity"`
	EntityID  string `json:"entity_id"`
}

// Store implements a zero-CGo transactional WAL + atomic snapshot storage engine with in-memory indexes.
type Store struct {
	mu           sync.RWMutex
	dataDir      string
	snapshotPath string
	walPath      *os.File
	state        Snapshot

	// Secondary indexes for O(1) lookup
	userByUsername   map[string]string
	userByEmail      map[string]string
	roleByName       map[string]string
	clientByClientID map[string]string
	apiKeyByHash     map[string]string
}

// Open initializes or recovers the persistent WAL store in dataDir.
func Open(dataDir string) (*Store, error) {
	if err := os.MkdirAll(dataDir, 0o755); err != nil {
		return nil, fmt.Errorf("create store directory: %w", err)
	}
	snapPath := filepath.Join(dataDir, "snapshot.json")
	walFilePath := filepath.Join(dataDir, "wal.log")

	walFile, err := os.OpenFile(walFilePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return nil, fmt.Errorf("open wal file: %w", err)
	}

	s := &Store{
		dataDir:      dataDir,
		snapshotPath: snapPath,
		walPath:      walFile,
		state: Snapshot{
			SchemaVersion: 1,
			Migrations:    []MigrationRecord{},
			Users:         make(map[string]User),
			Roles:         make(map[string]policy.Role),
			Policies:      make(map[string]policy.Policy),
			OAuthClients:  make(map[string]OAuthClient),
			APIKeys:       make(map[string]APIKey),
			Sessions:      make(map[string]Session),
			AuditLogs:     []AuditEntry{},
		},
	}

	if raw, err := os.ReadFile(snapPath); err == nil && len(raw) > 0 {
		var loaded Snapshot
		if err := json.Unmarshal(raw, &loaded); err != nil {
			_ = walFile.Close()
			return nil, fmt.Errorf("corrupt snapshot.json: %w", err)
		}
		s.ensureMaps(&loaded)
		s.state = loaded
	}

	s.applyMigrationsLocked()
	s.rebuildIndexesLocked()
	if err := s.persistLocked("store.init", "system", "init"); err != nil {
		_ = walFile.Close()
		return nil, err
	}
	return s, nil
}

// Close flushes and closes the underlying WAL file handle.
func (s *Store) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.walPath != nil {
		return s.walPath.Close()
	}
	return nil
}

func (s *Store) ensureMaps(snap *Snapshot) {
	if snap.Users == nil {
		snap.Users = make(map[string]User)
	}
	if snap.Roles == nil {
		snap.Roles = make(map[string]policy.Role)
	}
	if snap.Policies == nil {
		snap.Policies = make(map[string]policy.Policy)
	}
	if snap.OAuthClients == nil {
		snap.OAuthClients = make(map[string]OAuthClient)
	}
	if snap.APIKeys == nil {
		snap.APIKeys = make(map[string]APIKey)
	}
	if snap.Sessions == nil {
		snap.Sessions = make(map[string]Session)
	}
	if snap.AuditLogs == nil {
		snap.AuditLogs = []AuditEntry{}
	}
}

func (s *Store) applyMigrationsLocked() {
	applied := make(map[int]bool, len(s.state.Migrations))
	for _, m := range s.state.Migrations {
		applied[m.Version] = true
	}
	migrations := []struct {
		version int
		name    string
	}{
		{1, "001_init_core_identity_collections"},
		{2, "002_add_abac_policy_conditions_and_indexes"},
		{3, "003_add_sha256_hash_chained_audit_ledger"},
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, m := range migrations {
		if !applied[m.version] {
			s.state.Migrations = append(s.state.Migrations, MigrationRecord{
				Version:   m.version,
				Name:      m.name,
				AppliedAt: now,
			})
			s.state.SchemaVersion = m.version
		}
	}
}

func (s *Store) rebuildIndexesLocked() {
	s.userByUsername = make(map[string]string, len(s.state.Users))
	s.userByEmail = make(map[string]string, len(s.state.Users))
	for id, u := range s.state.Users {
		s.userByUsername[strings.ToLower(u.Username)] = id
		if u.Email != "" {
			s.userByEmail[strings.ToLower(u.Email)] = id
		}
	}

	s.roleByName = make(map[string]string, len(s.state.Roles))
	for id, r := range s.state.Roles {
		s.roleByName[strings.ToLower(r.Name)] = id
	}

	s.clientByClientID = make(map[string]string, len(s.state.OAuthClients))
	for id, c := range s.state.OAuthClients {
		s.clientByClientID[c.ClientID] = id
	}

	s.apiKeyByHash = make(map[string]string, len(s.state.APIKeys))
	for id, k := range s.state.APIKeys {
		if k.KeyHash != "" {
			s.apiKeyByHash[k.KeyHash] = id
		}
	}
}

func (s *Store) persistLocked(op, entity, entityID string) error {
	now := time.Now().UTC().Format(time.RFC3339)
	s.state.WALSequence++
	s.state.SnapshotAt = now

	if s.walPath != nil {
		rec := walRecord{
			Sequence:  s.state.WALSequence,
			Timestamp: now,
			Operation: op,
			Entity:    entity,
			EntityID:  entityID,
		}
		if line, err := json.Marshal(rec); err == nil {
			_, _ = s.walPath.Write(append(line, '\n'))
		}
	}

	s.state.Checksum = ""
	raw, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal snapshot: %w", err)
	}
	tmpPath := s.snapshotPath + ".tmp"
	if err := os.WriteFile(tmpPath, raw, 0o600); err != nil {
		return fmt.Errorf("write snapshot tmp: %w", err)
	}
	if err := os.Rename(tmpPath, s.snapshotPath); err != nil {
		return fmt.Errorf("commit snapshot: %w", err)
	}
	return nil
}

func newID(prefix string) string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

// AppendAuditLog appends a new SHA-256 hash-chained audit entry.
func (s *Store) AppendAuditLog(actor, action, resource, severity, outcome, ipAddr, details string) AuditEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry := s.appendAuditLocked(actor, action, resource, severity, outcome, ipAddr, details)
	_ = s.persistLocked("audit.append", "audit_log", entry.ID)
	return entry
}

func (s *Store) appendAuditLocked(actor, action, resource, severity, outcome, ipAddr, details string) AuditEntry {
	prevHash := "GENESIS"
	var seq int64 = 1
	if n := len(s.state.AuditLogs); n > 0 {
		last := s.state.AuditLogs[n-1]
		prevHash = last.Hash
		seq = last.Sequence + 1
	}
	if severity == "" {
		severity = "info"
	}
	if actor == "" {
		actor = "system"
	}
	now := time.Now().UTC().Format(time.RFC3339)
	hash := crypto.ComputeAuditHash(prevHash, now, actor, action, resource, outcome, details)
	entry := AuditEntry{
		ID:        fmt.Sprintf("aud_%06d", seq),
		Sequence:  seq,
		Timestamp: now,
		Actor:     actor,
		Action:    action,
		Resource:  resource,
		Severity:  severity,
		Outcome:   outcome,
		IPAddress: ipAddr,
		Details:   details,
		PrevHash:  prevHash,
		Hash:      hash,
	}
	s.state.AuditLogs = append(s.state.AuditLogs, entry)
	return entry
}

// VerifyAuditChain validates every link in the SHA-256 audit log chain from GENESIS.
func (s *Store) VerifyAuditChain() (valid bool, verifiedCount int, brokenAtID string) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	expectedPrev := "GENESIS"
	for i, entry := range s.state.AuditLogs {
		if entry.PrevHash != expectedPrev {
			return false, i, entry.ID
		}
		computed := crypto.ComputeAuditHash(
			entry.PrevHash,
			entry.Timestamp,
			entry.Actor,
			entry.Action,
			entry.Resource,
			entry.Outcome,
			entry.Details,
		)
		if computed != entry.Hash {
			return false, i, entry.ID
		}
		expectedPrev = entry.Hash
	}
	return true, len(s.state.AuditLogs), ""
}

// ListUsers returns all users sorted by username (with password hashes removed).
func (s *Store) ListUsers() []User {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]User, 0, len(s.state.Users))
	for _, u := range s.state.Users {
		out = append(out, u.Sanitize())
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Username < out[j].Username
	})
	return out
}

// GetUserByUsername retrieves the full User record (including PasswordHash) for authentication.
func (s *Store) GetUserByUsername(username string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.userByUsername[strings.ToLower(strings.TrimSpace(username))]
	if !ok {
		return User{}, false
	}
	u, exists := s.state.Users[id]
	return u, exists
}

// GetUserByID retrieves a user by ID.
func (s *Store) GetUserByID(id string) (User, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, exists := s.state.Users[id]
	return u, exists
}

// CreateUser creates a new user with a salted PBKDF2 password hash.
func (s *Store) CreateUser(u User, plainPassword, actor, ip string) (User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	u.Username = strings.TrimSpace(u.Username)
	u.Email = strings.TrimSpace(u.Email)
	if u.Username == "" {
		return User{}, errors.New("username is required")
	}
	if _, exists := s.userByUsername[strings.ToLower(u.Username)]; exists {
		return User{}, fmt.Errorf("username '%s' already exists", u.Username)
	}
	if u.Email != "" {
		if _, exists := s.userByEmail[strings.ToLower(u.Email)]; exists {
			return User{}, fmt.Errorf("email '%s' already exists", u.Email)
		}
	}
	if plainPassword == "" {
		plainPassword = "ChangeMe!2026"
	}
	hash, err := crypto.HashPassword(plainPassword)
	if err != nil {
		return User{}, err
	}
	if u.ID == "" {
		u.ID = newID("usr")
	}
	if u.Status == "" {
		u.Status = "active"
	}
	if u.Department == "" {
		u.Department = "Engineering"
	}
	if len(u.Roles) == 0 {
		u.Roles = []string{"developer"}
	}
	u.PasswordHash = hash
	u.CreatedAt = time.Now().UTC().Format(time.RFC3339)

	s.state.Users[u.ID] = u
	s.rebuildIndexesLocked()
	s.appendAuditLocked(actor, "user.create", u.ID, "info", "SUCCESS", ip, fmt.Sprintf("Created user %s (%s) roles=%v", u.Username, u.Department, u.Roles))
	if err := s.persistLocked("user.create", "user", u.ID); err != nil {
		return User{}, err
	}
	return u.Sanitize(), nil
}

// DeleteUser removes a user by ID.
func (s *Store) DeleteUser(id, actor, ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, exists := s.state.Users[id]
	if !exists {
		return errors.New("user not found")
	}
	delete(s.state.Users, id)
	s.rebuildIndexesLocked()
	s.appendAuditLocked(actor, "user.delete", id, "warn", "SUCCESS", ip, fmt.Sprintf("Deleted user %s", u.Username))
	return s.persistLocked("user.delete", "user", id)
}

// TouchUserLogin updates LastLoginAt for a user.
func (s *Store) TouchUserLogin(id string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if u, ok := s.state.Users[id]; ok {
		u.LastLoginAt = time.Now().UTC().Format(time.RFC3339)
		s.state.Users[id] = u
		_ = s.persistLocked("user.login", "user", id)
	}
}

// ListRoles returns all RBAC roles sorted by name.
func (s *Store) ListRoles() []policy.Role {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]policy.Role, 0, len(s.state.Roles))
	for _, r := range s.state.Roles {
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Name < out[j].Name
	})
	return out
}

// CreateRole registers or updates an RBAC role.
func (s *Store) CreateRole(r policy.Role, actor, ip string) (policy.Role, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	r.Name = strings.TrimSpace(r.Name)
	if r.Name == "" {
		return policy.Role{}, errors.New("role name is required")
	}
	if existingID, exists := s.roleByName[strings.ToLower(r.Name)]; exists && r.ID == "" {
		r.ID = existingID
	}
	if r.ID == "" {
		r.ID = newID("rol")
	}
	if r.CreatedAt == "" {
		r.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	s.state.Roles[r.ID] = r
	s.rebuildIndexesLocked()
	s.appendAuditLocked(actor, "role.upsert", r.ID, "info", "SUCCESS", ip, fmt.Sprintf("Saved role %s permissions=%v", r.Name, r.Permissions))
	if err := s.persistLocked("role.upsert", "role", r.ID); err != nil {
		return policy.Role{}, err
	}
	return r, nil
}

// DeleteRole removes a role by ID.
func (s *Store) DeleteRole(id, actor, ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, exists := s.state.Roles[id]
	if !exists {
		return errors.New("role not found")
	}
	delete(s.state.Roles, id)
	s.rebuildIndexesLocked()
	s.appendAuditLocked(actor, "role.delete", id, "warn", "SUCCESS", ip, fmt.Sprintf("Deleted role %s", r.Name))
	return s.persistLocked("role.delete", "role", id)
}

// ListPolicies returns all policies sorted by priority descending, then ID.
func (s *Store) ListPolicies() []policy.Policy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]policy.Policy, 0, len(s.state.Policies))
	for _, p := range s.state.Policies {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Priority != out[j].Priority {
			return out[i].Priority > out[j].Priority
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// CreatePolicy creates or updates a combined RBAC/ABAC policy.
func (s *Store) CreatePolicy(p policy.Policy, actor, ip string) (policy.Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	p.Name = strings.TrimSpace(p.Name)
	if p.Name == "" {
		return policy.Policy{}, errors.New("policy name is required")
	}
	p.Effect = strings.ToLower(strings.TrimSpace(p.Effect))
	if p.Effect != "allow" && p.Effect != "deny" {
		p.Effect = "allow"
	}
	if p.ID == "" {
		p.ID = newID("pol")
	}
	if p.Priority == 0 {
		p.Priority = 50
	}
	if len(p.Roles) == 0 {
		p.Roles = []string{"*"}
	}
	if len(p.Actions) == 0 {
		p.Actions = []string{"*"}
	}
	if len(p.Resources) == 0 {
		p.Resources = []string{"*"}
	}
	if p.CreatedAt == "" {
		p.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	s.state.Policies[p.ID] = p
	s.appendAuditLocked(actor, "policy.upsert", p.ID, "info", "SUCCESS", ip, fmt.Sprintf("Saved %s policy '%s' (priority=%d)", strings.ToUpper(p.Effect), p.Name, p.Priority))
	if err := s.persistLocked("policy.upsert", "policy", p.ID); err != nil {
		return policy.Policy{}, err
	}
	return p, nil
}

// DeletePolicy deletes a policy by ID.
func (s *Store) DeletePolicy(id, actor, ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, exists := s.state.Policies[id]
	if !exists {
		return errors.New("policy not found")
	}
	delete(s.state.Policies, id)
	s.appendAuditLocked(actor, "policy.delete", id, "warn", "SUCCESS", ip, fmt.Sprintf("Deleted policy '%s'", p.Name))
	return s.persistLocked("policy.delete", "policy", id)
}

// ListOAuthClients returns all OAuth2 clients (sanitized).
func (s *Store) ListOAuthClients() []OAuthClient {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]OAuthClient, 0, len(s.state.OAuthClients))
	for _, c := range s.state.OAuthClients {
		out = append(out, c.Sanitize())
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ClientID < out[j].ClientID
	})
	return out
}

// GetOAuthClientByClientID looks up an OAuth2 client by its public client_id.
func (s *Store) GetOAuthClientByClientID(clientID string) (OAuthClient, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	id, ok := s.clientByClientID[strings.TrimSpace(clientID)]
	if !ok {
		return OAuthClient{}, false
	}
	c, exists := s.state.OAuthClients[id]
	return c, exists
}

// CreateOAuthClient registers a new OAuth2 client and returns the sanitized record + raw client secret.
func (s *Store) CreateOAuthClient(c OAuthClient, rawSecret, actor, ip string) (OAuthClient, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		return OAuthClient{}, "", errors.New("client name is required")
	}
	if c.ID == "" {
		c.ID = newID("cli")
	}
	if c.ClientID == "" {
		c.ClientID = "aether_" + strings.ToLower(strings.ReplaceAll(c.Name, " ", "_")) + "_" + c.ID[len(c.ID)-4:]
	}
	if _, exists := s.clientByClientID[c.ClientID]; exists {
		return OAuthClient{}, "", fmt.Errorf("client_id '%s' already exists", c.ClientID)
	}
	if rawSecret == "" {
		var err error
		rawSecret, err = crypto.GenerateClientSecret()
		if err != nil {
			return OAuthClient{}, "", err
		}
	}
	c.ClientSecretHash = crypto.HashAPIKey(rawSecret)
	if len(rawSecret) > 10 {
		c.ClientSecretPreview = rawSecret[:10] + "..."
	} else {
		c.ClientSecretPreview = "acs_***"
	}
	if len(c.GrantTypes) == 0 {
		c.GrantTypes = []string{"client_credentials", "password"}
	}
	if len(c.Scopes) == 0 {
		c.Scopes = []string{"openid", "profile", "iam:read"}
	}
	if len(c.DefaultRoles) == 0 {
		c.DefaultRoles = []string{"developer"}
	}
	if c.SigningAlg == "" {
		c.SigningAlg = "RS256"
	}
	c.Active = true
	c.CreatedAt = time.Now().UTC().Format(time.RFC3339)

	s.state.OAuthClients[c.ID] = c
	s.rebuildIndexesLocked()
	s.appendAuditLocked(actor, "client.create", c.ID, "info", "SUCCESS", ip, fmt.Sprintf("Registered OAuth2 client %s (%s)", c.Name, c.ClientID))
	if err := s.persistLocked("client.create", "oauth_client", c.ID); err != nil {
		return OAuthClient{}, "", err
	}
	return c.Sanitize(), rawSecret, nil
}

// DeleteOAuthClient deletes an OAuth2 client by ID.
func (s *Store) DeleteOAuthClient(id, actor, ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, exists := s.state.OAuthClients[id]
	if !exists {
		return errors.New("oauth client not found")
	}
	delete(s.state.OAuthClients, id)
	s.rebuildIndexesLocked()
	s.appendAuditLocked(actor, "client.delete", id, "warn", "SUCCESS", ip, fmt.Sprintf("Deleted OAuth2 client %s", c.ClientID))
	return s.persistLocked("client.delete", "oauth_client", id)
}

// ListAPIKeys returns all scoped API keys (sanitized).
func (s *Store) ListAPIKeys() []APIKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]APIKey, 0, len(s.state.APIKeys))
	for _, k := range s.state.APIKeys {
		out = append(out, k.Sanitize())
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt > out[j].CreatedAt
	})
	return out
}

// CreateAPIKey generates a new `aiam_` API key, stores its SHA-256 hash, and returns the record + plaintext key once.
func (s *Store) CreateAPIKey(k APIKey, customRawKey, actor, ip string) (APIKey, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	k.Name = strings.TrimSpace(k.Name)
	if k.Name == "" {
		return APIKey{}, "", errors.New("api key name is required")
	}
	var rawKey, prefix, hash string
	if customRawKey != "" {
		rawKey = customRawKey
		if len(rawKey) > 13 {
			prefix = rawKey[:13] + "..."
		} else {
			prefix = rawKey
		}
		hash = crypto.HashAPIKey(rawKey)
	} else {
		var err error
		rawKey, prefix, hash, err = crypto.GenerateAPIKey()
		if err != nil {
			return APIKey{}, "", err
		}
	}
	if k.ID == "" {
		k.ID = newID("key")
	}
	k.KeyPrefix = prefix
	k.KeyHash = hash
	if len(k.Scopes) == 0 {
		k.Scopes = []string{"iam:read", "policy:evaluate"}
	}
	if len(k.Roles) == 0 {
		k.Roles = []string{"developer"}
	}
	if k.RateLimitRPS <= 0 {
		k.RateLimitRPS = 50
	}
	k.Active = true
	k.CreatedAt = time.Now().UTC().Format(time.RFC3339)

	s.state.APIKeys[k.ID] = k
	s.rebuildIndexesLocked()
	s.appendAuditLocked(actor, "apikey.create", k.ID, "info", "SUCCESS", ip, fmt.Sprintf("Issued API key '%s' (%s) scopes=%v", k.Name, k.KeyPrefix, k.Scopes))
	if err := s.persistLocked("apikey.create", "api_key", k.ID); err != nil {
		return APIKey{}, "", err
	}
	return k.Sanitize(), rawKey, nil
}

// VerifyAPIKey looks up an `aiam_` key by its SHA-256 fingerprint and updates LastUsedAt.
func (s *Store) VerifyAPIKey(rawKey string) (APIKey, bool) {
	hash := crypto.HashAPIKey(strings.TrimSpace(rawKey))
	s.mu.Lock()
	defer s.mu.Unlock()

	id, exists := s.apiKeyByHash[hash]
	if !exists {
		return APIKey{}, false
	}
	k, ok := s.state.APIKeys[id]
	if !ok || !k.Active {
		return APIKey{}, false
	}
	k.LastUsedAt = time.Now().UTC().Format(time.RFC3339)
	s.state.APIKeys[id] = k
	return k.Sanitize(), true
}

// DeleteAPIKey revokes and deletes an API key by ID.
func (s *Store) DeleteAPIKey(id, actor, ip string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	k, exists := s.state.APIKeys[id]
	if !exists {
		return errors.New("api key not found")
	}
	delete(s.state.APIKeys, id)
	s.rebuildIndexesLocked()
	s.appendAuditLocked(actor, "apikey.delete", id, "warn", "SUCCESS", ip, fmt.Sprintf("Revoked API key '%s' (%s)", k.Name, k.KeyPrefix))
	return s.persistLocked("apikey.delete", "api_key", id)
}

// RecordSession records an issued OAuth2/JWT token session.
func (s *Store) RecordSession(sess Session) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess.ID == "" {
		sess.ID = newID("ses")
	}
	if sess.CreatedAt == "" {
		sess.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	s.state.Sessions[sess.ID] = sess
	_ = s.persistLocked("session.create", "session", sess.ID)
}

// ListAuditLogs returns audit entries filtered by optional search query, severity, and outcome (newest first).
func (s *Store) ListAuditLogs(query, severity, outcome string, limit int) []AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()

	q := strings.ToLower(strings.TrimSpace(query))
	sev := strings.ToLower(strings.TrimSpace(severity))
	outFilter := strings.ToUpper(strings.TrimSpace(outcome))
	if limit <= 0 || limit > 500 {
		limit = 200
	}

	res := make([]AuditEntry, 0, len(s.state.AuditLogs))
	for i := len(s.state.AuditLogs) - 1; i >= 0; i-- {
		e := s.state.AuditLogs[i]
		if sev != "" && sev != "all" && !strings.EqualFold(e.Severity, sev) {
			continue
		}
		if outFilter != "" && outFilter != "ALL" && !strings.EqualFold(e.Outcome, outFilter) {
			continue
		}
		if q != "" {
			haystack := strings.ToLower(e.Actor + " " + e.Action + " " + e.Resource + " " + e.Details + " " + e.Hash)
			if !strings.Contains(haystack, q) {
				continue
			}
		}
		res = append(res, e)
		if len(res) >= limit {
			break
		}
	}
	return res
}

// Stats returns live counts across all identity, policy, session, and audit collections.
func (s *Store) Stats() map[string]any {
	s.mu.RLock()
	defer s.mu.RUnlock()

	activeUsers := 0
	mfaUsers := 0
	for _, u := range s.state.Users {
		if u.Status == "active" {
			activeUsers++
		}
		if u.MFAEnabled {
			mfaUsers++
		}
	}
	allowPolicies := 0
	denyPolicies := 0
	for _, p := range s.state.Policies {
		if strings.EqualFold(p.Effect, "deny") {
			denyPolicies++
		} else {
			allowPolicies++
		}
	}
	return map[string]any{
		"schema_version":  s.state.SchemaVersion,
		"wal_sequence":    s.state.WALSequence,
		"migrations":      len(s.state.Migrations),
		"users_total":     len(s.state.Users),
		"users_active":    activeUsers,
		"users_mfa":       mfaUsers,
		"roles_total":     len(s.state.Roles),
		"policies_total":  len(s.state.Policies),
		"policies_allow":  allowPolicies,
		"policies_deny":   denyPolicies,
		"clients_total":   len(s.state.OAuthClients),
		"apikeys_total":   len(s.state.APIKeys),
		"sessions_total":  len(s.state.Sessions),
		"audit_entries":   len(s.state.AuditLogs),
		"last_snapshot":   s.state.SnapshotAt,
	}
}

// ExportBackup produces a verifiable JSON snapshot backup with SHA-256 payload checksum.
func (s *Store) ExportBackup() ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	cp := s.state
	cp.Checksum = ""
	rawWithoutChecksum, err := json.Marshal(cp)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(rawWithoutChecksum)
	cp.Checksum = hex.EncodeToString(sum[:])
	return json.MarshalIndent(cp, "", "  ")
}

// RestoreBackup atomically replaces the store state from a JSON snapshot backup and rebuilds all indexes.
func (s *Store) RestoreBackup(rawJSON []byte, actor, ip string) error {
	var incoming Snapshot
	if err := json.Unmarshal(rawJSON, &incoming); err != nil {
		return fmt.Errorf("invalid backup json: %w", err)
	}
	if incoming.SchemaVersion <= 0 {
		return errors.New("backup missing valid schema_version")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	s.ensureMaps(&incoming)
	s.state = incoming
	s.applyMigrationsLocked()
	s.rebuildIndexesLocked()
	s.appendAuditLocked(actor, "admin.restore", "snapshot", "critical", "SUCCESS", ip, fmt.Sprintf("Restored state snapshot (users=%d, policies=%d)", len(s.state.Users), len(s.state.Policies)))
	return s.persistLocked("admin.restore", "snapshot", "restore")
}

// SeedDemo populates enterprise IAM roles, users, RBAC/ABAC policies, OAuth2 clients, and API keys if empty.
func (s *Store) SeedDemo() error {
	s.mu.Lock()
	hasData := len(s.state.Users) > 0 || len(s.state.Roles) > 0
	s.mu.Unlock()
	if hasData {
		return nil
	}

	roles := []policy.Role{
		{
			ID:          "rol_super_admin",
			Name:        "super_admin",
			Description: "Global IAM, Cryptographic & Policy Governance Administrator",
			Permissions: []string{"*:*", "iam:*", "policies:*", "audit:*"},
			BuiltIn:     true,
		},
		{
			ID:          "rol_sre_lead",
			Name:        "sre_lead",
			Description: "Site Reliability & Production Infrastructure Lead",
			Permissions: []string{"infra:*", "deployments:approve", "clusters:scale", "metrics:read"},
			BuiltIn:     true,
		},
		{
			ID:          "rol_sec_auditor",
			Name:        "security_auditor",
			Description: "Zero-Trust Compliance & Cryptographic Ledger Auditor",
			Permissions: []string{"audit:read", "audit:verify", "policies:read", "users:read"},
			BuiltIn:     true,
		},
		{
			ID:          "rol_developer",
			Name:        "developer",
			Description: "Application & Microservice Software Engineer",
			Permissions: []string{"repos:read", "repos:write", "staging:deploy", "profile:update"},
			BuiltIn:     true,
		},
	}
	for _, r := range roles {
		if _, err := s.CreateRole(r, "system.seed", "127.0.0.1"); err != nil {
			return err
		}
	}

	users := []struct {
		user User
		pass string
	}{
		{
			user: User{
				ID:         "usr_admin",
				Username:   "admin",
				Email:      "admin@aetheriam.io",
				FullName:   "Soren Lindqvist (Chief Security Officer)",
				Department: "Security",
				Status:     "active",
				MFAEnabled: true,
				Roles:      []string{"super_admin", "security_auditor"},
			},
			pass: "AetherAdmin!2026",
		},
		{
			user: User{
				ID:         "usr_elena",
				Username:   "elena.vance",
				Email:      "elena.vance@aetheriam.io",
				FullName:   "Elena Vance (Principal SRE)",
				Department: "Platform",
				Status:     "active",
				MFAEnabled: true,
				Roles:      []string{"sre_lead"},
			},
			pass: "ElenaSRE!2026",
		},
		{
			user: User{
				ID:         "usr_marcus",
				Username:   "marcus.chen",
				Email:      "marcus.chen@aetheriam.io",
				FullName:   "Marcus Chen (GRC & Audit Specialist)",
				Department: "Security",
				Status:     "active",
				MFAEnabled: true,
				Roles:      []string{"security_auditor"},
			},
			pass: "MarcusSec!2026",
		},
		{
			user: User{
				ID:         "usr_aria",
				Username:   "aria.patel",
				Email:      "aria.patel@aetheriam.io",
				FullName:   "Aria Patel (Senior Backend Engineer)",
				Department: "Engineering",
				Status:     "active",
				MFAEnabled: false,
				Roles:      []string{"developer"},
			},
			pass: "AriaDev!2026",
		},
	}
	for _, item := range users {
		if _, err := s.CreateUser(item.user, item.pass, "system.seed", "127.0.0.1"); err != nil {
			return err
		}
	}

	policies := []policy.Policy{
		{
			ID:          "pol_deny_external_prod",
			Name:        "Deny Untrusted External Subnet on Production",
			Description: "Explicit zero-trust block for high-risk external CIDR 203.0.113.0/24 targeting production resources.",
			Effect:      "deny",
			Priority:    100,
			Roles:       []string{"*"},
			Actions:     []string{"*"},
			Resources:   []string{"arn:aether:prod:*", "cluster:prod-*"},
			Condition: policy.ABACCondition{
				AllowedCIDRs: []string{"203.0.113.0/24"},
			},
			Enabled: true,
		},
		{
			ID:          "pol_allow_super_admin",
			Name:        "Allow Super Admin Full Control Plane Governance with MFA",
			Description: "Grants super_admin full IAM and control-plane operations when MFA is verified.",
			Effect:      "allow",
			Priority:    90,
			Roles:       []string{"super_admin"},
			Actions:     []string{"*"},
			Resources:   []string{"*"},
			Condition: policy.ABACCondition{
				RequireMFA:  true,
				Departments: []string{"Security", "Platform"},
			},
			Enabled: true,
		},
		{
			ID:          "pol_allow_prod_sre",
			Name:        "Allow SRE Production Deployment on Corporate Network",
			Description: "Permits SRE Leads in Platform/Security to deploy to production clusters from private corporate CIDRs with MFA.",
			Effect:      "allow",
			Priority:    75,
			Roles:       []string{"sre_lead"},
			Actions:     []string{"infra:*", "deployments:*", "clusters:*"},
			Resources:   []string{"arn:aether:prod:*", "cluster:prod-*"},
			Condition: policy.ABACCondition{
				AllowedCIDRs: []string{"10.0.0.0/8", "192.168.0.0/16", "127.0.0.1/32"},
				Departments:  []string{"Platform", "Security"},
				Environments: []string{"production"},
				RequireMFA:   true,
			},
			Enabled: true,
		},
		{
			ID:          "pol_allow_staging_dev",
			Name:        "Allow Developers Staging & Repository Access",
			Description: "Allows developers and SREs to read/write repositories and deploy to staging or development environments.",
			Effect:      "allow",
			Priority:    50,
			Roles:       []string{"developer", "sre_lead"},
			Actions:     []string{"repos:*", "staging:*", "infra:read"},
			Resources:   []string{"arn:aether:staging:*", "repo:*"},
			Condition: policy.ABACCondition{
				Environments: []string{"staging", "development"},
			},
			Enabled: true,
		},
		{
			ID:          "pol_allow_owner_profile",
			Name:        "Allow Self-Service Identity Profile Ownership Match",
			Description: "Allows any authenticated identity to update their own profile record when SubjectID == ResourceOwnerID.",
			Effect:      "allow",
			Priority:    40,
			Roles:       []string{"*"},
			Actions:     []string{"profile:update", "profile:read"},
			Resources:   []string{"user:profile/*"},
			Condition: policy.ABACCondition{
				OwnerMatch: true,
			},
			Enabled: true,
		},
	}
	for _, p := range policies {
		if _, err := s.CreatePolicy(p, "system.seed", "127.0.0.1"); err != nil {
			return err
		}
	}

	_, _, _ = s.CreateOAuthClient(OAuthClient{
		ID:           "cli_console",
		ClientID:     "aether-console-client",
		Name:         "AetherIAM Control Plane Console",
		Description:  "First-party OIDC/OAuth2 administrative application",
		GrantTypes:   []string{"client_credentials", "password"},
		Scopes:       []string{"openid", "profile", "email", "iam:admin", "policy:evaluate"},
		RedirectURIs: []string{"http://localhost:8080/oauth/callback"},
		DefaultRoles: []string{"super_admin"},
		SigningAlg:   "RS256",
	}, "acs_demo_console_secret_2026", "system.seed", "127.0.0.1")

	_, _, _ = s.CreateOAuthClient(OAuthClient{
		ID:           "cli_mesh",
		ClientID:     "k8s-mesh-operator",
		Name:         "Kubernetes Zero-Trust Service Mesh Operator",
		Description:  "Machine-to-machine OAuth2 client verifying sidecar workloads",
		GrantTypes:   []string{"client_credentials"},
		Scopes:       []string{"iam:read", "policy:evaluate"},
		RedirectURIs: []string{"https://mesh.aether.internal/callback"},
		DefaultRoles: []string{"sre_lead"},
		SigningAlg:   "HS256",
	}, "acs_demo_mesh_secret_2026", "system.seed", "127.0.0.1")

	_, _, _ = s.CreateAPIKey(APIKey{
		ID:           "key_platform_auto",
		Name:         "Platform CI/CD Policy Gatekeeper Key",
		OwnerUserID:  "usr_elena",
		Scopes:       []string{"iam:read", "policy:evaluate"},
		Roles:        []string{"sre_lead"},
		RateLimitRPS: 100,
		ExpiresAt:    "2027-12-31T23:59:59Z",
	}, "aiam_demo_platform_automation_key_2026", "system.seed", "127.0.0.1")

	return nil
}
