package policy

import (
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// Role defines an RBAC role and its granted permission patterns (e.g. "users:read", "finance:*", "*:*").
type Role struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Permissions []string `json:"permissions"`
	BuiltIn     bool     `json:"built_in"`
	CreatedAt   string   `json:"created_at"`
}

// ABACCondition defines fine-grained contextual and attribute constraints on a Policy.
type ABACCondition struct {
	AllowedCIDRs       []string          `json:"allowed_cidrs,omitempty"`
	Departments        []string          `json:"departments,omitempty"`
	Environments       []string          `json:"environments,omitempty"`
	RequireMFA         bool              `json:"require_mfa,omitempty"`
	OwnerMatch         bool              `json:"owner_match,omitempty"`
	TimeWindowStart    string            `json:"time_window_start,omitempty"` // "HH:MM" UTC
	TimeWindowEnd      string            `json:"time_window_end,omitempty"`   // "HH:MM" UTC
	RequiredAttributes map[string]string `json:"required_attributes,omitempty"`
}

// Policy defines a combined RBAC + ABAC governance rule.
type Policy struct {
	ID          string        `json:"id"`
	Name        string        `json:"name"`
	Description string        `json:"description"`
	Effect      string        `json:"effect"` // "allow" or "deny"
	Priority    int           `json:"priority"`
	Roles       []string      `json:"roles"`     // role names or "*"
	Actions     []string      `json:"actions"`   // action patterns e.g. "deploy", "infra:*", "*"
	Resources   []string      `json:"resources"` // resource patterns e.g. "arn:aether:prod:*", "*"
	Condition   ABACCondition `json:"condition"`
	Enabled     bool          `json:"enabled"`
	CreatedAt   string        `json:"created_at"`
}

// EvalRequest captures the subject, resource, action, and environmental context for policy evaluation.
type EvalRequest struct {
	SubjectID       string            `json:"subject_id"`
	Username        string            `json:"username"`
	Roles           []string          `json:"roles"`
	Department      string            `json:"department"`
	MFAVerified     bool              `json:"mfa_verified"`
	IPAddress       string            `json:"ip_address"`
	Environment     string            `json:"environment"`
	Action          string            `json:"action"`
	Resource        string            `json:"resource"`
	ResourceOwnerID string            `json:"resource_owner_id,omitempty"`
	Timestamp       time.Time         `json:"-"`
	EvalTimeUTC     string            `json:"eval_time_utc,omitempty"` // optional "HH:MM" or RFC3339 override
	Attributes      map[string]string `json:"attributes,omitempty"`
}

// TraceStep documents a single evaluation step in the deterministic decision trace.
type TraceStep struct {
	Phase    string `json:"phase"`
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Effect   string `json:"effect"`
	Matched  bool   `json:"matched"`
	Reason   string `json:"reason"`
}

// EvalResult contains the final authorization decision and full step-by-step explanation trace.
type EvalResult struct {
	Allowed               bool        `json:"allowed"`
	Decision              string      `json:"decision"` // "ALLOW" or "DENY"
	MatchedPolicyID       string      `json:"matched_policy_id,omitempty"`
	MatchedPolicyName     string      `json:"matched_policy_name,omitempty"`
	RBACGranted           bool        `json:"rbac_granted"`
	RBACMatchedRole       string      `json:"rbac_matched_role,omitempty"`
	RBACMatchedPermission string      `json:"rbac_matched_permission,omitempty"`
	Reason                string      `json:"reason"`
	EvaluatedAt           string      `json:"evaluated_at"`
	DurationMicros        int64       `json:"duration_micros"`
	Trace                 []TraceStep `json:"trace"`
}

// Evaluate executes deterministic combined RBAC + ABAC policy evaluation:
// 1. Explicit DENY policies sorted by priority descending are evaluated first.
// 2. Subject's RBAC role permissions are evaluated.
// 3. Explicit ALLOW policies (with ABAC conditions) sorted by priority descending are evaluated.
// 4. Default Zero-Trust DENY if neither an ALLOW policy nor an unrestricted RBAC grant matches.
func Evaluate(req EvalRequest, roles []Role, policies []Policy) EvalResult {
	start := time.Now()
	evalTime := req.Timestamp
	if evalTime.IsZero() {
		evalTime = start.UTC()
	}
	if req.EvalTimeUTC != "" {
		if parsed, err := time.Parse(time.RFC3339, req.EvalTimeUTC); err == nil {
			evalTime = parsed.UTC()
		} else if parsedHM, err := time.Parse("15:04", req.EvalTimeUTC); err == nil {
			evalTime = time.Date(2026, 1, 1, parsedHM.Hour(), parsedHM.Minute(), 0, 0, time.UTC)
		}
	}

	trace := make([]TraceStep, 0, len(policies)+2)

	// Sort policies by Priority DESC, then ID ASC for determinism
	sortedPolicies := make([]Policy, len(policies))
	copy(sortedPolicies, policies)
	sort.Slice(sortedPolicies, func(i, j int) bool {
		if sortedPolicies[i].Priority != sortedPolicies[j].Priority {
			return sortedPolicies[i].Priority > sortedPolicies[j].Priority
		}
		return sortedPolicies[i].ID < sortedPolicies[j].ID
	})

	// Phase 1: Explicit DENY policies
	for _, pol := range sortedPolicies {
		if !pol.Enabled || !strings.EqualFold(pol.Effect, "deny") {
			continue
		}
		matched, reason := matchPolicy(req, pol, evalTime)
		trace = append(trace, TraceStep{
			Phase:    "ABAC_EXPLICIT_DENY",
			RuleID:   pol.ID,
			RuleName: pol.Name,
			Effect:   "DENY",
			Matched:  matched,
			Reason:   reason,
		})
		if matched {
			return EvalResult{
				Allowed:           false,
				Decision:          "DENY",
				MatchedPolicyID:   pol.ID,
				MatchedPolicyName: pol.Name,
				Reason:            fmt.Sprintf("Explicit DENY policy '%s' (%s) matched: %s", pol.Name, pol.ID, reason),
				EvaluatedAt:       start.UTC().Format(time.RFC3339),
				DurationMicros:    time.Since(start).Microseconds(),
				Trace:             trace,
			}
		}
	}

	// Phase 2: RBAC Role Permission Resolution
	rbacGranted, matchedRole, matchedPerm, rbacReason := evaluateRBAC(req, roles)
	trace = append(trace, TraceStep{
		Phase:    "RBAC_PERMISSION_CHECK",
		RuleID:   matchedRole,
		RuleName: "RBAC Role Matrix",
		Effect:   "RBAC",
		Matched:  rbacGranted,
		Reason:   rbacReason,
	})

	// Phase 3: Explicit ALLOW policies with ABAC conditions
	for _, pol := range sortedPolicies {
		if !pol.Enabled || !strings.EqualFold(pol.Effect, "allow") {
			continue
		}
		matched, reason := matchPolicy(req, pol, evalTime)
		trace = append(trace, TraceStep{
			Phase:    "ABAC_ALLOW_POLICY",
			RuleID:   pol.ID,
			RuleName: pol.Name,
			Effect:   "ALLOW",
			Matched:  matched,
			Reason:   reason,
		})
		if matched {
			return EvalResult{
				Allowed:               true,
				Decision:              "ALLOW",
				MatchedPolicyID:       pol.ID,
				MatchedPolicyName:     pol.Name,
				RBACGranted:           rbacGranted,
				RBACMatchedRole:       matchedRole,
				RBACMatchedPermission: matchedPerm,
				Reason:                fmt.Sprintf("Allowed by policy '%s' (%s): %s", pol.Name, pol.ID, reason),
				EvaluatedAt:           start.UTC().Format(time.RFC3339),
				DurationMicros:        time.Since(start).Microseconds(),
				Trace:                 trace,
			}
		}
	}

	// Fallback: default zero-trust deny
	denyReason := "Zero-trust implicit deny: no enabled ALLOW policy matched subject, resource, action, and ABAC conditions"
	if rbacGranted {
		denyReason = fmt.Sprintf("RBAC role '%s' grants '%s', but no active ABAC ALLOW policy satisfied the contextual constraints", matchedRole, matchedPerm)
	}
	return EvalResult{
		Allowed:               false,
		Decision:              "DENY",
		RBACGranted:           rbacGranted,
		RBACMatchedRole:       matchedRole,
		RBACMatchedPermission: matchedPerm,
		Reason:                denyReason,
		EvaluatedAt:           start.UTC().Format(time.RFC3339),
		DurationMicros:        time.Since(start).Microseconds(),
		Trace:                 trace,
	}
}

func evaluateRBAC(req EvalRequest, roles []Role) (bool, string, string, string) {
	if len(req.Roles) == 0 {
		return false, "", "", "subject has no assigned RBAC roles"
	}
	roleMap := make(map[string]Role, len(roles))
	for _, r := range roles {
		roleMap[strings.ToLower(r.Name)] = r
		roleMap[strings.ToLower(r.ID)] = r
	}

	compositeTarget := req.Resource + ":" + req.Action
	for _, subjRole := range req.Roles {
		r, ok := roleMap[strings.ToLower(subjRole)]
		if !ok {
			continue
		}
		for _, perm := range r.Permissions {
			if matchPattern(perm, req.Action) || matchPattern(perm, compositeTarget) || perm == "*:*" || perm == "*" {
				return true, r.Name, perm, fmt.Sprintf("role '%s' grants permission '%s' matching action '%s'", r.Name, perm, req.Action)
			}
		}
	}
	return false, "", "", fmt.Sprintf("none of subject roles %v grant permission for action '%s' on '%s'", req.Roles, req.Action, req.Resource)
}

func matchPolicy(req EvalRequest, pol Policy, evalTime time.Time) (bool, string) {
	// 1. Check Role Binding
	if !matchesAnyRole(req.Roles, pol.Roles) {
		return false, fmt.Sprintf("subject roles %v do not intersect policy roles %v", req.Roles, pol.Roles)
	}

	// 2. Check Action Pattern
	if !matchesAnyPattern(req.Action, pol.Actions) {
		return false, fmt.Sprintf("action '%s' does not match policy actions %v", req.Action, pol.Actions)
	}

	// 3. Check Resource Pattern
	if !matchesAnyPattern(req.Resource, pol.Resources) {
		return false, fmt.Sprintf("resource '%s' does not match policy resources %v", req.Resource, pol.Resources)
	}

	// 4. Evaluate ABAC Conditions
	cond := pol.Condition
	var matchedDetails []string
	matchedDetails = append(matchedDetails, "role/action/resource matched")

	// 4a. MFA Check
	if cond.RequireMFA {
		if !req.MFAVerified {
			return false, "ABAC condition failed: policy requires MFAVerified=true"
		}
		matchedDetails = append(matchedDetails, "MFA verified")
	}

	// 4b. Resource Owner Match
	if cond.OwnerMatch {
		if req.SubjectID == "" || req.SubjectID != req.ResourceOwnerID {
			return false, fmt.Sprintf("ABAC condition failed: subject '%s' is not resource owner '%s'", req.SubjectID, req.ResourceOwnerID)
		}
		matchedDetails = append(matchedDetails, "resource owner verified")
	}

	// 4c. Department Check
	if len(cond.Departments) > 0 {
		if !containsFold(cond.Departments, req.Department) {
			return false, fmt.Sprintf("ABAC condition failed: department '%s' not in %v", req.Department, cond.Departments)
		}
		matchedDetails = append(matchedDetails, fmt.Sprintf("department='%s'", req.Department))
	}

	// 4d. Environment Check
	if len(cond.Environments) > 0 {
		if !containsFold(cond.Environments, req.Environment) {
			return false, fmt.Sprintf("ABAC condition failed: environment '%s' not in %v", req.Environment, cond.Environments)
		}
		matchedDetails = append(matchedDetails, fmt.Sprintf("environment='%s'", req.Environment))
	}

	// 4e. IP CIDR Check
	if len(cond.AllowedCIDRs) > 0 {
		if !matchIPCIDRs(req.IPAddress, cond.AllowedCIDRs) {
			return false, fmt.Sprintf("ABAC condition failed: IP '%s' outside allowed CIDRs %v", req.IPAddress, cond.AllowedCIDRs)
		}
		matchedDetails = append(matchedDetails, fmt.Sprintf("IP '%s' in allowed CIDR", req.IPAddress))
	}

	// 4f. Time Window Check (UTC HH:MM)
	if cond.TimeWindowStart != "" && cond.TimeWindowEnd != "" {
		ok, msg := matchTimeWindow(evalTime, cond.TimeWindowStart, cond.TimeWindowEnd)
		if !ok {
			return false, "ABAC condition failed: " + msg
		}
		matchedDetails = append(matchedDetails, msg)
	}

	// 4g. Required Attributes Check
	if len(cond.RequiredAttributes) > 0 {
		for k, expectedVal := range cond.RequiredAttributes {
			actualVal, exists := req.Attributes[k]
			if !exists || !strings.EqualFold(actualVal, expectedVal) {
				return false, fmt.Sprintf("ABAC condition failed: attribute '%s'='%s' does not match required '%s'", k, actualVal, expectedVal)
			}
		}
		matchedDetails = append(matchedDetails, "custom attributes matched")
	}

	return true, strings.Join(matchedDetails, "; ")
}

func matchesAnyRole(subjectRoles, policyRoles []string) bool {
	if len(policyRoles) == 0 {
		return true
	}
	for _, pr := range policyRoles {
		if pr == "*" {
			return true
		}
		for _, sr := range subjectRoles {
			if strings.EqualFold(sr, pr) {
				return true
			}
		}
	}
	return false
}

func matchesAnyPattern(value string, patterns []string) bool {
	for _, p := range patterns {
		if matchPattern(p, value) {
			return true
		}
	}
	return false
}

// matchPattern supports exact match (case-insensitive), "*", "*:*", prefix glob "prefix*", and suffix glob "*suffix".
func matchPattern(pattern, value string) bool {
	p := strings.ToLower(strings.TrimSpace(pattern))
	v := strings.ToLower(strings.TrimSpace(value))
	if p == "*" || p == "*:*" || p == v {
		return true
	}
	if strings.HasSuffix(p, "*") {
		prefix := strings.TrimSuffix(p, "*")
		if strings.HasPrefix(v, prefix) {
			return true
		}
	}
	if strings.HasPrefix(p, "*") {
		suffix := strings.TrimPrefix(p, "*")
		if strings.HasSuffix(v, suffix) {
			return true
		}
	}
	return false
}

func containsFold(slice []string, item string) bool {
	for _, s := range slice {
		if s == "*" || strings.EqualFold(strings.TrimSpace(s), strings.TrimSpace(item)) {
			return true
		}
	}
	return false
}

func matchIPCIDRs(ipStr string, cidrs []string) bool {
	ipStr = strings.TrimSpace(ipStr)
	if ipStr == "" {
		return false
	}
	if host, _, err := net.SplitHostPort(ipStr); err == nil {
		ipStr = host
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, cidr := range cidrs {
		cidr = strings.TrimSpace(cidr)
		if cidr == "*" || cidr == "0.0.0.0/0" || cidr == "::/0" {
			return true
		}
		if !strings.Contains(cidr, "/") {
			if singleIP := net.ParseIP(cidr); singleIP != nil && singleIP.Equal(ip) {
				return true
			}
			continue
		}
		_, network, err := net.ParseCIDR(cidr)
		if err == nil && network.Contains(ip) {
			return true
		}
	}
	return false
}

func matchTimeWindow(evalTime time.Time, startHHMM, endHHMM string) (bool, string) {
	startMin, err1 := parseHHMM(startHHMM)
	endMin, err2 := parseHHMM(endHHMM)
	if err1 != nil || err2 != nil {
		return false, fmt.Sprintf("invalid time window format %s-%s", startHHMM, endHHMM)
	}
	curMin := evalTime.UTC().Hour()*60 + evalTime.UTC().Minute()
	curFormatted := fmt.Sprintf("%02d:%02d UTC", evalTime.UTC().Hour(), evalTime.UTC().Minute())

	var inside bool
	if startMin <= endMin {
		inside = curMin >= startMin && curMin <= endMin
	} else {
		// Overnight window e.g. 22:00 to 06:00
		inside = curMin >= startMin || curMin <= endMin
	}
	if !inside {
		return false, fmt.Sprintf("current time %s outside window %s-%s UTC", curFormatted, startHHMM, endHHMM)
	}
	return true, fmt.Sprintf("time %s within window %s-%s UTC", curFormatted, startHHMM, endHHMM)
}

func parseHHMM(s string) (int, error) {
	t, err := time.Parse("15:04", strings.TrimSpace(s))
	if err != nil {
		return 0, err
	}
	return t.Hour()*60 + t.Minute(), nil
}
