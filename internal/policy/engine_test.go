package policy

import (
	"testing"
)

func TestPolicyEngineRBACAndABAC(t *testing.T) {
	roles := []Role{
		{
			ID:          "rol_sre",
			Name:        "sre_lead",
			Permissions: []string{"infra:*", "deployments:approve"},
		},
		{
			ID:          "rol_dev",
			Name:        "developer",
			Permissions: []string{"repos:read", "repos:write"},
		},
	}

	policies := []Policy{
		{
			ID:        "pol_deny_untrusted_ip",
			Name:      "Block External IP on Production",
			Effect:    "deny",
			Priority:  100,
			Roles:     []string{"*"},
			Actions:   []string{"infra:*", "deployments:*"},
			Resources: []string{"arn:aether:prod:*"},
			Condition: ABACCondition{
				AllowedCIDRs: []string{"203.0.113.0/24"}, // suspicious range
			},
			Enabled: true,
		},
		{
			ID:        "pol_allow_prod_sre",
			Name:      "Allow SRE Production Deployment with MFA & Corp Network",
			Effect:    "allow",
			Priority:  50,
			Roles:     []string{"sre_lead"},
			Actions:   []string{"infra:*", "deployments:*"},
			Resources: []string{"arn:aether:prod:*"},
			Condition: ABACCondition{
				AllowedCIDRs:    []string{"10.0.0.0/8", "192.168.1.0/24"},
				Departments:     []string{"Platform", "Security"},
				Environments:    []string{"production"},
				RequireMFA:      true,
				TimeWindowStart: "08:00",
				TimeWindowEnd:   "20:00",
			},
			Enabled: true,
		},
		{
			ID:        "pol_allow_owner_profile",
			Name:      "Allow Users to Edit Own Profile",
			Effect:    "allow",
			Priority:  20,
			Roles:     []string{"*"},
			Actions:   []string{"profile:update"},
			Resources: []string{"user:profile/*"},
			Condition: ABACCondition{
				OwnerMatch: true,
			},
			Enabled: true,
		},
	}

	// Case 1: SRE Lead on Corp IP with MFA inside Time Window -> ALLOW
	res1 := Evaluate(EvalRequest{
		SubjectID:   "usr_1",
		Username:    "alice",
		Roles:       []string{"sre_lead"},
		Department:  "Platform",
		MFAVerified: true,
		IPAddress:   "10.24.1.15",
		Environment: "production",
		Action:      "infra:deploy",
		Resource:    "arn:aether:prod:k8s-eu-west",
		EvalTimeUTC: "14:30",
	}, roles, policies)

	if !res1.Allowed || res1.Decision != "ALLOW" || res1.MatchedPolicyID != "pol_allow_prod_sre" {
		t.Fatalf("Case 1 expected ALLOW by pol_allow_prod_sre, got: %+v", res1)
	}
	if !res1.RBACGranted || len(res1.Trace) < 2 {
		t.Fatalf("Case 1 expected RBACGranted=true and detailed trace, got: %+v", res1)
	}

	// Case 2: Explicit DENY overrides ALLOW when IP matches blocked range
	res2 := Evaluate(EvalRequest{
		SubjectID:   "usr_1",
		Username:    "alice",
		Roles:       []string{"sre_lead"},
		Department:  "Platform",
		MFAVerified: true,
		IPAddress:   "203.0.113.45",
		Environment: "production",
		Action:      "infra:deploy",
		Resource:    "arn:aether:prod:k8s-eu-west",
		EvalTimeUTC: "14:30",
	}, roles, policies)

	if res2.Allowed || res2.Decision != "DENY" || res2.MatchedPolicyID != "pol_deny_untrusted_ip" {
		t.Fatalf("Case 2 expected explicit DENY by pol_deny_untrusted_ip, got: %+v", res2)
	}

	// Case 3: MFA missing -> DENY
	res3 := Evaluate(EvalRequest{
		SubjectID:   "usr_1",
		Username:    "alice",
		Roles:       []string{"sre_lead"},
		Department:  "Platform",
		MFAVerified: false,
		IPAddress:   "10.24.1.15",
		Environment: "production",
		Action:      "infra:deploy",
		Resource:    "arn:aether:prod:k8s-eu-west",
		EvalTimeUTC: "14:30",
	}, roles, policies)

	if res3.Allowed || res3.Decision != "DENY" {
		t.Fatalf("Case 3 expected DENY when MFAVerified=false, got: %+v", res3)
	}

	// Case 4: Outside Time Window -> DENY
	res4 := Evaluate(EvalRequest{
		SubjectID:   "usr_1",
		Username:    "alice",
		Roles:       []string{"sre_lead"},
		Department:  "Platform",
		MFAVerified: true,
		IPAddress:   "10.24.1.15",
		Environment: "production",
		Action:      "infra:deploy",
		Resource:    "arn:aether:prod:k8s-eu-west",
		EvalTimeUTC: "23:15",
	}, roles, policies)

	if res4.Allowed || res4.Decision != "DENY" {
		t.Fatalf("Case 4 expected DENY outside UTC time window, got: %+v", res4)
	}

	// Case 5: Resource Owner Match -> ALLOW when SubjectID == ResourceOwnerID, DENY otherwise
	res5Allow := Evaluate(EvalRequest{
		SubjectID:       "usr_77",
		Roles:           []string{"developer"},
		Action:          "profile:update",
		Resource:        "user:profile/usr_77",
		ResourceOwnerID: "usr_77",
	}, roles, policies)
	if !res5Allow.Allowed {
		t.Fatalf("Case 5a expected ALLOW for matching resource owner, got: %+v", res5Allow)
	}

	res5Deny := Evaluate(EvalRequest{
		SubjectID:       "usr_77",
		Roles:           []string{"developer"},
		Action:          "profile:update",
		Resource:        "user:profile/usr_99",
		ResourceOwnerID: "usr_99",
	}, roles, policies)
	if res5Deny.Allowed {
		t.Fatalf("Case 5b expected DENY for mismatched resource owner, got: %+v", res5Deny)
	}
}
