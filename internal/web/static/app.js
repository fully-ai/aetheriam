// AetherIAM Security & Identity Governance Console Logic
const state = {
  lastIssuedToken: "",
};

const tabMeta = {
  overview: {
    title: "Overview Dashboard",
    subtitle: "Real-time OIDC/JWKS telemetry, hybrid RBAC/ABAC governance & cryptographic audit chain",
  },
  users: {
    title: "Users & Identities",
    subtitle: "Manage identities, salted PBKDF2-SHA256 credentials, department attributes & MFA enforcement",
  },
  policies: {
    title: "RBAC / ABAC Policies",
    subtitle: "Configure role permission matrices and contextual attribute-based access rules",
  },
  simulator: {
    title: "Interactive Policy Simulator",
    subtitle: "Execute deterministic zero-trust policy evaluations with granular step-by-step explanation traces",
  },
  clients: {
    title: "OAuth2 Clients & Scoped API Keys",
    subtitle: "Provision OIDC applications and SHA-256 fingerprinted programmatic aiam_ tokens",
  },
  audit: {
    title: "Tamper-Evident Hash-Chained Audit Ledger",
    subtitle: "Inspect immutable SHA-256 linked governance events from GENESIS to current head",
  },
  backup: {
    title: "Transactional WAL Backup & Restore",
    subtitle: "Export verifiable JSON state snapshots or perform live atomic state recovery",
  },
};

function showToast(msg) {
  const container = document.getElementById("toastContainer");
  const el = document.createElement("div");
  el.className = "toast";
  el.textContent = msg;
  container.appendChild(el);
  setTimeout(() => el.remove(), 3500);
}

async function apiFetch(path, options = {}) {
  const res = await fetch(path, {
    headers: { "Content-Type": "application/json", ...(options.headers || {}) },
    ...options,
  });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    throw new Error(data.error_description || data.error || `HTTP ${res.status}`);
  }
  return data;
}

function escapeHTML(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;");
}

// Navigation & Modals
document.querySelectorAll("#sidebarNav .nav-item").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll("#sidebarNav .nav-item").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    const tab = btn.dataset.tab;
    document.getElementById(`tab-${tab}`).classList.add("active");
    document.getElementById("pageTitle").textContent = tabMeta[tab].title;
    document.getElementById("pageSubtitle").textContent = tabMeta[tab].subtitle;
  });
});

document.querySelectorAll("[data-close]").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.getElementById(btn.dataset.close).classList.add("hidden");
  });
});

document.getElementById("themeToggleBtn").addEventListener("click", () => {
  const html = document.documentElement;
  const next = html.getAttribute("data-theme") === "dark" ? "light" : "dark";
  html.setAttribute("data-theme", next);
});

// Load Stats & Overview
async function loadStats() {
  const s = await apiFetch("/api/v1/stats");
  document.getElementById("statUsersTotal").textContent = s.users_total;
  document.getElementById("statUsersMFA").textContent = s.users_mfa;
  document.getElementById("statPoliciesTotal").textContent = s.policies_total;
  document.getElementById("statRolesTotal").textContent = s.roles_total;
  document.getElementById("statPoliciesDeny").textContent = s.policies_deny;
  document.getElementById("statCredsTotal").textContent = (s.clients_total || 0) + (s.apikeys_total || 0);
  document.getElementById("statTokensIssued").textContent = s.tokens_issued || 0;
  document.getElementById("statAuditTotal").textContent = s.audit_entries;
  document.getElementById("activeKidBadge").textContent = `KID: ${s.active_kid}`;

  const chainText = s.audit_chain_valid
    ? `SHA-256 Chain Intact (${s.audit_verified_count} links)`
    : `Chain Tampered at ${s.audit_broken_at}`;
  document.getElementById("statAuditIntegrity").textContent = chainText;
  document.getElementById("sidebarChainText").textContent = chainText;
}

// OIDC & JWKS Discovery
async function loadDiscovery(path) {
  const data = await apiFetch(path);
  document.getElementById("discoveryOutput").textContent = JSON.stringify(data, null, 2);
}

document.getElementById("loadOIDCBtn").addEventListener("click", () => loadDiscovery("/.well-known/openid-configuration"));
document.getElementById("loadJWKSBtn").addEventListener("click", () => loadDiscovery("/.well-known/jwks.json"));

// Quick OAuth2 Token Sandbox
document.getElementById("qtGrantType").addEventListener("change", (e) => {
  if (e.target.value === "client_credentials") {
    document.getElementById("qtPrincipal").value = "aether-console-client";
    document.getElementById("qtSecret").value = "acs_demo_console_secret_2026";
  } else {
    document.getElementById("qtPrincipal").value = "admin";
    document.getElementById("qtSecret").value = "AetherAdmin!2026";
  }
});

document.getElementById("quickTokenForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const grantType = document.getElementById("qtGrantType").value;
  const alg = document.getElementById("qtAlg").value;
  const principal = document.getElementById("qtPrincipal").value.trim();
  const secret = document.getElementById("qtSecret").value.trim();

  const payload =
    grantType === "client_credentials"
      ? { grant_type: grantType, client_id: principal, client_secret: secret, signing_alg: alg }
      : { grant_type: grantType, username: principal, password: secret, signing_alg: alg };

  try {
    const res = await apiFetch("/api/v1/auth/token", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    state.lastIssuedToken = res.access_token;
    document.getElementById("quickTokenOutput").textContent = JSON.stringify(res, null, 2);
    showToast(`Issued ${res.signing_alg} JWT access_token`);
    loadStats();
    loadAudit();
  } catch (err) {
    document.getElementById("quickTokenOutput").textContent = `Error: ${err.message}`;
    showToast(`Token Error: ${err.message}`);
  }
});

document.getElementById("verifyIssuedTokenBtn").addEventListener("click", async () => {
  if (!state.lastIssuedToken) {
    showToast("Issue a JWT token first");
    return;
  }
  try {
    const res = await apiFetch("/api/v1/auth/verify", {
      method: "POST",
      body: JSON.stringify({ token: state.lastIssuedToken }),
    });
    document.getElementById("quickTokenOutput").textContent = JSON.stringify(res, null, 2);
    showToast("JWT signature & expiration verified");
  } catch (err) {
    showToast(`Verify failed: ${err.message}`);
  }
});

// Users & Identities
async function loadUsers() {
  const q = document.getElementById("userSearchInput").value.trim();
  const dept = document.getElementById("userDeptFilter").value;
  const data = await apiFetch(`/api/v1/users?q=${encodeURIComponent(q)}&department=${encodeURIComponent(dept)}`);
  const tbody = document.getElementById("usersTableBody");
  tbody.innerHTML = data.items
    .map(
      (u) => `
    <tr>
      <td>
        <strong>${escapeHTML(u.username)}</strong>
        <div class="muted">${escapeHTML(u.full_name)} • ${escapeHTML(u.email)}</div>
      </td>
      <td><span class="badge badge-indigo">${escapeHTML(u.department)}</span></td>
      <td>${(u.roles || []).map((r) => `<span class="tag">${escapeHTML(r)}</span>`).join(" ")}</td>
      <td>${u.mfa_enabled ? '<span class="badge badge-emerald">MFA Verified</span>' : '<span class="badge badge-amber">No MFA</span>'}</td>
      <td><span class="badge badge-emerald">${escapeHTML(u.status)}</span></td>
      <td class="muted">${escapeHTML((u.created_at || "").slice(0, 10))}</td>
      <td>
        <button class="btn btn-danger btn-sm" onclick="deleteUser('${escapeHTML(u.id)}')">Delete</button>
      </td>
    </tr>`
    )
    .join("");
}

window.deleteUser = async function (id) {
  try {
    await apiFetch(`/api/v1/users/${id}`, { method: "DELETE" });
    showToast(`Deleted user ${id}`);
    loadUsers();
    loadStats();
    loadAudit();
  } catch (err) {
    showToast(err.message);
  }
};

document.getElementById("userSearchInput").addEventListener("input", loadUsers);
document.getElementById("userDeptFilter").addEventListener("change", loadUsers);
document.getElementById("openUserModalBtn").addEventListener("click", () => {
  document.getElementById("userModal").classList.remove("hidden");
});

document.getElementById("createUserForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = {
    username: document.getElementById("newUsername").value.trim(),
    email: document.getElementById("newEmail").value.trim(),
    full_name: document.getElementById("newFullName").value.trim(),
    password: document.getElementById("newPassword").value,
    department: document.getElementById("newDepartment").value,
    roles: document
      .getElementById("newRoles")
      .value.split(",")
      .map((s) => s.trim())
      .filter(Boolean),
    mfa_enabled: document.getElementById("newMFA").checked,
  };
  try {
    await apiFetch("/api/v1/users", { method: "POST", body: JSON.stringify(payload) });
    document.getElementById("userModal").classList.add("hidden");
    e.target.reset();
    showToast(`Provisioned identity ${payload.username}`);
    loadUsers();
    loadStats();
    loadAudit();
  } catch (err) {
    showToast(err.message);
  }
});

// Roles & Policies
async function loadPoliciesAndRoles() {
  const effect = document.getElementById("policyEffectFilter").value;
  const [polData, roleData] = await Promise.all([
    apiFetch(`/api/v1/policies?effect=${encodeURIComponent(effect)}`),
    apiFetch("/api/v1/roles"),
  ]);

  const polContainer = document.getElementById("policiesList");
  polContainer.innerHTML = polData.items
    .map((p) => {
      const isDeny = p.effect.toLowerCase() === "deny";
      const conds = [];
      if (p.condition?.require_mfa) conds.push("MFA=true");
      if (p.condition?.owner_match) conds.push("OwnerMatch=true");
      if (p.condition?.allowed_cidrs?.length) conds.push(`CIDR: ${p.condition.allowed_cidrs.join(",")}`);
      if (p.condition?.departments?.length) conds.push(`Dept: ${p.condition.departments.join(",")}`);
      if (p.condition?.environments?.length) conds.push(`Env: ${p.condition.environments.join(",")}`);
      return `
      <div class="entity-card">
        <div class="entity-card-header">
          <div>
            <span class="badge ${isDeny ? "badge-rose" : "badge-emerald"}">${escapeHTML(p.effect.toUpperCase())}</span>
            <strong>${escapeHTML(p.name)}</strong>
            <span class="tag">Priority ${p.priority}</span>
          </div>
          <button class="btn btn-danger btn-sm" onclick="deletePolicy('${escapeHTML(p.id)}')">Delete</button>
        </div>
        <div class="muted">${escapeHTML(p.description || "")}</div>
        <div class="tag-list">
          <span class="tag">Roles: ${(p.roles || []).join(", ")}</span>
          <span class="tag">Actions: ${(p.actions || []).join(", ")}</span>
          <span class="tag">Resources: ${(p.resources || []).join(", ")}</span>
          ${conds.map((c) => `<span class="tag">${escapeHTML(c)}</span>`).join("")}
        </div>
      </div>`;
    })
    .join("");

  const roleContainer = document.getElementById("rolesList");
  roleContainer.innerHTML = roleData.items
    .map(
      (r) => `
      <div class="entity-card">
        <div class="entity-card-header">
          <div>
            <span class="badge badge-violet">${escapeHTML(r.name)}</span>
            <span class="muted">${escapeHTML(r.id)}</span>
          </div>
          <button class="btn btn-danger btn-sm" onclick="deleteRole('${escapeHTML(r.id)}')">Delete</button>
        </div>
        <div class="muted">${escapeHTML(r.description)}</div>
        <div class="tag-list">
          ${(r.permissions || []).map((perm) => `<span class="tag">${escapeHTML(perm)}</span>`).join("")}
        </div>
      </div>`
    )
    .join("");
}

window.deletePolicy = async function (id) {
  try {
    await apiFetch(`/api/v1/policies/${id}`, { method: "DELETE" });
    showToast(`Deleted policy ${id}`);
    loadPoliciesAndRoles();
    loadStats();
    loadAudit();
  } catch (err) {
    showToast(err.message);
  }
};

window.deleteRole = async function (id) {
  try {
    await apiFetch(`/api/v1/roles/${id}`, { method: "DELETE" });
    showToast(`Deleted role ${id}`);
    loadPoliciesAndRoles();
    loadStats();
  } catch (err) {
    showToast(err.message);
  }
};

document.getElementById("policyEffectFilter").addEventListener("change", loadPoliciesAndRoles);
document.getElementById("openPolicyModalBtn").addEventListener("click", () => {
  document.getElementById("policyModal").classList.remove("hidden");
});
document.getElementById("openRoleModalBtn").addEventListener("click", () => {
  document.getElementById("roleModal").classList.remove("hidden");
});

const splitCSV = (v) =>
  v
    .split(",")
    .map((s) => s.trim())
    .filter(Boolean);

document.getElementById("createPolicyForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = {
    name: document.getElementById("polName").value.trim(),
    effect: document.getElementById("polEffect").value,
    priority: parseInt(document.getElementById("polPriority").value, 10) || 50,
    roles: splitCSV(document.getElementById("polRoles").value),
    actions: splitCSV(document.getElementById("polActions").value),
    resources: splitCSV(document.getElementById("polResources").value),
    enabled: true,
    condition: {
      allowed_cidrs: splitCSV(document.getElementById("polCIDRs").value),
      departments: splitCSV(document.getElementById("polDepts").value),
      environments: splitCSV(document.getElementById("polEnvs").value),
      require_mfa: document.getElementById("polMFA").checked,
    },
  };
  try {
    await apiFetch("/api/v1/policies", { method: "POST", body: JSON.stringify(payload) });
    document.getElementById("policyModal").classList.add("hidden");
    showToast(`Created policy ${payload.name}`);
    loadPoliciesAndRoles();
    loadStats();
    loadAudit();
  } catch (err) {
    showToast(err.message);
  }
});

document.getElementById("createRoleForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = {
    name: document.getElementById("roleName").value.trim(),
    description: document.getElementById("roleDesc").value.trim(),
    permissions: splitCSV(document.getElementById("rolePerms").value),
  };
  try {
    await apiFetch("/api/v1/roles", { method: "POST", body: JSON.stringify(payload) });
    document.getElementById("roleModal").classList.add("hidden");
    showToast(`Saved role ${payload.name}`);
    loadPoliciesAndRoles();
    loadStats();
  } catch (err) {
    showToast(err.message);
  }
});

// Interactive Policy Simulator
const simPresets = {
  sre_allow: {
    username: "elena.vance",
    subject_id: "usr_elena",
    roles: "sre_lead",
    department: "Platform",
    action: "infra:deploy",
    resource: "arn:aether:prod:k8s-eu-west",
    ip: "10.24.0.15",
    env: "production",
    owner: "usr_elena",
    mfa: true,
  },
  ip_deny: {
    username: "elena.vance",
    subject_id: "usr_elena",
    roles: "sre_lead",
    department: "Platform",
    action: "infra:deploy",
    resource: "arn:aether:prod:k8s-eu-west",
    ip: "203.0.113.42",
    env: "production",
    owner: "usr_elena",
    mfa: true,
  },
  no_mfa: {
    username: "elena.vance",
    subject_id: "usr_elena",
    roles: "sre_lead",
    department: "Platform",
    action: "infra:deploy",
    resource: "arn:aether:prod:k8s-eu-west",
    ip: "10.24.0.15",
    env: "production",
    owner: "usr_elena",
    mfa: false,
  },
  owner_match: {
    username: "aria.patel",
    subject_id: "usr_aria",
    roles: "developer",
    department: "Engineering",
    action: "profile:update",
    resource: "user:profile/usr_aria",
    ip: "172.16.0.10",
    env: "production",
    owner: "usr_aria",
    mfa: false,
  },
};

document.querySelectorAll("[data-preset]").forEach((btn) => {
  btn.addEventListener("click", () => {
    const p = simPresets[btn.dataset.preset];
    if (!p) return;
    document.getElementById("simUsername").value = p.username;
    document.getElementById("simSubjectId").value = p.subject_id;
    document.getElementById("simRoles").value = p.roles;
    document.getElementById("simDepartment").value = p.department;
    document.getElementById("simAction").value = p.action;
    document.getElementById("simResource").value = p.resource;
    document.getElementById("simIP").value = p.ip;
    document.getElementById("simEnv").value = p.env;
    document.getElementById("simOwnerId").value = p.owner;
    document.getElementById("simMFA").checked = p.mfa;
    document.getElementById("simulatorForm").requestSubmit();
  });
});

document.getElementById("simulatorForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = {
    username: document.getElementById("simUsername").value.trim(),
    subject_id: document.getElementById("simSubjectId").value.trim(),
    roles: splitCSV(document.getElementById("simRoles").value),
    department: document.getElementById("simDepartment").value.trim(),
    action: document.getElementById("simAction").value.trim(),
    resource: document.getElementById("simResource").value.trim(),
    ip_address: document.getElementById("simIP").value.trim(),
    environment: document.getElementById("simEnv").value,
    resource_owner_id: document.getElementById("simOwnerId").value.trim(),
    mfa_verified: document.getElementById("simMFA").checked,
  };

  try {
    const res = await apiFetch("/api/v1/policies/evaluate", {
      method: "POST",
      body: JSON.stringify(payload),
    });
    const badge = document.getElementById("simDecisionBadge");
    badge.textContent = `${res.decision} (${res.duration_micros} µs)`;
    badge.className = `badge ${res.allowed ? "badge-emerald" : "badge-rose"}`;

    document.getElementById("simSummaryBox").innerHTML = `
      <div><strong>Decision:</strong> ${escapeHTML(res.decision)} ${
      res.matched_policy_name ? `• Matched Policy: <code>${escapeHTML(res.matched_policy_name)}</code>` : ""
    }</div>
      <div><strong>Reason:</strong> ${escapeHTML(res.reason)}</div>
      <div class="muted">RBAC Role Grant: ${res.rbac_granted ? `YES (${escapeHTML(res.rbac_matched_role)} → ${escapeHTML(res.rbac_matched_permission)})` : "NO"}</div>
    `;

    document.getElementById("simTraceBody").innerHTML = (res.trace || [])
      .map(
        (step) => `
      <tr>
        <td><span class="tag">${escapeHTML(step.phase)}</span></td>
        <td><strong>${escapeHTML(step.rule_name || step.rule_id)}</strong></td>
        <td><span class="badge ${step.effect === "DENY" ? "badge-rose" : "badge-indigo"}">${escapeHTML(step.effect)}</span></td>
        <td>${step.matched ? '<span class="badge badge-emerald">MATCHED</span>' : '<span class="badge badge-amber">SKIPPED</span>'}</td>
        <td class="muted">${escapeHTML(step.reason)}</td>
      </tr>`
      )
      .join("");
    loadStats();
    loadAudit();
  } catch (err) {
    showToast(err.message);
  }
});

// OAuth2 Clients & API Keys
async function loadClientsAndKeys() {
  const [cliData, keyData] = await Promise.all([apiFetch("/api/v1/clients"), apiFetch("/api/v1/apikeys")]);

  document.getElementById("clientsList").innerHTML = cliData.items
    .map(
      (c) => `
    <div class="entity-card">
      <div class="entity-card-header">
        <div>
          <strong>${escapeHTML(c.name)}</strong>
          <span class="badge badge-indigo">${escapeHTML(c.signing_alg)}</span>
        </div>
        <button class="btn btn-danger btn-sm" onclick="deleteClient('${escapeHTML(c.id)}')">Delete</button>
      </div>
      <div class="muted">client_id: <code>${escapeHTML(c.client_id)}</code> • secret: <code>${escapeHTML(c.client_secret_preview)}</code></div>
      <div class="tag-list">
        ${(c.grant_types || []).map((g) => `<span class="tag">${escapeHTML(g)}</span>`).join("")}
        ${(c.scopes || []).map((s) => `<span class="tag">${escapeHTML(s)}</span>`).join("")}
      </div>
    </div>`
    )
    .join("");

  document.getElementById("apiKeysList").innerHTML = keyData.items
    .map(
      (k) => `
    <div class="entity-card">
      <div class="entity-card-header">
        <div>
          <strong>${escapeHTML(k.name)}</strong>
          <span class="badge badge-emerald">${escapeHTML(k.key_prefix)}</span>
        </div>
        <button class="btn btn-danger btn-sm" onclick="deleteAPIKey('${escapeHTML(k.id)}')">Revoke</button>
      </div>
      <div class="tag-list">
        <span class="tag">Roles: ${(k.roles || []).join(", ")}</span>
        <span class="tag">Scopes: ${(k.scopes || []).join(", ")}</span>
        <span class="tag">${k.rate_limit_rps} RPS</span>
      </div>
    </div>`
    )
    .join("");
}

window.deleteClient = async function (id) {
  await apiFetch(`/api/v1/clients/${id}`, { method: "DELETE" });
  showToast(`Deleted OAuth2 client ${id}`);
  loadClientsAndKeys();
  loadStats();
};

window.deleteAPIKey = async function (id) {
  await apiFetch(`/api/v1/apikeys/${id}`, { method: "DELETE" });
  showToast(`Revoked API key ${id}`);
  loadClientsAndKeys();
  loadStats();
};

document.getElementById("openClientModalBtn").addEventListener("click", () => {
  document.getElementById("clientModal").classList.remove("hidden");
});
document.getElementById("openAPIKeyModalBtn").addEventListener("click", () => {
  document.getElementById("apiKeyModal").classList.remove("hidden");
});

document.getElementById("createClientForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = {
    name: document.getElementById("cliName").value.trim(),
    client_id: document.getElementById("cliClientId").value.trim(),
    signing_alg: document.getElementById("cliAlg").value,
    scopes: splitCSV(document.getElementById("cliScopes").value),
    default_roles: splitCSV(document.getElementById("cliRoles").value),
  };
  try {
    const res = await apiFetch("/api/v1/clients", { method: "POST", body: JSON.stringify(payload) });
    document.getElementById("clientModal").classList.add("hidden");
    const banner = document.getElementById("secretBanner");
    banner.classList.remove("hidden");
    banner.textContent = `New OAuth2 Client Registered! client_id: ${res.client.client_id} | client_secret (save now): ${res.client_secret}`;
    loadClientsAndKeys();
    loadStats();
  } catch (err) {
    showToast(err.message);
  }
});

document.getElementById("createAPIKeyForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = {
    name: document.getElementById("keyName").value.trim(),
    scopes: splitCSV(document.getElementById("keyScopes").value),
    roles: splitCSV(document.getElementById("keyRoles").value),
  };
  try {
    const res = await apiFetch("/api/v1/apikeys", { method: "POST", body: JSON.stringify(payload) });
    document.getElementById("apiKeyModal").classList.add("hidden");
    const banner = document.getElementById("secretBanner");
    banner.classList.remove("hidden");
    banner.textContent = `New Scoped API Key Generated (save now — stored only as SHA-256 hash): ${res.raw_key}`;
    loadClientsAndKeys();
    loadStats();
  } catch (err) {
    showToast(err.message);
  }
});

// Audit Ledger
async function loadAudit() {
  const q = document.getElementById("auditSearchInput").value.trim();
  const sev = document.getElementById("auditSeverityFilter").value;
  const out = document.getElementById("auditOutcomeFilter").value;
  const data = await apiFetch(
    `/api/v1/audit?q=${encodeURIComponent(q)}&severity=${encodeURIComponent(sev)}&outcome=${encodeURIComponent(out)}`
  );

  const banner = document.getElementById("auditIntegrityBanner");
  banner.innerHTML = data.chain_integrity
    ? `<span class="badge badge-emerald">✓ SHA-256 HASH CHAIN VERIFIED (${data.chain_verified_count} immutable blocks)</span>`
    : `<span class="badge badge-rose">✗ HASH CHAIN BROKEN AT ${escapeHTML(data.chain_broken_at)}</span>`;

  document.getElementById("auditTableBody").innerHTML = (data.items || [])
    .map(
      (a) => `
    <tr>
      <td><code>#${a.sequence}</code></td>
      <td class="muted">${escapeHTML(a.timestamp)}</td>
      <td><strong>${escapeHTML(a.actor)}</strong></td>
      <td><code>${escapeHTML(a.action)}</code></td>
      <td>${escapeHTML(a.resource)}</td>
      <td><span class="badge ${a.outcome === "DENY" ? "badge-rose" : "badge-emerald"}">${escapeHTML(a.outcome)}</span></td>
      <td>
        <div class="tag" title="Prev: ${escapeHTML(a.prev_hash)} → Curr: ${escapeHTML(a.hash)}">
          ${escapeHTML(a.prev_hash.slice(0, 10))}… → ${escapeHTML(a.hash.slice(0, 14))}…
        </div>
        <div class="muted">${escapeHTML(a.details)}</div>
      </td>
    </tr>`
    )
    .join("");
}

document.getElementById("filterAuditBtn").addEventListener("click", loadAudit);
document.getElementById("auditSearchInput").addEventListener("input", loadAudit);

// Backup & Restore
document.getElementById("previewBackupBtn").addEventListener("click", async () => {
  const data = await apiFetch("/api/v1/admin/backup");
  const formatted = JSON.stringify(data, null, 2);
  document.getElementById("backupPreviewBox").textContent = formatted;
  document.getElementById("restoreJsonInput").value = formatted;
  showToast("Loaded transactional snapshot into preview & restore editor");
});

document.getElementById("downloadBackupBtn").addEventListener("click", () => {
  window.location.href = "/api/v1/admin/backup";
});

document.getElementById("executeRestoreBtn").addEventListener("click", async () => {
  const raw = document.getElementById("restoreJsonInput").value.trim();
  if (!raw) {
    showToast("Paste or load a snapshot JSON payload first");
    return;
  }
  try {
    await apiFetch("/api/v1/admin/restore", { method: "POST", body: raw });
    showToast("Snapshot restored & secondary indexes rebuilt!");
    refreshAll();
  } catch (err) {
    showToast(`Restore failed: ${err.message}`);
  }
});

async function refreshAll() {
  await Promise.all([
    loadStats(),
    loadDiscovery("/.well-known/jwks.json"),
    loadUsers(),
    loadPoliciesAndRoles(),
    loadClientsAndKeys(),
    loadAudit(),
  ]);
}

document.getElementById("refreshAllBtn").addEventListener("click", () => {
  refreshAll();
  showToast("Synchronized console with AetherIAM store");
});

window.addEventListener("DOMContentLoaded", () => {
  refreshAll();
});
