#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-http://localhost:8002/api}"

echo "Loading enterprise CRVM demo data into ${API_BASE} ..."

node <<'NODE'
const API = process.env.API_BASE || "http://localhost:8002/api";

const findings = [
  {
    source: "tenable",
    source_id: "TENABLE-203948-CVE-2025-24813",
    title: "Apache Tomcat RCE on internet-facing claims portal",
    severity: "CRITICAL",
    cve: "CVE-2025-24813",
    category: "vulnerability",
    scanner_severity: "Critical",
    exploit_available: true,
    active_exploitation: true,
    patch_available: true,
    description: "Public exploit path from external edge through vulnerable Tomcat upload handling into a production claims service.",
    metadata: { cvss: 9.8, epss: 0.94, kev: true, mitre: "T1190,T1505", ransomware: "initial-access-broker" },
    asset: { external_id: "app-claims-web-prod-01", name: "Claims Web Portal", type: "WEB_APP", environment: "PRODUCTION", provider: "aws", region: "us-east-1", criticality: 5, data_sensitivity: 5, internet_exposure: true, owner: "claims-platform", compliance_scope: "PCI,SOC2", tags: { service: "claims", tier: "edge" } }
  },
  {
    source: "wiz",
    source_id: "WIZ-IAM-7781",
    title: "Over-privileged deployment role can administer production account",
    severity: "CRITICAL",
    category: "iam_policy",
    control_id: "AWS-IAM-ADMIN-WILDCARD",
    scanner_severity: "Critical",
    exploit_available: true,
    active_exploitation: false,
    patch_available: true,
    description: "Deployment role grants wildcard IAM and CloudFormation privileges and is reachable from CI/CD runner identity.",
    metadata: { cloud: "aws", account: "prod-security", toxic_combination: "ci_runner_token,iam_admin,production_account", epss: 0.86, mitre: "T1098,T1078" },
    asset: { external_id: "iam-prod-deploy-role", name: "Prod Deploy IAM Role", type: "IAM_ROLE", environment: "PRODUCTION", provider: "aws", region: "global", criticality: 5, data_sensitivity: 4, internet_exposure: false, owner: "platform-engineering", compliance_scope: "SOC2", tags: { service: "platform", privilege: "admin" } }
  },
  {
    source: "github-advanced-security",
    source_id: "GHAS-SECRET-991",
    title: "Production database credential exposed in build logs",
    severity: "CRITICAL",
    category: "secrets",
    scanner_severity: "Critical",
    exploit_available: true,
    active_exploitation: true,
    patch_available: true,
    description: "Secret scanning found a live production database credential in CI logs with successful authentication telemetry.",
    metadata: { secret_type: "postgres_password", rotation_required: true, epss: 0.91, mitre: "T1552,T1078" },
    asset: { external_id: "github-actions-prod-runner", name: "GitHub Actions Production Runner", type: "CI_CD", environment: "PRODUCTION", provider: "github", region: "global", criticality: 5, data_sensitivity: 5, internet_exposure: true, owner: "devsecops", compliance_scope: "SOC2", tags: { service: "ci-cd", runner: "prod" } }
  },
  {
    source: "prisma-cloud",
    source_id: "PCC-K8S-4420",
    title: "Privileged Kubernetes workload mounts host filesystem",
    severity: "HIGH",
    category: "kubernetes_policy",
    scanner_severity: "High",
    exploit_available: true,
    active_exploitation: false,
    patch_available: true,
    description: "Privileged pod in production namespace can mount hostPath and access node credentials.",
    metadata: { cluster: "eks-prod-payments", namespace: "payments", epss: 0.72, mitre: "T1611,T1613" },
    asset: { external_id: "eks-prod-payments", name: "EKS Payments Cluster", type: "KUBERNETES_CLUSTER", environment: "PRODUCTION", provider: "aws", region: "us-east-1", criticality: 5, data_sensitivity: 5, internet_exposure: false, owner: "payments-platform", compliance_scope: "PCI", tags: { service: "payments", cluster: "eks" } }
  },
  {
    source: "aws-security-hub",
    source_id: "SH-S3-1129",
    title: "Customer document bucket allows cross-account read through stale policy",
    severity: "HIGH",
    category: "cloud_control",
    control_id: "S3-BUCKET-POLICY-STALE-XACCOUNT",
    scanner_severity: "High",
    exploit_available: false,
    active_exploitation: false,
    patch_available: true,
    description: "S3 bucket policy grants read access to retired vendor account and contains regulated customer documents.",
    metadata: { bucket: "prod-customer-documents", data: "regulated-documents", epss: 0.55, mitre: "T1530" },
    asset: { external_id: "s3-prod-customer-documents", name: "Customer Documents S3", type: "DATA_STORE", environment: "PRODUCTION", provider: "aws", region: "us-east-1", criticality: 5, data_sensitivity: 5, internet_exposure: false, owner: "data-platform", compliance_scope: "SOC2,HIPAA", tags: { service: "documents", data: "regulated" } }
  },
  {
    source: "crowdstrike",
    source_id: "CS-EDR-31002",
    title: "Suspicious lateral movement from admin jump host",
    severity: "HIGH",
    category: "endpoint",
    scanner_severity: "High",
    exploit_available: true,
    active_exploitation: true,
    patch_available: false,
    description: "EDR observed remote service creation and credential access pattern from jump host into production subnet.",
    metadata: { tactic: "lateral_movement", technique: "remote-service", epss: 0.83, mitre: "T1021,T1003" },
    asset: { external_id: "jump-admin-prod-01", name: "Production Admin Jump Host", type: "VM", environment: "PRODUCTION", provider: "azure", region: "eastus", criticality: 4, data_sensitivity: 4, internet_exposure: true, owner: "infra-ops", compliance_scope: "SOC2", tags: { service: "admin", subnet: "prod-admin" } }
  },
  {
    source: "snyk",
    source_id: "SNYK-JS-NEXT-501",
    title: "Critical vulnerable package in customer API image",
    severity: "HIGH",
    category: "container",
    scanner_severity: "High",
    exploit_available: true,
    active_exploitation: false,
    patch_available: true,
    description: "Container image includes vulnerable transitive dependency with SSRF-to-metadata-service escalation.",
    metadata: { image: "customer-api:2026.05.03", package: "node-fetch", epss: 0.78, mitre: "T1190,T1552" },
    asset: { external_id: "svc-customer-api-prod", name: "Customer API Service", type: "CONTAINER_SERVICE", environment: "PRODUCTION", provider: "aws", region: "us-east-1", criticality: 5, data_sensitivity: 5, internet_exposure: true, owner: "customer-platform", compliance_scope: "SOC2", tags: { service: "customer-api", tier: "api" } }
  },
  {
    source: "qualys",
    source_id: "QID-38971",
    title: "TLS private key file readable by application user",
    severity: "MEDIUM",
    category: "configuration",
    scanner_severity: "Medium",
    exploit_available: false,
    active_exploitation: false,
    patch_available: true,
    description: "File permissions allow local application user to read TLS private key on production web node.",
    metadata: { qid: "38971", epss: 0.31, mitre: "T1552" },
    asset: { external_id: "app-claims-web-prod-02", name: "Claims Web Portal Node 2", type: "VM", environment: "PRODUCTION", provider: "aws", region: "us-east-1", criticality: 4, data_sensitivity: 4, internet_exposure: true, owner: "claims-platform", compliance_scope: "SOC2", tags: { service: "claims", tier: "edge" } }
  },
  {
    source: "defender",
    source_id: "MDE-44381",
    title: "Unsupported OS on finance batch server",
    severity: "MEDIUM",
    category: "patch",
    scanner_severity: "Medium",
    exploit_available: false,
    active_exploitation: false,
    patch_available: true,
    description: "Finance batch host runs unsupported OS build and misses EDR tamper protection baseline.",
    metadata: { os: "windows-server-2012r2", epss: 0.42, business_process: "month-end-close" },
    asset: { external_id: "fin-batch-prod-01", name: "Finance Batch Server", type: "VM", environment: "PRODUCTION", provider: "azure", region: "eastus", criticality: 4, data_sensitivity: 4, internet_exposure: false, owner: "finance-it", compliance_scope: "SOX", tags: { service: "finance", job: "batch" } }
  },
  {
    source: "servicenow-cmdb",
    source_id: "CMDB-OWNER-109",
    title: "Tier-1 payment service missing accountable owner",
    severity: "MEDIUM",
    category: "governance",
    scanner_severity: "Medium",
    exploit_available: false,
    active_exploitation: false,
    patch_available: false,
    description: "Critical production service lacks named technical owner and escalation route for urgent remediation.",
    metadata: { cmdb_ci: "payment-auth-service", sla_risk: true, governance: "owner_required" },
    asset: { external_id: "svc-payment-auth-prod", name: "Payment Auth Service", type: "SERVICE", environment: "PRODUCTION", provider: "aws", region: "us-east-1", criticality: 5, data_sensitivity: 5, internet_exposure: false, owner: "unassigned", compliance_scope: "PCI", tags: { service: "payment-auth", owner_gap: "true" } }
  }
];

const integrations = [
  { provider: "tenable-enterprise", name: "Tenable Enterprise VM", category: "scanner", auth_mode: "manual_secret_reference", endpoint: "https://tenable.example.internal", owner: "security-operations", scopes: "read:findings,read:assets", operation: "ingest_findings" },
  { provider: "wiz-cloud", name: "Wiz Cloud Security", category: "cloud", auth_mode: "manual_secret_reference", endpoint: "https://api.wiz.example.internal", owner: "cloud-security", scopes: "read:issues,read:assets,read:iam", operation: "ingest_cloud_findings" },
  { provider: "github-advanced-security", name: "GitHub Advanced Security", category: "code", auth_mode: "manual_secret_reference", endpoint: "https://api.github.com", owner: "devsecops", scopes: "repo,security_events,workflow", operation: "ingest_code_findings" },
  { provider: "crowdstrike-edr", name: "CrowdStrike Falcon EDR", category: "endpoint", auth_mode: "manual_secret_reference", endpoint: "https://api.crowdstrike.example.internal", owner: "soc", scopes: "hosts:read,detections:read", operation: "ingest_endpoint_findings" }
];

async function request(path, body) {
  const response = await fetch(`${API}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body ?? {})
  });
  if (!response.ok) throw new Error(`${path} ${response.status}: ${await response.text()}`);
  return response.json();
}

async function get(path) {
  const response = await fetch(`${API}${path}`);
  if (!response.ok) throw new Error(`${path} ${response.status}: ${await response.text()}`);
  return response.json();
}

console.log("1/6 Ingesting enterprise scanner and posture findings...");
console.log(await request("/ingest/json", { findings }));

console.log("2/6 Appending enterprise integrations...");
for (const integration of integrations) {
  await request("/integrations", integration);
}

console.log("3/6 Activating virtual patching, agent planning, CRVM and path snapshots...");
await request("/virtual-patching", { action: "activate" });
await request("/agentic", { goal: "reduce highest-risk attack paths", prompt: "Plan governed path breakers for exploited production attack paths.", dry_run: true });
await request("/attack-paths", { action: "snapshot" });
await request("/crvm/snapshot", { action: "board_snapshot" });

console.log("4/6 Creating simulations, remediation plans, and approval workflows...");
const actions = (await get("/remediation-actions")).actions || [];
for (const action of actions.slice(0, 6)) {
  await request(`/remediation-actions/${action._id}/simulate`, {});
  await request(`/remediation-actions/${action._id}/plan`, {});
  await request(`/remediation-actions/${action._id}/workflow`, {});
}

console.log("5/6 Running connector dry checks...");
for (const integration of integrations) {
  await request("/connectors/live", { provider: integration.provider, operation: integration.operation, dry_run: true, payload: { demo: true, mode: "health_check" } });
}

console.log("6/6 Verifying loaded demo state...");
const dashboard = await get("/dashboard");
const attackPaths = await get("/attack-paths");
const crvm = await get("/crvm");
console.log(JSON.stringify({
  assets: dashboard.counts.assets,
  open_findings: dashboard.counts.open_findings,
  remediation_actions: dashboard.counts.remediation_actions,
  simulations: dashboard.counts.simulations,
  workflows: dashboard.counts.workflows,
  attack_paths: attackPaths.attack_paths?.summary?.total_paths || attackPaths.attack_paths?.paths?.length || 0,
  crvm_discovered_assets: crvm.crvm?.exposure_intelligence?.discovered_assets,
  crvm_internet_exposed_assets: crvm.crvm?.exposure_intelligence?.internet_exposed_assets
}, null, 2));
NODE
