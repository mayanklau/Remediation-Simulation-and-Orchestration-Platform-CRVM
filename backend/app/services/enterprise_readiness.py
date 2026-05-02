from typing import Any, Literal

ReadinessStatus = Literal["implemented", "contract_ready", "external_setup_required"]


def _control(control_id: str, name: str, status: ReadinessStatus) -> dict[str, str]:
    evidence = {
        "implemented": "Implemented in application logic and covered by current tests/builds.",
        "contract_ready": "Application contract exists; wire customer-specific external systems and credentials.",
        "external_setup_required": "Requires customer infrastructure, cloud account, regional deployment, or security service configuration.",
    }[status]
    return {"id": control_id, "name": name, "status": status, "evidence": evidence}


def _category(category_id: str, name: str, owner: str, controls: list[tuple[str, str, ReadinessStatus]]) -> dict[str, Any]:
    return {"id": category_id, "name": name, "owner": owner, "controls": [_control(*control) for control in controls]}


ENTERPRISE_READINESS_CATALOG: list[dict[str, Any]] = [
    _category("identity_access_tenancy", "Identity, Access, And Tenancy", "security-platform", [
        ("oidc_sso", "OIDC, SAML, Azure AD, Okta, Google Workspace, generic IdP contract", "contract_ready"),
        ("scim_lifecycle", "SCIM provisioning, user lifecycle, group-to-role mapping", "contract_ready"),
        ("tenant_rbac", "Tenant isolation, cross-tenant denial tests, RBAC on APIs/routes/buttons/service accounts/API keys", "implemented"),
        ("session_support", "Session expiry, renewal, refresh-token strategy, break-glass audit, support impersonation controls", "contract_ready"),
    ]),
    _category("secrets_credentials", "Secrets And Credentials", "platform-security", [
        ("secret_references", "Vault, AWS Secrets Manager, Azure Key Vault, GCP Secret Manager references", "contract_ready"),
        ("no_raw_secrets", "No raw secret storage, masked display, secret access audit", "implemented"),
        ("credential_lifecycle", "Validation, rotation, expiry, OAuth refresh, connector health checks", "contract_ready"),
        ("customer_keys", "Customer-managed keys, BYOK, field-level encryption, encryption at rest and transit", "external_setup_required"),
    ]),
    _category("connectors_integrations", "Connectors And Integrations", "integration-engineering", [
        ("manual_connector_builder", "Manual/custom HTTP connector builder, dry-run/live modes, health and run history", "implemented"),
        ("connector_runtime", "Retries, backoff, dead-letter queues, sync scheduler, trust/data-quality scores", "contract_ready"),
        ("scanner_cloud_edr", "Tenable, Qualys, Rapid7, Wiz, Prisma Cloud, Lacework, Snyk, GHAS, GitLab, AWS, GCP, Azure, Defender, CrowdStrike, SentinelOne", "contract_ready"),
        ("work_management", "ServiceNow, Jira, GitHub Issues, Azure DevOps, Slack, Teams, Email, CMDB, CAB calendar", "contract_ready"),
        ("webhook_sdk", "Webhook signatures, mapping UI, normalization contracts, connector marketplace and parser SDK", "contract_ready"),
    ]),
    _category("ingestion_normalization_quality", "Ingestion, Normalization, And Data Quality", "data-platform", [
        ("ingestion_modes", "JSON, CSV, API, webhook, batch, streaming ingestion", "implemented"),
        ("mapping_lineage", "CSV/API mapping, normalization, canonical mapping, dedup explainability, finding lineage", "contract_ready"),
        ("data_quality", "Freshness, missing-field detection, confidence scoring, source quality dashboards", "contract_ready"),
        ("asset_context", "Asset resolution, merge/conflict workflow, ownership disputes, CMDB/cloud/Kubernetes/code/IAM enrichment, business-service/crown-jewel/exposure tagging", "contract_ready"),
    ]),
    _category("vulnerability_attack_paths", "Vulnerability Analytics And Attack Paths", "exposure-management", [
        ("domain_chaining", "Network, IAM, cloud, Kubernetes, app, CI/CD, secrets, data-store chaining", "implemented"),
        ("graph_algorithms", "Attack graph, shortest path, k-hop blast radius, reachability, choke points, centrality", "implemented"),
        ("preconditions", "Privilege, network access, user interaction, token scope, lateral movement, exploit availability", "implemented"),
        ("threat_intel", "EPSS, CISA KEV, threat intel, active exploitation enrichment", "contract_ready"),
        ("risk_quantification", "Difficulty, explainability, confidence, before/after risk, residual risk, FAIR-style risk dollars", "contract_ready"),
    ]),
    _category("simulation_decisioning", "Simulation And Decisioning", "remediation-governance", [
        ("control_simulation", "Patch, WAF, API gateway, IAM deny, segmentation, containers, Kubernetes, cloud policy simulation", "implemented"),
        ("risk_scoring", "Change, operational, rollback, approval, confidence, assumptions, evidence scoring", "implemented"),
        ("path_breakers", "Path-breaker recommendation, ROI, virtual patching, compensating controls, policy simulation", "implemented"),
        ("rollout_simulation", "Auto-approval, risk acceptance, progressive rollout, canary remediation", "contract_ready"),
    ]),
    _category("remediation_orchestration", "Remediation Orchestration", "security-operations", [
        ("queue_playbooks", "Queue, generated actions, playbooks, golden paths, owners, SLAs", "implemented"),
        ("campaigns", "Campaigns, blockers, waves, SLA breaches, risk reduction, freeze/maintenance windows", "implemented"),
        ("approval_exception", "CAB, service owner, security approvals, risk acceptance, exceptions, expiry, renewal", "implemented"),
        ("execution_hooks", "Dry-run/live execution, CI/CD, Kubernetes, cloud, IAM, Terraform, OPA/Rego, rollback, validation", "contract_ready"),
    ]),
    _category("ai_agentic_governance", "AI And Agentic Governance", "ai-risk", [
        ("model_routing", "LLM, SLM, local model, enterprise gateway, deterministic fallback, provider config", "implemented"),
        ("agent_safety", "Prompt/tool registry, dry-run mode, human approval, recommendation audit, confidence", "implemented"),
        ("model_risk", "Reasoning trace, decision record, policy simulator, eval harness, hallucination guardrails", "contract_ready"),
        ("prompt_security", "Prompt injection defenses, sensitive-data redaction, no secrets in prompts, connector-content sanitization", "contract_ready"),
    ]),
    _category("evidence_audit_compliance", "Evidence, Audit, And Compliance", "grc", [
        ("audit_evidence", "Full audit trail, immutable option, correlation IDs, evidence packs, chain of custody", "implemented"),
        ("evidence_exports", "Hash sealing, PDF/JSON/ZIP export, notarization, signed attestations", "contract_ready"),
        ("evidence_lifecycle", "Before state, simulation, approval, execution, validation, residual risk, legal hold, retention", "implemented"),
        ("compliance_mapping", "SOC 2, ISO 27001, NIST CSF, PCI DSS, HIPAA, FedRAMP-ready controls, DORA metrics", "contract_ready"),
    ]),
    _category("reporting_executive", "Reporting And Executive Views", "security-leadership", [
        ("dashboards", "Executive, CISO, service-owner, engineering, audit, connector, queue, production health dashboards", "implemented"),
        ("risk_reports", "Business-service, crown-jewel, attack-path closure, weekly risk reduction, blockers, SLA, exceptions", "implemented"),
        ("exports_telemetry", "Board export, evidence readiness, customer success telemetry, adoption analytics, release notes, mobile view", "contract_ready"),
        ("leadership_views", "Risk-in-dollars, exposure timeline, remediation debt, blast-radius regression, control drift", "contract_ready"),
    ]),
    _category("platform_architecture", "Platform Architecture", "architecture", [
        ("contracts", "Services, repositories, DTOs, validation, OpenAPI, versioning, generated clients", "implemented"),
        ("workers_scale", "Workers, queues, retries, idempotency, transactions, cache, migrations, index checks", "contract_ready"),
        ("resilience", "Backups, restores, fixtures, multi-tenant data strategy, data residency, regional isolation", "contract_ready"),
        ("deployment_modes", "Multi-region, active-active, DR, RPO/RTO, air-gapped, on-prem, PrivateLink", "external_setup_required"),
    ]),
    _category("security_hardening", "Security Hardening", "appsec", [
        ("api_security", "Rate limits, payload limits, CORS allowlist, CSRF where needed, headers, validation, encoding", "implemented"),
        ("runtime_security", "SSRF protection, upload validation, webhook signatures, prompt-injection protection", "contract_ready"),
        ("supply_chain", "Dependency, secret, SAST, DAST, container, SBOM, license scans, non-root containers", "contract_ready"),
        ("kubernetes_security", "Least privilege, network policies, security contexts, admission policies, disclosure policy", "external_setup_required"),
    ]),
    _category("observability_operations", "Observability And Operations", "sre", [
        ("telemetry", "Structured logs, request/correlation IDs, metrics, traces, errors, alerts, SLOs, SLIs", "implemented"),
        ("runtime_monitoring", "Synthetic monitoring, queue depth, connector failures, simulation duration, risk latency, worker/database health", "contract_ready"),
        ("operability", "Health/readiness/liveness probes, graceful shutdown, incident/DR runbooks, diagnostics, admin console", "contract_ready"),
        ("release_ops", "Feature flags, dark launches, release rollback, change logs, customer-facing status", "contract_ready"),
    ]),
    _category("testing_quality", "Testing And Quality Gates", "quality-engineering", [
        ("test_pyramid", "Unit, API, integration, database, tenant, RBAC, connector, worker, queue, frontend tests", "implemented"),
        ("advanced_tests", "E2E, accessibility, visual regression, performance, load, chaos, failover, backup/restore", "contract_ready"),
        ("contract_security_tests", "Migration, OpenAPI, security, AI eval, prompt injection, preview/staging/prod checks", "contract_ready"),
        ("ci_gates", "Lint, typecheck, tests, build, dependency, container, SBOM gates", "implemented"),
    ]),
    _category("deployment_devops", "Deployment And DevOps", "devops", [
        ("packaging", "Docker Compose, production Dockerfiles, Kubernetes manifests, Helm, Terraform, cloud examples", "contract_ready"),
        ("environments", "Local, dev, staging, production, config validation, strict production checks, CI/CD, previews", "implemented"),
        ("deployment_patterns", "Blue/green, canary, rollback, migration pipeline, secret injection, scaling guides, DR guide", "contract_ready"),
        ("secure_release", "Release rollback, diagnostic bundles, status indicators, support runbooks", "contract_ready"),
    ]),
    _category("product_experience", "Product Experience", "product-design", [
        ("onboarding", "Guided first run, admin/tenant/connector onboarding, empty/loading/error states, disabled reasons", "implemented"),
        ("productivity", "Bulk actions, saved filters, advanced search, graph filters/zoom/minimap/export/drill-down", "implemented"),
        ("exports_notifications", "CSV/PDF/JSON export, email/Slack/Teams/webhooks, preferences, feedback, in-product docs", "contract_ready"),
        ("readiness_guides", "Demo separation, customer pilot, go-live, production readiness checklists", "implemented"),
    ]),
    _category("commercial_packaging", "Commercial And Packaging", "product-operations", [
        ("editions", "Edition gating, license enforcement, usage metering, tenant/connector/model metrics", "contract_ready"),
        ("marketplace", "Marketplace packaging, plugin packaging, self-service onboarding, support access controls", "contract_ready"),
        ("customer_health", "Secure support bundle, adoption telemetry, health score, trial and enterprise modes", "contract_ready"),
        ("billing_packaging", "Customer usage, model usage, connector usage, license mode, enterprise packaging", "contract_ready"),
    ]),
]


def build_enterprise_readiness_catalog() -> dict[str, Any]:
    controls = [control for category in ENTERPRISE_READINESS_CATALOG for control in category["controls"]]
    implemented = len([control for control in controls if control["status"] == "implemented"])
    contract_ready = len([control for control in controls if control["status"] == "contract_ready"])
    external = len([control for control in controls if control["status"] == "external_setup_required"])
    return {
        "categories": ENTERPRISE_READINESS_CATALOG,
        "summary": {
            "categories": len(ENTERPRISE_READINESS_CATALOG),
            "controls": len(controls),
            "implemented": implemented,
            "contract_ready": contract_ready,
            "external_setup_required": external,
            "readiness_score": round(((implemented + contract_ready * 0.65) / len(controls)) * 100),
            "final_bar": [
                "secure by default",
                "tenant-safe by default",
                "dry-run by default",
                "evidence-first by default",
                "every action audited",
                "every recommendation explainable",
                "every deployment reproducible",
            ],
        },
    }
