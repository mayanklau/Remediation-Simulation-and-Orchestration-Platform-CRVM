from __future__ import annotations

from collections import Counter, defaultdict
from statistics import mean
from typing import Any

from motor.motor_asyncio import AsyncIOMotorDatabase

from app.models import ReportSnapshot
from app.services.attack_paths import build_attack_path_model
from app.services.dashboard import asset_graph
from app.services.tenant import touch_audit


SEVERITY_WEIGHTS = {"CRITICAL": 5, "HIGH": 4, "MEDIUM": 3, "LOW": 2}
LEVEL_SCORES = {"LOW": 0, "MEDIUM": 11, "HIGH": 22, "CRITICAL": 33}
POSTURE_MODULE_WEIGHTS = {
    "androidpt": 0.07,
    "iospt": 0.07,
    "externalpt": 0.12,
    "api": 0.14,
    "internalpt": 0.1,
    "database": 0.13,
    "operatingsystem": 0.12,
    "network": 0.12,
    "audit": 0.13,
}


async def build_crvm_model(db: AsyncIOMotorDatabase, tenant_id: str) -> dict[str, Any]:
    assets = await db.assets.find({"tenant_id": tenant_id}).to_list(1000)
    findings = await db.findings.find({"tenant_id": tenant_id, "status": {"$nin": ["RESOLVED", "FALSE_POSITIVE"]}}).to_list(2000)
    actions = await db.remediation_actions.find({"tenant_id": tenant_id}).to_list(1000)
    simulations = await db.simulations.find({"tenant_id": tenant_id}).sort("created_at", -1).to_list(1000)
    policies = await db.policies.find({"tenant_id": tenant_id, "enabled": True}).to_list(500)

    graph = await asset_graph(db, tenant_id)
    attack_paths = await build_attack_path_model(db, tenant_id)
    app_scores = [_application_score(asset, findings, actions, simulations, policies) for asset in assets]
    app_scores.sort(key=lambda item: item["app_posture_score"], reverse=True)
    exposure = _exposure_intelligence(assets, findings, graph, attack_paths)
    remediation_loop = _discovery_to_remediation_loop(app_scores, actions, simulations, attack_paths)
    portfolio = _portfolio_summary(app_scores, exposure, remediation_loop, attack_paths)

    return {
        "generated_by": "crvm-app-posture-engine",
        "lineage": {
            "source_zip": "app-posture.zip",
            "ported_concepts": [
                "app posture weighted module score",
                "CRVM vulnerability discovery score",
                "CIA impact score",
                "environment score",
                "CRQ / ROSI / RAROC economic formulas",
                "asset exposure and compromisability views",
                "discovery-to-remediation operating loop",
            ],
            "implementation": "Native Python/FastAPI/Mongo service using the existing tenant, asset, finding, attack-path, simulation, and remediation collections.",
        },
        "summary": portfolio,
        "application_posture": app_scores[:50],
        "exposure_intelligence": exposure,
        "remediation_loop": remediation_loop,
        "scoring_model": {
            "module_score": "severitySum / (totalFindings * 5) * 10",
            "overall_score": "weighted active module score on a 0-10 scale",
            "cytwin_risk_score": "(environmentScore + vulnerabilityDiscoveryScore) / 2",
            "app_posture_score": "overallScore * 0.6 + cytwinRiskScore * 0.4",
            "cia_score": "confidentiality + integrity + availability levels mapped to 0..99",
            "rosi": "((ALE_before - ALE_after) - securityCost) / securityCost * 100",
            "raroc": "(ALE_before - ALE_after) / economicCapital",
        },
    }


async def snapshot_crvm_model(db: AsyncIOMotorDatabase, tenant_id: str) -> dict[str, Any]:
    model = await build_crvm_model(db, tenant_id)
    report = ReportSnapshot(
        tenant_id=tenant_id,
        name="CRVM discovery-to-remediation posture",
        type="crvm_app_posture",
        data=model,
        created_by="crvm-posture-engine",
    )
    await db.report_snapshots.insert_one(report.model_dump(by_alias=True))
    await touch_audit(db, tenant_id, "crvm-posture-engine", "crvm_snapshot_generated", "report", report.id, model["summary"])
    return {"report": report, "crvm": model}


def _application_score(asset: dict[str, Any], findings: list[dict[str, Any]], actions: list[dict[str, Any]], simulations: list[dict[str, Any]], policies: list[dict[str, Any]]) -> dict[str, Any]:
    asset_findings = [finding for finding in findings if finding.get("asset_id") == asset.get("_id")]
    asset_actions = [action for action in actions if action.get("finding_id") in {finding.get("_id") for finding in asset_findings}]
    simulation_by_action = {simulation.get("remediation_action_id"): simulation for simulation in simulations}
    module_scores = _module_scores(asset_findings, asset)
    active_weights = {key: POSTURE_MODULE_WEIGHTS[key] for key, value in module_scores.items() if value is not None}
    weight_total = sum(active_weights.values()) or 1
    overall = sum((module_scores[key] or 0) * weight for key, weight in active_weights.items()) / weight_total
    env_score = _environment_score(asset, asset_findings, policies)
    vul_discovery = _vulnerability_discovery_score(asset_findings)
    cytwin = round((env_score + vul_discovery) / 2, 2)
    app_posture = round(overall * 0.6 + cytwin * 0.4, 2)
    economics = _cyber_economics(asset, asset_findings, asset_actions, simulation_by_action)
    open_critical = len([finding for finding in asset_findings if finding.get("severity") == "CRITICAL"])
    return {
        "asset_id": asset.get("_id"),
        "application": asset.get("name"),
        "owner": asset.get("owner") or "Unassigned",
        "team": asset.get("team") or "Unassigned",
        "environment": asset.get("environment", "UNKNOWN"),
        "internet_exposure": bool(asset.get("internet_exposure")),
        "module_scores": module_scores,
        "overall_score": round(overall, 2),
        "environment_score": env_score,
        "vulnerability_discovery_score": vul_discovery,
        "cytwin_risk_score": cytwin,
        "app_posture_score": app_posture,
        "posture_band": _band(app_posture),
        "cia_score": _cia_score(asset),
        "crq": economics,
        "open_findings": len(asset_findings),
        "open_critical_findings": open_critical,
        "remediation_actions": len(asset_actions),
        "simulated_actions": len([action for action in asset_actions if simulation_by_action.get(action.get("_id"))]),
        "next_best_actions": _next_best_actions(asset, asset_findings, asset_actions, app_posture),
    }


def _module_scores(findings: list[dict[str, Any]], asset: dict[str, Any]) -> dict[str, float | None]:
    buckets = {
        "api": ["api", "application"],
        "externalpt": ["external", "internet", "network"],
        "internalpt": ["internal", "lateral"],
        "database": ["database", "data"],
        "operatingsystem": ["os", "operating", "host"],
        "network": ["network", "port", "firewall"],
        "audit": ["compliance", "control", "audit"],
        "androidpt": ["android", "mobile"],
        "iospt": ["ios", "mobile"],
    }
    scores: dict[str, float | None] = {}
    asset_type = str(asset.get("type", "")).lower()
    for module, keywords in buckets.items():
        matched = [
            finding
            for finding in findings
            if any(keyword in str(finding.get("category", "")).lower() or keyword in str(finding.get("source", "")).lower() or keyword in asset_type for keyword in keywords)
        ]
        scores[module] = _severity_module_score(matched) if matched else None
    if all(value is None for value in scores.values()) and findings:
        scores["externalpt" if asset.get("internet_exposure") else "internalpt"] = _severity_module_score(findings)
    return scores


def _severity_module_score(findings: list[dict[str, Any]]) -> float:
    if not findings:
        return 0
    total = len(findings)
    severity_sum = sum(SEVERITY_WEIGHTS.get(str(finding.get("severity", "LOW")).upper(), 2) for finding in findings)
    return round((severity_sum / (total * 5)) * 10, 2)


def _environment_score(asset: dict[str, Any], findings: list[dict[str, Any]], policies: list[dict[str, Any]]) -> float:
    criticality = _level_10(asset.get("criticality", 3))
    sensitivity = _level_10(asset.get("data_sensitivity", 3))
    reachability = 10 if asset.get("internet_exposure") else 7.5 if asset.get("environment") == "PRODUCTION" else 5
    compensating_control = max(0, 10 - len(policies) * 0.8)
    threat = min(10, _severity_module_score(findings))
    probability = min(10, mean([finding.get("business_risk_score", 0) for finding in findings] or [0]) / 10)
    cia = _cia_score(asset) / 9.9
    return round(mean([criticality, sensitivity, reachability, compensating_control, threat, probability, cia]), 2)


def _vulnerability_discovery_score(findings: list[dict[str, Any]]) -> float:
    if not findings:
        return 0
    cvss = mean([_cvss(finding) for finding in findings])
    owasp = mean([_owasp_score(finding) for finding in findings])
    kev = 10 if any(finding.get("active_exploitation") or finding.get("metadata", {}).get("kev") for finding in findings) else 0
    ransomware = 10 if any("ransom" in str(finding.get("metadata", {})).lower() for finding in findings) else 0
    epss = mean([float(finding.get("metadata", {}).get("epss", 0) or 0) * 10 for finding in findings])
    exploitdb = 10 if any(finding.get("exploit_available") for finding in findings) else 0
    return round(mean([cvss, owasp, kev, ransomware, epss, exploitdb]), 2)


def _cyber_economics(asset: dict[str, Any], findings: list[dict[str, Any]], actions: list[dict[str, Any]], simulation_by_action: dict[str, dict[str, Any]]) -> dict[str, Any]:
    asset_value = (asset.get("criticality", 3) + asset.get("data_sensitivity", 3)) * 125000
    likelihood_before = min(0.95, mean([finding.get("business_risk_score", 0) for finding in findings] or [0]) / 100)
    reduction = sum(float(simulation_by_action.get(action.get("_id"), {}).get("risk_reduction_estimate", action.get("expected_risk_reduction", 0)) or 0) for action in actions)
    likelihood_after = max(0.02, likelihood_before * (1 - min(0.85, reduction / 100)))
    ale_before = round(asset_value * likelihood_before, 2)
    ale_after = round(asset_value * likelihood_after, 2)
    security_cost = max(25000, len(actions) * 18000 + len(findings) * 2500)
    economic_capital = max(100000, asset_value * 0.35)
    rosi = round((((ale_before - ale_after) - security_cost) / security_cost) * 100, 2) if security_cost else 0
    raroc = round((ale_before - ale_after) / economic_capital, 4) if economic_capital else 0
    return {
        "asset_value": round(asset_value, 2),
        "ale_before": ale_before,
        "ale_after": ale_after,
        "security_cost": security_cost,
        "rosi_percent": rosi,
        "raroc": raroc,
        "expected_loss_reduction": round(ale_before - ale_after, 2),
    }


def _exposure_intelligence(assets: list[dict[str, Any]], findings: list[dict[str, Any]], graph: dict[str, Any], attack_paths: dict[str, Any]) -> dict[str, Any]:
    categories = Counter(str(finding.get("category", "vulnerability")).lower() for finding in findings)
    exposed_assets = [asset for asset in assets if asset.get("internet_exposure")]
    return {
        "discovered_assets": len(assets),
        "internet_exposed_assets": len(exposed_assets),
        "reachable_edges": len(graph.get("edges", [])),
        "attack_paths": attack_paths.get("summary", {}).get("attack_paths", 0),
        "password_leak_signals": categories.get("password", 0) + categories.get("secret", 0),
        "owasp_signals": sum(count for category, count in categories.items() if "owasp" in category or "application" in category or "api" in category),
        "open_port_signals": sum(count for category, count in categories.items() if "port" in category or "network" in category),
        "typosquat_signals": categories.get("typosquat", 0),
        "domain_enumeration_signals": categories.get("domain", 0),
        "compromisability": _compromisability(findings),
    }


def _discovery_to_remediation_loop(app_scores: list[dict[str, Any]], actions: list[dict[str, Any]], simulations: list[dict[str, Any]], attack_paths: dict[str, Any]) -> dict[str, Any]:
    simulated_ids = {simulation.get("remediation_action_id") for simulation in simulations}
    immediate_apps = [app for app in app_scores if app["posture_band"] in {"critical", "high"}]
    path_breakers = [
        recommendation
        for path in attack_paths.get("paths", [])
        for recommendation in path.get("path_breaker_recommendations", [])[:1]
    ]
    return {
        "stages": [
            {"stage": "discover", "status": "active", "count": len(app_scores)},
            {"stage": "score", "status": "active", "count": len([app for app in app_scores if app["app_posture_score"] > 0])},
            {"stage": "chain", "status": "active", "count": attack_paths.get("summary", {}).get("attack_paths", 0)},
            {"stage": "simulate", "status": "active", "count": len(simulated_ids)},
            {"stage": "remediate", "status": "active", "count": len(actions)},
            {"stage": "evidence", "status": "ready", "count": len(path_breakers)},
        ],
        "immediate_applications": immediate_apps[:10],
        "path_breakers": path_breakers[:10],
        "simulation_coverage": round((len(simulated_ids) / len(actions)) * 100, 2) if actions else 0,
        "closure_narrative": "Discovery, posture scoring, attack-path chaining, simulation, approval, remediation planning, and evidence snapshots now share one CRVM data loop.",
    }


def _portfolio_summary(app_scores: list[dict[str, Any]], exposure: dict[str, Any], remediation_loop: dict[str, Any], attack_paths: dict[str, Any]) -> dict[str, Any]:
    return {
        "applications": len(app_scores),
        "average_app_posture_score": round(mean([app["app_posture_score"] for app in app_scores] or [0]), 2),
        "critical_or_high_applications": len([app for app in app_scores if app["posture_band"] in {"critical", "high"}]),
        "internet_exposed_assets": exposure["internet_exposed_assets"],
        "attack_paths": attack_paths.get("summary", {}).get("attack_paths", 0),
        "risk_reduction_available": round(sum(item.get("estimated_risk_reduction", 0) for item in remediation_loop["path_breakers"]), 2),
        "simulation_coverage": remediation_loop["simulation_coverage"],
    }


def _next_best_actions(asset: dict[str, Any], findings: list[dict[str, Any]], actions: list[dict[str, Any]], app_posture: float) -> list[str]:
    steps = []
    if asset.get("internet_exposure"):
        steps.append("Validate exposed attack surface and apply path breaker or virtual patch before production remediation.")
    if any(finding.get("active_exploitation") for finding in findings):
        steps.append("Escalate active exploitation findings into immediate remediation workflow.")
    if any(finding.get("patch_available") for finding in findings):
        steps.append("Run patch simulation and generate rollout/rollback plan.")
    if not actions and findings:
        steps.append("Generate remediation actions from open CRVM findings.")
    if app_posture >= 7:
        steps.append("Require evidence pack before closure because posture risk is high.")
    return steps[:5] or ["Monitor posture drift and refresh scanner discovery."]


def _compromisability(findings: list[dict[str, Any]]) -> dict[str, Any]:
    exploitable = [finding for finding in findings if finding.get("exploit_available") or finding.get("active_exploitation")]
    trending = [finding for finding in findings if finding.get("metadata", {}).get("epss", 0) and float(finding.get("metadata", {}).get("epss", 0)) >= 0.8]
    return {
        "exploitable_findings": len(exploitable),
        "active_exploitation": len([finding for finding in findings if finding.get("active_exploitation")]),
        "trending_vulnerabilities": len(trending),
        "score": round(min(100, len(exploitable) * 8 + len(trending) * 5 + len([finding for finding in findings if finding.get("severity") == "CRITICAL"]) * 6), 2),
    }


def _cia_score(asset: dict[str, Any]) -> int:
    sensitivity = _level_name(asset.get("data_sensitivity", 3))
    integrity = _level_name(asset.get("criticality", 3))
    availability = "CRITICAL" if asset.get("environment") == "PRODUCTION" else integrity
    return min(99, LEVEL_SCORES[sensitivity] + LEVEL_SCORES[integrity] + LEVEL_SCORES[availability])


def _level_name(value: Any) -> str:
    number = int(value or 3)
    if number >= 5:
        return "CRITICAL"
    if number >= 4:
        return "HIGH"
    if number >= 3:
        return "MEDIUM"
    return "LOW"


def _level_10(value: Any) -> float:
    return {1: 2.5, 2: 4, 3: 5, 4: 7.5, 5: 10}.get(int(value or 3), 5)


def _cvss(finding: dict[str, Any]) -> float:
    metadata = finding.get("metadata", {})
    return float(metadata.get("cvss") or metadata.get("cvss_v3") or metadata.get("cvss_v2") or SEVERITY_WEIGHTS.get(str(finding.get("severity", "LOW")).upper(), 2) * 2)


def _owasp_score(finding: dict[str, Any]) -> float:
    category = str(finding.get("category", "")).lower()
    title = str(finding.get("title", "")).lower()
    if any(token in category or token in title for token in ["injection", "auth", "access", "crypto"]):
        return 10
    if any(token in category or token in title for token in ["misconfig", "vulnerable", "api"]):
        return 7.5
    if any(token in category or token in title for token in ["logging", "monitoring", "ssrf"]):
        return 5
    return 2.5


def _band(score: float) -> str:
    if score >= 8:
        return "critical"
    if score >= 6:
        return "high"
    if score >= 4:
        return "medium"
    return "managed"
