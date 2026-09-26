"""Explainable inventory triage, not a claim of runtime use or quantum safety."""

import re
from collections import Counter
from typing import Literal

from pydantic import BaseModel

from app.scanner import Finding

PRIORITIES = {"high": 1, "medium": 2, "informational": 3}
PUBLIC_KEY = {"RSA", "ECC", "EC", "ECDSA", "ECDH", "ECDHE", "DSA", "DH", "ED25519", "ED448", "X25519", "X448"}
LEGACY = {"MD5", "SHA1", "DES", "3DES", "DES3", "TRIPLEDES"}


class AssessedFinding(Finding):
    id: str
    migration_concern: str
    priority: Literal["high", "medium", "informational"]
    reason: str


def concern(finding: Finding) -> tuple[str, str, str]:
    if finding.status != "confirmed" or finding.evidence_type == "indirect" or finding.type == "ai_behavior":
        return ("verify_indirect_usage", "medium",
                f"Evidence remains {finding.status}; establish the implementation and mechanism before selecting a migration.")
    algorithm = re.sub(r"[-_ ]", "", finding.algorithm or "").upper()
    protocol = re.sub(r"[v _-]", "", finding.protocol or "", flags=re.I).upper()
    if algorithm in LEGACY:
        return ("legacy_mechanism_review", "high",
                f"{finding.algorithm} is a legacy mechanism; verify active use, security purpose, and replacement compatibility.")
    if finding.type == "certificate" and re.search(r"MD5|SHA[ _-]?1(?!\d)", finding.signature_algorithm or "", re.I):
        return ("legacy_certificate_signature", "high",
                "The certificate references a legacy signature digest; review issuance and trust-chain compatibility before replacement.")
    if algorithm in PUBLIC_KEY or (finding.type == "certificate" and re.search(
            r"RSA|ECDSA|DSA|ED25519|ED448", finding.signature_algorithm or "", re.I)):
        return ("post_quantum_transition_attention", "high",
                "Public-key evidence requires post-quantum transition planning; identify its purpose, provider, and interoperability constraints.")
    if protocol in {"SSL", "SSL2", "SSL3", "TLS1", "TLS1.0", "TLS1.1"}:
        return ("legacy_protocol_review", "high",
                f"{finding.protocol} references a legacy protocol; verify whether it is enabled before changing negotiation policy.")
    if algorithm in {"AES", "CHACHA20"}:
        return ("symmetric_parameter_review", "medium",
                "Review mode, key length, nonce handling, and provider support; the algorithm name alone does not establish implementation security.")
    if algorithm in {"SHA224", "SHA256", "SHA384", "SHA512", "SHA3"}:
        return ("maintain_crypto_inventory", "informational",
                "This hash reference alone does not justify urgent replacement; retain its purpose and implementation in the inventory.")
    if finding.protocol:
        return ("protocol_compatibility_review", "medium" if protocol in {"TLS", "TLS1.2"} else "informational",
                "Review negotiated versions, cipher suites, and certificate dependencies; protocol version alone does not establish quantum resistance.")
    if finding.type in {"library", "dependency", "provider"}:
        return ("provider_capability_review", "medium",
                "An import, setting, or package declaration is present; inspect active APIs and provider capabilities without assuming a particular algorithm or vulnerability.")
    if finding.type in {"certificate_path", "key_path", "certificate", "cipher_suite"}:
        return ("configuration_reference_review", "medium",
                "Validate the referenced material or settings and their consuming components before making compatibility changes.")
    return ("maintain_crypto_inventory", "informational", "Retain this evidence and establish its operational purpose before selecting changes.")


def assess_findings(findings: list[Finding]) -> list[AssessedFinding]:
    assessed = []
    seen = set()
    for finding in findings:
        identity = finding.model_dump_json()
        if identity in seen:
            continue
        seen.add(identity)
        category, priority, reason = concern(finding)
        assessed.append(AssessedFinding(**finding.model_dump(), id=f"finding-{len(assessed) + 1}",
                        migration_concern=category, priority=priority, reason=reason))
    return assessed


def display_name(finding: Finding) -> str:
    return finding.algorithm or finding.protocol or finding.library or finding.reference or finding.ai_label or finding.type


def checklist(findings: list[AssessedFinding]) -> list[dict]:
    groups = {}
    for finding in findings:
        key = (PRIORITIES[finding.priority], finding.migration_concern, display_name(finding), finding.status)
        groups.setdefault(key, []).append(finding)
    items = []
    for (rank, category, name, status), group in sorted(groups.items()):
        if category == "verify_indirect_usage":
            steps = ["Inspect the wrapper implementation and establish whether cryptography is used.",
                     "Record the actual mechanism, provider, and dependent components if present.",
                     "Add focused tests and reassess this unconfirmed finding before selecting a replacement."]
        elif category == "post_quantum_transition_attention":
            steps = ["Identify dependent components and confirm the cryptographic operation and provider.",
                     "Introduce or document a provider abstraction at the observed boundary.",
                     "Evaluate a suitable alternative provider for the operation and deployment constraints.",
                     "Test interoperability, data formats, and certificate/authentication compatibility as applicable.",
                     "Run regression tests and validate rollback before deployment."]
        elif category.startswith("legacy_"):
            steps = ["Confirm whether this legacy reference is active and identify its consumers.",
                     "Select a supported replacement appropriate to the operation and compatibility requirements.",
                     "Test replacement configuration, peer negotiation or persisted-data compatibility as applicable.",
                     "Run regression and rollback tests before disabling the old mechanism."]
        elif category == "maintain_crypto_inventory":
            steps = ["Document the mechanism's purpose and owning component.",
                     "Retain regression coverage and reassess when provider or policy requirements change."]
        else:
            steps = ["Verify the active setting, referenced material, or provider and its consumers.",
                     "Document algorithm parameters and compatibility constraints without assuming an unsupported dependency.",
                     "Test any proposed change with the affected components and retain rollback coverage."]
        items.append({"id": f"action-{len(items) + 1}", "priority": rank,
                      "title": f"{'Verify' if category == 'verify_indirect_usage' else 'Review'} {name}",
                      "finding_status": status, "affected_components": sorted({f.file for f in group}),
                      "finding_ids": [f.id for f in group], "reason": group[0].reason, "steps": steps})
    return items


def summary(findings: list[AssessedFinding]) -> dict:
    counts = Counter(f.status for f in findings)
    return {"total_findings": len(findings), "high_priority": sum(f.priority == "high" for f in findings),
            "confirmed": counts["confirmed"], "likely": counts["likely"], "uncertain": counts["uncertain"]}
