"""Evidence relationships only; no program call graph or filesystem access."""

import hashlib
import posixpath
import re

from app.migration import AssessedFinding, display_name


class Graph:
    def __init__(self):
        self.nodes = {}
        self.edges = {}

    def node(self, kind, value, **fields):
        node_id = f"{kind}:{value}"
        self.nodes.setdefault(node_id, {"id": node_id, "type": kind, "label": value, **fields})
        return node_id

    def edge(self, source, target, relation, finding_ids, inferred=False, **fields):
        key = (source, target, relation, inferred)
        edge = self.edges.setdefault(key, {"from": source, "to": target, "relation": relation,
                                          "inferred": inferred, "finding_ids": [], **fields})
        edge["finding_ids"] = sorted(set(edge["finding_ids"]) | set(finding_ids))

    def output(self):
        return {"nodes": list(self.nodes.values()), "edges": list(self.edges.values())}


def resolve_reference(file: str, reference: str, known_files: set[str]) -> str | None:
    reference = reference.replace("\\", "/")
    if reference.startswith("/") or re.match(r"^[A-Za-z]:|^[\w+.-]+://", reference) or "$" in reference:
        return None
    candidates = {posixpath.normpath(reference),
                  posixpath.normpath(posixpath.join(posixpath.dirname(file), reference))}
    matches = {path for path in candidates if not path.startswith("../") and path in known_files}
    return next(iter(matches)) if len(matches) == 1 else None


def build_graphs(findings: list[AssessedFinding], inventory_files: list[str], items: list[dict]) -> tuple[dict, dict]:
    graph = Graph()
    known_files = {f.file for f in findings} | set(inventory_files)
    observed = {}
    for finding in findings:
        component = graph.node("file", finding.file)
        inferred = finding.status != "confirmed" or finding.evidence_type == "indirect"
        ids = [finding.id]
        if finding.type == "certificate":
            fingerprint = hashlib.sha256(finding.evidence.encode()).hexdigest()[:16]
            mechanism = graph.node("certificate", f"{finding.file}:{fingerprint}",
                                   subject=finding.subject, serial_number=finding.serial_number)
            graph.edge(component, mechanism, "contains_certificate", ids, inferred)
            if finding.algorithm:
                algorithm = graph.node("algorithm", finding.algorithm)
                graph.edge(mechanism, algorithm, "public_key_algorithm", ids, inferred)
        elif finding.type in {"certificate_path", "key_path"} and finding.reference:
            mechanism = graph.node(finding.type, f"{finding.file}:{finding.reference}", reference=finding.reference)
            graph.edge(component, mechanism, "references", ids, inferred)
            target = resolve_reference(finding.file, finding.reference, known_files)
            if target:
                file_node = graph.node("file", target)
                graph.edge(component, file_node, "references_certificate_file" if finding.type == "certificate_path" else "references_key_file",
                           ids, True, basis="Unique lexical match against repository inventory; runtime path base is not proven.")
        else:
            kind = "algorithm" if finding.algorithm else "protocol" if finding.protocol else (
                "library" if finding.library else "ai_behavior" if finding.type == "ai_behavior" else finding.type)
            mechanism = graph.node(kind, display_name(finding))
            relation = {"library": "imports", "dependency": "declares_dependency", "provider": "configures_provider",
                        "protocol": "configures_protocol", "ai_behavior": "may_use"}.get(finding.type, "uses")
            graph.edge(component, mechanism, relation, ids, inferred)
        observed[finding.id] = (mechanism, component, inferred)
    dependencies = graph.output()
    # The proposed graph extends the evidence graph; gates are not executed test results.
    graph.nodes = dict(graph.nodes)
    graph.edges = {key: dict(value) for key, value in graph.edges.items()}
    for item in items:
        action = graph.node("migration_action", item["id"], title=item["title"], status="proposed")
        gate = graph.node("validation_gate", item["id"], title=item["steps"][-1], status="not_run")
        graph.edge(action, gate, "requires_validation", item["finding_ids"], True, proposed=True)
        for finding_id in item["finding_ids"]:
            mechanism, component, inferred = observed[finding_id]
            graph.edge(mechanism, component, "observed_in", [finding_id], inferred)
            graph.edge(component, action, "proposed_action", [finding_id], True, proposed=True)
    return dependencies, graph.output()
