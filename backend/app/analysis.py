"""Analyze an existing upload result without rescanning, opening paths, or invoking AI."""

from pydantic import BaseModel, Field, model_validator

from app.migration import assess_findings, checklist, summary
from app.relationships import build_graphs
from app.scanner import Finding
from app.report import build_report


class AnalysisRequest(BaseModel):
    crypto_findings: list[Finding] = Field(max_length=10_000)
    source_files: list[str] = Field(default_factory=list, max_length=10_000)
    config_files: list[str] = Field(default_factory=list, max_length=10_000)
    dependency_files: list[str] = Field(default_factory=list, max_length=10_000)
    certificate_files: list[str] = Field(default_factory=list, max_length=10_000)

    @model_validator(mode="after")
    def preserve_ai_uncertainty(self):
        if any((f.type == "ai_behavior" or f.evidence_type == "indirect") and f.status == "confirmed"
               for f in self.crypto_findings):
            raise ValueError("AI/indirect evidence must remain likely or uncertain")
        return self


def analyze(request: AnalysisRequest) -> dict:
    findings = assess_findings(request.crypto_findings)
    items = checklist(findings)
    files = request.source_files + request.config_files + request.dependency_files + request.certificate_files
    dependencies, migration_graph = build_graphs(findings, files, items)
    return {"findings": [f.model_dump() for f in findings], "dependencies": dependencies,
            "migration_checklist": items, "migration_graph": migration_graph, "summary": summary(findings),
            "report": build_report(findings)}
