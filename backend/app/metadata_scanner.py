"""Scan inventoried metadata once even when config/dependency categories overlap."""

import logging
from pathlib import Path

from app.config_scanner import scan_config, unique_findings
from app.dependency_scanner import scan_dependencies
from app.scanner import Finding

logger = logging.getLogger(__name__)
MAX_METADATA_BYTES = 2 * 1024 * 1024


def scan_metadata(root: Path, config_files: list[str], dependency_files: list[str]) -> list[Finding]:
    findings = []
    configs, dependencies = set(config_files), set(dependency_files)
    for relative in sorted(configs | dependencies):
        with (root / relative).open("rb") as stream:
            data = stream.read(MAX_METADATA_BYTES + 1)
        if len(data) > MAX_METADATA_BYTES:
            logger.warning("Metadata byte limit reached; file skipped")
            continue
        source = data.decode("utf-8-sig", errors="replace")
        if relative in configs:
            findings.extend(scan_config(source, relative))
        if relative in dependencies:
            findings.extend(scan_dependencies(source, relative))
    return unique_findings(findings)
