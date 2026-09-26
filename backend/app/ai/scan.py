"""Bounded AI hints for opaque calls; never modify deterministic evidence."""

import logging
import re
from pathlib import Path

from app.ai.inference import ModelUnavailable, predict_crypto_behavior
from app.scanner import Finding, TOKEN

logger = logging.getLogger(__name__)
MAX_CANDIDATES = 20
MAX_SOURCE_FILES = 100
MAX_SOURCE_BYTES = 64 * 1024
LANGUAGES = {".py": "python", ".java": "java", ".js": "javascript", ".ts": "typescript"}
CALL = re.compile(r"\b([\w$]+)\s*\.\s*(sign|verify|protect|unprotect|encrypt_record|encryptRecord|decrypt_record|decryptRecord|encrypt|decrypt|create)\s*\(")


def scan_indirect_calls(root: Path, source_files: list[str], direct: list[Finding]) -> list[Finding]:
    confirmed = set()
    for finding in direct:
        if finding.line is not None and finding.status == "confirmed":
            confirmed.update((finding.file, line) for line in range(
                finding.line, finding.line + finding.evidence.count("\n") + 1))
    findings = []
    candidates = 0
    for file in sorted(source_files)[:MAX_SOURCE_FILES]:
        language = LANGUAGES.get(Path(file).suffix.lower())
        if not language:
            continue
        with (root / file).open("rb") as stream:
            data = stream.read(MAX_SOURCE_BYTES + 1)
        if len(data) > MAX_SOURCE_BYTES:
            continue
        source = data.decode("utf-8-sig", errors="replace")
        # Remove strings/comments only from the candidate detector, retaining offsets/lines.
        masked = TOKEN.sub(lambda m: re.sub(r"[^\n]", " ", m[0])
                           if m.lastgroup in {"string", "comment"} else m[0], source)
        lines = source.splitlines()
        seen_lines = set()
        for match in CALL.finditer(masked):
            if match[2] == "create" and not re.search(r"(?i)crypto|secure|vault|key_?service", match[1]):
                continue
            line = masked.count("\n", 0, match.start()) + 1
            if (file, line) in confirmed or line in seen_lines:
                continue
            seen_lines.add(line)
            if candidates >= MAX_CANDIDATES:
                return findings
            candidates += 1
            code = lines[line - 1].strip()[:2000]
            context = "\n".join(lines[max(0, line - 3):line - 1])[:2000]
            try:
                prediction = predict_crypto_behavior(code, context, language)
            except ModelUnavailable:
                logger.warning("Local AI model unavailable; deterministic scan retained")
                return findings
            if prediction["label"] == "non_crypto":
                continue
            findings.append(Finding(type="ai_behavior", file=file, line=line, evidence=code[:300],
                evidence_type="indirect", status=prediction["status"],
                ai_label=prediction["label"], ai_confidence=prediction["confidence"]))
    return findings
