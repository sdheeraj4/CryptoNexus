"""Parse only public X.509 certificates using cryptography; never load private keys."""

import re
from pathlib import Path
from typing import Literal

from cryptography import x509
from cryptography.exceptions import UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import ObjectIdentifier, SignatureAlgorithmOID
from pydantic import BaseModel

from app.scanner import Finding

MAX_CERTIFICATE_BYTES = 2 * 1024 * 1024
MAX_CERTIFICATES_PER_FILE = 100
PEM_START = re.compile(rb"-----BEGIN CERTIFICATE-----")
SIGNATURE_NAMES = {oid.dotted_string: name for name, oid in vars(SignatureAlgorithmOID).items()
                   if isinstance(oid, ObjectIdentifier)}


class CertificateIssue(BaseModel):
    file: str
    line: int | None = None
    status: Literal["skipped"] = "skipped"
    reason: Literal["invalid_or_unsupported_certificate", "not_a_certificate",
                    "file_too_large", "certificate_limit", "unreadable_file"]


def certificate_finding(certificate: x509.Certificate, file: str, line: int | None) -> Finding:
    key = certificate.public_key()
    algorithm = next((name for kind, name in (
        (rsa.RSAPublicKey, "RSA"), (ec.EllipticCurvePublicKey, "ECC"),
        (dsa.DSAPublicKey, "DSA"), (ed25519.Ed25519PublicKey, "Ed25519"),
        (ed448.Ed448PublicKey, "Ed448"),
    ) if isinstance(key, kind)), None)
    oid = certificate.signature_algorithm_oid.dotted_string
    return Finding(
        type="certificate", algorithm=algorithm, file=file, line=line,
        key_size=getattr(key, "key_size", None), usage="certificate_public_key",
        evidence="X.509 certificate; SHA256 fingerprint: " + certificate.fingerprint(hashes.SHA256()).hex(),
        subject=certificate.subject.rfc4514_string(), issuer=certificate.issuer.rfc4514_string(),
        serial_number=str(certificate.serial_number),
        signature_algorithm=SIGNATURE_NAMES.get(oid, oid),
        valid_from=certificate.not_valid_before_utc.isoformat(),
        valid_until=certificate.not_valid_after_utc.isoformat(),
    )


def scan_certificate(data: bytes, file: str) -> tuple[list[Finding], list[CertificateIssue]]:
    """Return findings plus safe skips. PEM bundles tolerate individual invalid blocks."""
    findings, issues = [], []
    if len(data) > MAX_CERTIFICATE_BYTES:
        return [], [CertificateIssue(file=file, reason="file_too_large")]
    starts = list(PEM_START.finditer(data))
    if not starts and b"-----BEGIN " in data:
        return [], [CertificateIssue(file=file, reason="not_a_certificate")]
    if starts:
        # Only delimit PEM blocks here; all certificate decoding is done by cryptography.
        blocks = ((data[match.start():starts[index + 1].start() if index + 1 < len(starts) else len(data)],
                   data.count(b"\n", 0, match.start()) + 1)
                  for index, match in enumerate(starts[:MAX_CERTIFICATES_PER_FILE]))
        loader = x509.load_pem_x509_certificate
        if len(starts) > MAX_CERTIFICATES_PER_FILE:
            issues.append(CertificateIssue(file=file, reason="certificate_limit"))
    else:
        blocks = [(data, None)]  # Binary DER has no meaningful source line.
        loader = x509.load_der_x509_certificate
    for block, line in blocks:
        try:
            findings.append(certificate_finding(loader(block), file, line))
        except (ValueError, UnsupportedAlgorithm):
            # Do not return parser exceptions or raw input: either could contain secrets.
            issues.append(CertificateIssue(file=file, line=line, reason="invalid_or_unsupported_certificate"))
    return findings, issues


def scan_certificates(root: Path, certificate_files: list[str]) -> tuple[list[Finding], list[CertificateIssue]]:
    findings, issues = [], []
    for relative in sorted(set(certificate_files)):
        if Path(relative).suffix.lower() not in {".crt", ".cer", ".pem"}:
            continue
        try:
            with (root / relative).open("rb") as stream:
                data = stream.read(MAX_CERTIFICATE_BYTES + 1)
        except OSError:
            issues.append(CertificateIssue(file=relative, reason="unreadable_file"))
            continue
        file_findings, file_issues = scan_certificate(data, relative)
        findings.extend(file_findings)
        issues.extend(file_issues)
    return findings, issues
