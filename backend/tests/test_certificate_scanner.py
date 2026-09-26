import io
import json
import zipfile
from datetime import datetime, timezone

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed25519, ed448, rsa
from cryptography.x509.oid import NameOID
from fastapi.testclient import TestClient

from app.certificate_scanner import scan_certificate, scan_certificates
from app.main import app

VALID_FROM = datetime(2025, 1, 1, tzinfo=timezone.utc)
VALID_UNTIL = datetime(2027, 1, 1, tzinfo=timezone.utc)
SERIAL = (1 << 150) + 12345


@pytest.fixture(scope="module")
def samples():
    keys = {
        "RSA": rsa.generate_private_key(public_exponent=65537, key_size=2048),
        "ECC": ec.generate_private_key(ec.SECP256R1()),
        "DSA": dsa.generate_private_key(key_size=2048),
        "Ed25519": ed25519.Ed25519PrivateKey.generate(),
        "Ed448": ed448.Ed448PrivateKey.generate(),
    }
    result = {}
    for algorithm, key in keys.items():
        cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "server.example")]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "CryptoNexus Test CA")]))
            .public_key(key.public_key()).serial_number(SERIAL)
            .not_valid_before(VALID_FROM).not_valid_after(VALID_UNTIL)
            .sign(key, None if algorithm.startswith("Ed") else hashes.SHA256()))
        result[algorithm] = key, cert
    return result


@pytest.mark.parametrize("algorithm,size", [("RSA", 2048), ("ECC", 256),
    ("DSA", 2048), ("Ed25519", None), ("Ed448", None)])
def test_public_key_algorithms(samples, algorithm, size):
    data = samples[algorithm][1].public_bytes(serialization.Encoding.PEM)
    findings, issues = scan_certificate(data, "certs/server.pem")
    assert issues == [] and len(findings) == 1
    finding = findings[0]
    assert finding.type == "certificate" and finding.algorithm == algorithm
    assert finding.key_size == size and finding.usage == "certificate_public_key"
    assert finding.file == "certs/server.pem" and finding.line == 1
    assert finding.evidence_type == "direct" and finding.status == "confirmed"


@pytest.mark.parametrize("extension", ["pem", "crt", "cer"])
@pytest.mark.parametrize("encoding", [serialization.Encoding.PEM, serialization.Encoding.DER])
def test_encodings_and_extensions(samples, tmp_path, extension, encoding):
    name = f"server.{extension}"
    (tmp_path / name).write_bytes(samples["RSA"][1].public_bytes(encoding))
    findings, issues = scan_certificates(tmp_path, [name])
    assert issues == [] and len(findings) == 1
    assert findings[0].algorithm == "RSA"
    assert findings[0].line == (1 if encoding == serialization.Encoding.PEM else None)


def test_certificate_metadata(samples):
    certificate = samples["RSA"][1]
    findings, issues = scan_certificate(certificate.public_bytes(serialization.Encoding.PEM), "server.crt")
    finding = findings[0]
    assert issues == []
    assert finding.subject == "CN=server.example"
    assert finding.issuer == "CN=CryptoNexus Test CA"
    assert finding.serial_number == str(SERIAL)
    assert finding.signature_algorithm == "RSA_WITH_SHA256"
    assert finding.valid_from == VALID_FROM.isoformat()
    assert finding.valid_until == VALID_UNTIL.isoformat()
    assert certificate.fingerprint(hashes.SHA256()).hex() in finding.evidence
    assert "-----BEGIN" not in finding.evidence


@pytest.mark.parametrize("data", [b"", b"not a certificate", b"\x30\x82\x01\xff",
    b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----",
    b"-----BEGIN CERTIFICATE-----\ntruncated"])
def test_invalid_certificate_is_a_controlled_skip(data):
    findings, issues = scan_certificate(data, "broken.crt")
    assert findings == [] and len(issues) == 1
    assert issues[0].status == "skipped"
    assert issues[0].reason == "invalid_or_unsupported_certificate"


def test_pem_bundle_recovers_after_corrupt_block(samples):
    rsa_pem = samples["RSA"][1].public_bytes(serialization.Encoding.PEM)
    ec_pem = samples["ECC"][1].public_bytes(serialization.Encoding.PEM)
    broken = b"-----BEGIN CERTIFICATE-----\ninvalid\n-----END CERTIFICATE-----\n"
    findings, issues = scan_certificate(rsa_pem + broken + ec_pem, "bundle.pem")
    assert [f.algorithm for f in findings] == ["RSA", "ECC"]
    assert len(issues) == 1 and issues[0].line == rsa_pem.count(b"\n") + 1
    assert findings[1].line == (rsa_pem + broken).count(b"\n") + 1


@pytest.mark.parametrize("encoding,format,encrypted", [
    (serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, False),
    (serialization.Encoding.PEM, serialization.PrivateFormat.TraditionalOpenSSL, False),
    (serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, True),
    (serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, False),
])
def test_private_keys_are_never_certificates(samples, encoding, format, encrypted):
    encryption = serialization.BestAvailableEncryption(b"test-password") if encrypted else serialization.NoEncryption()
    data = samples["RSA"][0].private_bytes(encoding, format, encryption)
    findings, issues = scan_certificate(data, "private.pem")
    assert findings == [] and len(issues) == 1
    assert issues[0].status == "skipped"
    assert "PRIVATE KEY" not in issues[0].model_dump_json()


def test_mixed_pem_never_returns_private_material(samples):
    key, cert = samples["RSA"]
    private = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                               serialization.NoEncryption())
    findings, issues = scan_certificate(private + cert.public_bytes(serialization.Encoding.PEM) + private, "mixed.pem")
    assert len(findings) == 1 and issues == []
    response = findings[0].model_dump_json()
    assert "PRIVATE KEY" not in response
    assert private.splitlines()[1].decode() not in response
    assert findings[0].line == private.count(b"\n") + 1


def test_certificate_limits(samples, monkeypatch):
    from app import certificate_scanner
    pem = samples["RSA"][1].public_bytes(serialization.Encoding.PEM)
    monkeypatch.setattr(certificate_scanner, "MAX_CERTIFICATES_PER_FILE", 1)
    findings, issues = scan_certificate(pem + pem, "bundle.pem")
    assert len(findings) == 1 and issues[0].reason == "certificate_limit"
    monkeypatch.setattr(certificate_scanner, "MAX_CERTIFICATE_BYTES", 10)
    findings, issues = scan_certificate(pem, "large.pem")
    assert findings == [] and issues[0].reason == "file_too_large"


def test_missing_file_and_unsupported_extension(tmp_path):
    findings, issues = scan_certificates(tmp_path, ["missing.pem", "skip.key"])
    assert findings == [] and len(issues) == 1
    assert issues[0].reason == "unreadable_file"


def test_upload_preserves_findings_and_cleans_workspace(samples, tmp_path, monkeypatch):
    from app import uploads
    monkeypatch.setattr(uploads.tempfile, "tempdir", str(tmp_path))
    private = samples["RSA"][0].private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, data in {
            "certs/server.crt": samples["RSA"][1].public_bytes(serialization.Encoding.PEM),
            "certs/ec.cer": samples["ECC"][1].public_bytes(serialization.Encoding.DER),
            "certs/broken.pem": b"invalid certificate",
            "certs/private.pem": private,
            "main.py": "RSA.generate(2048)",
            "security.yaml": "tls_version: TLSv1.2",
            "requirements.txt": "cryptography>=42",
        }.items():
            archive.writestr(name, data)
    response = TestClient(app).post("/api/upload", files={"file": ("repo.zip", stream.getvalue(), "application/zip")})
    assert response.status_code == 200
    result = response.json()
    assert result["total_files"] == 7
    assert len(result["certificate_files"]) == 4
    assert result["finding_count"] == len(result["crypto_findings"]) == 5
    certificates = [f for f in result["crypto_findings"] if f["type"] == "certificate"]
    assert {f["algorithm"] for f in certificates} == {"RSA", "ECC"}
    assert len(result["certificate_scan_issues"]) == 2
    assert {f["type"] for f in result["crypto_findings"]} == {"algorithm", "protocol", "dependency", "certificate"}
    assert private.splitlines()[1].decode() not in json.dumps(result)
    assert "PRIVATE KEY" not in response.text
    assert list(tmp_path.iterdir()) == []
