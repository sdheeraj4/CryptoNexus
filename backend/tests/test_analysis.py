import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.analysis import AnalysisRequest, analyze
from app.main import app
from app.scanner import Finding


def finding(**fields):
    return Finding(**{"type": "algorithm", "algorithm": "RSA", "file": "auth.py", "line": 1,
                      "evidence": "RSA.generate(2048)", "key_size": 2048, **fields})


def test_rsa_high_priority_and_no_mutation():
    original = finding()
    result = analyze(AnalysisRequest(crypto_findings=[original]))
    assessed = result["findings"][0]
    assert assessed["priority"] == "high"
    assert assessed["migration_concern"] == "post_quantum_transition_attention"
    assert assessed["status"] == "confirmed"
    assert assessed["key_size"] == 2048
    assert original.model_dump() == finding().model_dump()
    item = result["migration_checklist"][0]
    assert item["priority"] == 1 and item["affected_components"] == ["auth.py"]
    assert any("provider abstraction" in step for step in item["steps"])


def test_tls_and_certificate_relationships():
    rows = [finding(type="protocol", algorithm=None, protocol="TLS 1.2", file="security.yaml", evidence="tls_version: TLSv1.2"),
            finding(type="certificate_path", algorithm=None, reference="certs/server.crt", file="security.yaml", line=2,
                    evidence="certificate: certs/server.crt"),
            finding(type="certificate", file="certs/server.crt", subject="CN=server", serial_number="123",
                    evidence="X.509 certificate; SHA256 fingerprint: abc", usage="certificate_public_key")]
    result = analyze(AnalysisRequest(crypto_findings=rows))
    graph = result["dependencies"]
    assert graph["nodes"] and graph["edges"]
    assert any(e["from"] == "file:security.yaml" and e["to"] == "protocol:TLS 1.2"
               and not e["inferred"] for e in graph["edges"])
    assert any(e["from"] == "file:security.yaml" and e["to"] == "file:certs/server.crt"
               and e["inferred"] for e in graph["edges"])
    assert any(e["from"] == "file:certs/server.crt" and e["relation"] == "contains_certificate" for e in graph["edges"])


@pytest.mark.parametrize("status,confidence", [("uncertain", 0.42), ("likely", 0.82)])
def test_ai_remains_unconfirmed(status, confidence):
    row = finding(type="ai_behavior", algorithm=None, key_size=None, evidence_type="indirect",
                  status=status, ai_label="crypto_wrapper", ai_confidence=confidence)
    result = analyze(AnalysisRequest(crypto_findings=[row]))
    assert result["findings"][0]["status"] == status
    assert result["findings"][0]["ai_confidence"] == confidence
    assert result["summary"][status] == 1 and result["summary"]["confirmed"] == 0
    item = result["migration_checklist"][0]
    assert item["finding_status"] == status
    assert "Inspect the wrapper implementation" in item["steps"][0]
    assert all(e["inferred"] for e in result["dependencies"]["edges"])


@pytest.mark.parametrize("algorithm,priority", [("MD5", "high"), ("SHA1", "high"), ("DES", "high"),
    ("3DES", "high"), ("ECC", "high"), ("Ed25519", "high"), ("AES", "medium"),
    ("ChaCha20", "medium"), ("SHA256", "informational"), ("SHA512", "informational")])
def test_algorithm_rules(algorithm, priority):
    result = analyze(AnalysisRequest(crypto_findings=[finding(algorithm=algorithm)]))
    assert result["findings"][0]["priority"] == priority


@pytest.mark.parametrize("protocol,priority", [("SSL", "high"), ("SSL 3", "high"), ("SSLv2", "high"),
    ("TLSv1", "high"), ("TLS 1.0", "high"), ("TLS 1.1", "high"), ("TLS 1.2", "medium"), ("TLS 1.3", "informational")])
def test_protocol_rules(protocol, priority):
    result = analyze(AnalysisRequest(crypto_findings=[finding(type="protocol", algorithm=None, protocol=protocol)]))
    assert result["findings"][0]["priority"] == priority


def test_checklist_order_grouping_and_validation_graph():
    rows = [finding(algorithm="SHA256"), finding(algorithm="AES"), finding(), finding(file="second.py")]
    result = analyze(AnalysisRequest(crypto_findings=rows))
    items = result["migration_checklist"]
    assert [i["priority"] for i in items] == [1, 2, 3]
    assert items[0]["affected_components"] == ["auth.py", "second.py"]
    graph = result["migration_graph"]
    ids = {n["id"] for n in graph["nodes"]}
    assert all(e["from"] in ids and e["to"] in ids for e in graph["edges"])
    assert any(n["type"] == "validation_gate" and n["status"] == "not_run" for n in graph["nodes"])
    assert any(e["relation"] == "observed_in" for e in graph["edges"])
    assert any(e["relation"] == "proposed_action" and e["proposed"] for e in graph["edges"])
    assert not any(n["type"] == "validation_gate" for n in result["dependencies"]["nodes"])


@pytest.mark.parametrize("reference,inventory,linked", [
    ("../certs/server.crt", ["certs/server.crt"], True),
    ("server.crt", ["unrelated/server.crt"], False),
    ("/etc/ssl/server.crt", ["server.crt"], False),
    ("${CERT_PATH}", ["server.crt"], False),
    ("server.crt", ["server.crt", "config/server.crt"], False),
])
def test_path_resolution_is_conservative(reference, inventory, linked):
    row = finding(type="certificate_path", algorithm=None, file="config/security.yaml", reference=reference)
    result = analyze(AnalysisRequest(crypto_findings=[row], certificate_files=inventory))
    links = [e for e in result["dependencies"]["edges"] if e["relation"] == "references_certificate_file"]
    assert bool(links) == linked
    assert all(e["inferred"] for e in links)


def test_no_library_algorithm_assumption():
    rows = [finding(), finding(type="library", algorithm=None, library="Crypto", line=2, evidence="from Crypto import Cipher")]
    result = analyze(AnalysisRequest(crypto_findings=rows + rows))
    assert len(result["findings"]) == 2
    edges = result["dependencies"]["edges"]
    assert any(e["relation"] == "imports" for e in edges)
    assert not any(e["from"] == "algorithm:RSA" and e["to"] == "library:Crypto" for e in edges)


def test_empty_analysis_and_invalid_ai_confirmation():
    result = analyze(AnalysisRequest(crypto_findings=[]))
    assert result["migration_checklist"] == []
    invalid = finding(type="ai_behavior", algorithm=None, evidence_type="indirect").model_dump()
    with pytest.raises(ValueError, match="must remain likely or uncertain"):
        AnalysisRequest(crypto_findings=[invalid])


def test_analyze_zip_reuses_upload_pipeline(tmp_path, monkeypatch):
    from app import uploads
    monkeypatch.setattr(uploads.tempfile, "tempdir", str(tmp_path))
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("auth.py", "RSA.generate(2048)")
        archive.writestr("security.yaml", "tls_version: TLSv1.2\ncertificate: server.crt")
        archive.writestr("server.crt", "invalid certificate")
        archive.writestr("wrapper.py", "secure_provider.sign(payload)")
    client = TestClient(app)
    upload = client.post("/api/upload", files={"file": ("repo.zip", stream.getvalue(), "application/zip")})
    assert upload.status_code == 200
    response = client.post("/api/analyze", files={"file": ("repo.zip", stream.getvalue(), "application/zip")})
    assert response.status_code == 200
    result = response.json()
    assert result == analyze(AnalysisRequest.model_validate(upload.json()))
    assert result["summary"]["high_priority"] == 1
    assert any(f["type"] == "ai_behavior" and f["status"] in {"likely", "uncertain"} for f in result["findings"])
    assert result["dependencies"]["edges"] and result["migration_checklist"]
    assert not any(n["type"] == "certificate" for n in result["dependencies"]["nodes"])
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("invalid_zip", [False, True])
def test_analyze_rejects_unsafe_or_invalid_zip(tmp_path, monkeypatch, invalid_zip):
    from app import uploads
    monkeypatch.setattr(uploads.tempfile, "tempdir", str(tmp_path))
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("../escape.py", "RSA.generate(2048)")
    data = b"not a ZIP" if invalid_zip else stream.getvalue()
    response = TestClient(app).post("/api/analyze", files={"file": ("repo.zip", data, "application/zip")})
    assert response.status_code == 400
    assert list(tmp_path.iterdir()) == []


def test_analyze_requires_multipart_file():
    client = TestClient(app)
    assert client.post("/api/analyze").status_code == 422
    assert client.post("/api/analyze", json={"crypto_findings": []}).status_code == 422


def test_analyze_reuses_upload_size_limit(monkeypatch):
    from app import uploads
    monkeypatch.setattr(uploads, "MAX_UPLOAD_BYTES", 8)
    response = TestClient(app).post("/api/analyze", files={"file": ("repo.zip", b"x" * 9, "application/zip")})
    assert response.status_code == 413
