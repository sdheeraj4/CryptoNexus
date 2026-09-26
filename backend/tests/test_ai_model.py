import io
import json
import socket
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.ai import inference
from app.ai.dataset import load_dataset
from app.ai.inference import predict_crypto_behavior, prediction_from_probabilities
from app.ai.scan import scan_indirect_calls
from app.ai.train import split_records
from app.main import app
from app.scanner import scan_source


@pytest.mark.parametrize("code,label", [
    ("hashlib.sha256(payload).hexdigest()", "hashing"),
    ("cipher = AES.new(key, AES.MODE_GCM)\nciphertext = cipher.encrypt(data)", "encryption"),
    ("secure_provider.sign(payload)", "crypto_wrapper"),
    ("database_key = record.id", "non_crypto"),
])
def test_requested_local_predictions(code, label):
    result = predict_crypto_behavior(code, language="python")
    assert result["label"] == label
    assert 0 <= result["confidence"] <= 1
    assert result["status"] == ("likely" if result["confidence"] >= 0.60 else "uncertain")


@pytest.mark.parametrize("confidence,status", [(0.59, "uncertain"), (0.60, "likely"), (0.99, "likely")])
def test_confidence_threshold(confidence, status):
    result = prediction_from_probabilities(["crypto_wrapper", "non_crypto"], [confidence, 1 - confidence])
    assert result["status"] == status
    assert result["confidence"] == confidence


def test_model_loads_without_network(monkeypatch):
    def denied(*args, **kwargs):
        raise AssertionError("Network access is forbidden")
    inference.load_model.cache_clear()
    with monkeypatch.context() as patch:
        patch.setattr(socket, "socket", denied)
        patch.setattr(socket, "create_connection", denied)
        result = predict_crypto_behavior("hashlib.sha256(data)", language="python")
        assert result["label"] == "hashing"
        assert inference.load_model() is inference.load_model()
    inference.load_model.cache_clear()


def test_split_keeps_families_separate_and_is_reproducible():
    records = load_dataset()
    train, test = split_records(records)
    assert not {r["family_id"] for r in train} & {r["family_id"] for r in test}
    assert len(train) == 216 and len(test) == 80
    assert {r["label"] for r in train} == {r["label"] for r in test}
    assert split_records(records) == (train, test)
    metrics = json.loads(inference.MODEL_PATH.with_suffix(".metrics.json").read_text())
    assert all(0 <= metrics[name] <= 1 for name in ("accuracy", "macro_precision", "macro_recall", "macro_f1"))


def test_classification_endpoint():
    response = TestClient(app).post("/api/ai/classify", json={
        "code": "hashlib.sha256(payload).hexdigest()", "language": "python"})
    assert response.status_code == 200
    assert response.json()["label"] == "hashing"
    assert set(response.json()) == {"label", "confidence", "status"}


@pytest.mark.parametrize("payload", [{}, {"code": ""}, {"code": " "}, {"code": "a" * 16001}])
def test_invalid_classification_inputs(payload):
    assert TestClient(app).post("/api/ai/classify", json=payload).status_code == 422


def test_direct_evidence_is_preserved_and_wrappers_are_not_confirmed(tmp_path):
    source = "import hashlib\nhashlib.sha256(data)\nsecure_provider.sign(payload)\n"
    (tmp_path / "main.py").write_text(source)
    direct = scan_source(source, "main.py")
    before = [finding.model_dump() for finding in direct]
    indirect = scan_indirect_calls(tmp_path, ["main.py"], direct)
    assert [finding.model_dump() for finding in direct] == before
    assert all(f.status == "confirmed" for f in direct)
    assert len(indirect) == 1 and indirect[0].ai_label == "crypto_wrapper"
    assert indirect[0].status in {"likely", "uncertain"}
    assert indirect[0].evidence_type == "indirect" and indirect[0].algorithm is None


def test_candidate_limit_and_comments(tmp_path, monkeypatch):
    from app.ai import scan
    calls = []
    def predict(*args):
        calls.append(args)
        return {"label": "crypto_wrapper", "confidence": 0.8, "status": "likely"}
    monkeypatch.setattr(scan, "predict_crypto_behavior", predict)
    (tmp_path / "main.py").write_text('# vault.encrypt_record(data)\ns = "vault.encrypt_record(data)"\n'
                                     + "vault.encrypt_record(data)\n" * 50)
    findings = scan_indirect_calls(tmp_path, ["main.py"], [])
    assert len(calls) == len(findings) == scan.MAX_CANDIDATES
    assert findings[0].line == 3


def test_missing_model_is_controlled(tmp_path, monkeypatch):
    inference.load_model.cache_clear()
    monkeypatch.setattr(inference, "MODEL_PATH", tmp_path / "missing.joblib")
    try:
        assert TestClient(app).post("/api/ai/classify", json={"code": "vault.encrypt_record(data)"}).status_code == 503
        (tmp_path / "main.py").write_text("vault.encrypt_record(data)")
        assert scan_indirect_calls(tmp_path, ["main.py"], []) == []
    finally:
        inference.load_model.cache_clear()


def test_upload_combines_confirmed_and_ai_findings():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("main.py", "hashlib.sha256(data)\nsecure_provider.sign(payload)")
    response = TestClient(app).post("/api/upload", files={"file": ("test.zip", stream.getvalue(), "application/zip")})
    assert response.status_code == 200
    findings = response.json()["crypto_findings"]
    assert any(f["algorithm"] == "SHA256" and f["status"] == "confirmed" for f in findings)
    assert any(f["type"] == "ai_behavior" and f["status"] != "confirmed" for f in findings)
