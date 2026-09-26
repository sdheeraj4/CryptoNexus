import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.analysis import AnalysisRequest, analyze
from app.scanner import Finding
from app.sandbox import CryptoProvider, RSAProvider, Ed25519Provider
from app.report import DISCLAIMER


@pytest.mark.parametrize("provider_class", [RSAProvider, Ed25519Provider])
def test_shared_provider_interface(provider_class):
    provider = provider_class()
    assert isinstance(provider, CryptoProvider)
    message = b"CryptoNexus agility test"
    signature = provider.sign(message)
    assert provider.verify(message, signature)
    assert not provider.verify(message + b"tampered", signature)
    assert not provider.verify(message, b"invalid")


@pytest.mark.parametrize("provider,algorithm,size", [("rsa", "RSA", 2048), ("ed25519", "Ed25519", None)])
def test_sandbox_response_excludes_secrets(provider, algorithm, size):
    response = TestClient(app).post("/api/sandbox/run", json={"provider": provider, "message": "test"})
    assert response.status_code == 200
    result = response.json()
    assert set(result) == {"provider", "algorithm", "operation", "verified", "key_size", "message_length", "note"}
    assert result["algorithm"] == algorithm and result["key_size"] == size
    assert result["verified"] is True and result["message_length"] == 4
    assert "does not prove quantum safety" in result["note"]


def test_invalid_provider():
    assert TestClient(app).post("/api/sandbox/run", json={"provider": "fake-pqc"}).status_code == 422


def test_report_schema_and_derived_guidance():
    empty = analyze(AnalysisRequest(crypto_findings=[]))["report"]
    assert set(empty) == {"limitations", "compatibility_risks", "testing_steps", "disclaimer"}
    assert empty["disclaimer"] == DISCLAIMER
    assert empty["compatibility_risks"] == []
    finding = Finding(type="certificate", algorithm="RSA", file="server.crt", line=1,
                      evidence="X.509 certificate", usage="certificate_public_key")
    result = analyze(AnalysisRequest(crypto_findings=[finding]))
    assert result["findings"][0]["status"] == "confirmed"
    assert any("Certificate" in risk for risk in result["report"]["compatibility_risks"])
    assert any("sign/verify" in step for step in result["report"]["testing_steps"])
    assert result["report"]["disclaimer"] == "A CryptoNexus scan does not prove that a system is quantum-safe."
