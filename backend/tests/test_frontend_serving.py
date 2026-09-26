import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.report import DISCLAIMER


@pytest.mark.parametrize("path,expected", [("/", "PQC Migration Intelligence"),
    ("/style.css", "--viridian"), ("/script.js", '/api/sandbox/run'), ("/docs", "swagger-ui")])
def test_frontend_assets_and_docs_are_served(path, expected):
    response = TestClient(app).get(path)
    assert response.status_code == 200
    assert expected in response.text


def test_analyze_contract_with_frontend_mounted():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        archive.writestr("main.py", "RSA.generate(2048)")
    client = TestClient(app)
    response = client.post("/api/analyze", files={"file": ("repo.zip", stream.getvalue(), "application/zip")})
    assert response.status_code == 200
    result = response.json()
    assert {"findings", "dependencies", "migration_checklist", "migration_graph", "summary", "report"} <= result.keys()
    assert result["findings"][0]["status"] == "confirmed"
    assert result["report"]["disclaimer"] == DISCLAIMER
    assert {"limitations", "compatibility_risks", "testing_steps", "disclaimer"} == result["report"].keys()
    assert client.get("/health").json() == {"status": "ok", "service": "CryptoNexus"}
