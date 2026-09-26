import io
import stat
import zipfile

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app import uploads

client = TestClient(app)


def make_zip(files):
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        for name, content in files.items():
            archive.writestr(name, content)
    return stream.getvalue()


def post_zip(data, filename="sample.zip"):
    return client.post("/api/upload", files={"file": (filename, data, "application/zip")})


def test_health():
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok", "service": "CryptoNexus"}


def test_valid_zip_and_cleanup(tmp_path, monkeypatch):
    monkeypatch.setattr(uploads.tempfile, "tempdir", str(tmp_path))
    response = post_zip(make_zip({
        "repo/main.py": "raise Exception('Never execute me')",
        "repo/settings.yaml": "hello: world",
        "repo/cert.pem": "certificate placeholder",
        "repo/requirements.txt": "fastapi",
        "repo/package.json": "{}",
        "repo/README.md": "hello",
        **{f"repo/{directory}/ignored.py": "" for directory in uploads.IGNORED_DIRS},
    }))
    assert response.status_code == 200
    assert response.json() == {
        "project_name": "sample", "total_files": 6,
        "source_files": ["repo/main.py"],
        "config_files": ["repo/package.json", "repo/settings.yaml"],
        "certificate_files": ["repo/cert.pem"],
        "dependency_files": ["repo/package.json", "repo/requirements.txt"],
        "crypto_findings": [], "finding_count": 0,
        "certificate_scan_issues": [{"file": "repo/cert.pem", "line": None,
                                     "status": "skipped", "reason": "invalid_or_unsupported_certificate"}],
    }
    assert list(tmp_path.iterdir()) == []


@pytest.mark.parametrize("data", [b"", b"not a zip", b"PK\x03\x04broken"])
def test_invalid_zip(data):
    assert post_zip(data).status_code == 400


@pytest.mark.parametrize("path", ["../escape.py", "repo/../../escape.py",
    "/absolute.py", "C:/escape.py", "..\\escape.py", "repo/file:stream",
    "repo/NUL.txt", "repo/.git/../../escape.py"])
def test_path_traversal_rejected(path, tmp_path, monkeypatch):
    monkeypatch.setattr(uploads.tempfile, "tempdir", str(tmp_path))
    response = post_zip(make_zip({"good.py": "", path: "bad"}))
    assert response.status_code == 400
    assert list(tmp_path.iterdir()) == []


def test_symlink_rejected():
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w") as archive:
        entry = zipfile.ZipInfo("link")
        entry.create_system = 3
        entry.external_attr = (stat.S_IFLNK | 0o777) << 16
        archive.writestr(entry, "../outside")
    assert post_zip(stream.getvalue()).status_code == 400


def test_upload_limit(monkeypatch):
    monkeypatch.setattr(uploads, "MAX_UPLOAD_BYTES", 32)
    assert post_zip(make_zip({"main.py": "x" * 64})).status_code == 413


def test_expansion_limit(monkeypatch):
    monkeypatch.setattr(uploads, "MAX_EXTRACTED_BYTES", 32)
    assert post_zip(make_zip({"main.py": "x" * 64})).status_code == 413


def test_entry_limit(monkeypatch):
    monkeypatch.setattr(uploads, "MAX_ENTRIES", 1)
    assert post_zip(make_zip({"a.py": "", "b.py": ""})).status_code == 413


def test_request_limit():
    response = client.post("/api/upload", content=b"x",
                           headers={"Content-Length": str(22 * 1024 * 1024)})
    assert response.status_code == 413


def test_streamed_request_limit(monkeypatch):
    from app import main
    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 32)
    body = (b'--boundary\r\nContent-Disposition: form-data; name="file"; '
            b'filename="sample.zip"\r\nContent-Type: application/zip\r\n\r\n'
            + b"x" * (1024 * 1024 + 64) + b"\r\n--boundary--\r\n")
    response = client.post("/api/upload", content=iter([body]), headers={
        "Content-Type": "multipart/form-data; boundary=boundary",
    })
    assert response.status_code == 413
    assert "error" in response.json()


def test_missing_file():
    assert client.post("/api/upload").status_code == 422


def test_wrong_extension():
    assert post_zip(make_zip({"a.py": ""}), "a.txt").status_code == 400


def test_upload_scans_supported_sources_before_cleanup(tmp_path, monkeypatch):
    monkeypatch.setattr(uploads.tempfile, "tempdir", str(tmp_path))
    response = post_zip(make_zip({
        "src/auth.py": "from Crypto.PublicKey import RSA\nkey = RSA.generate(2048)\n",
        "src/hash.ts": 'import crypto from "node:crypto";\ncrypto.createHash("sha256");',
        "src/Cipher.java": 'Cipher.getInstance("AES/GCM/NoPadding");',
        "src/unused.go": 'crypto.createHash("md5")',
        "node_modules/bad.js": 'crypto.createHash("md5")',
        "cert.pem": 'RSA.generate(1024)',
    }))
    assert response.status_code == 200
    result = response.json()
    assert result["total_files"] == 5
    assert len(result["source_files"]) == 4
    assert result["certificate_files"] == ["cert.pem"]
    assert result["finding_count"] == len(result["crypto_findings"]) == 5
    assert {f["algorithm"] for f in result["crypto_findings"] if f["type"] == "algorithm"} == {"RSA", "AES", "SHA256"}
    rsa = next(f for f in result["crypto_findings"] if f["algorithm"] == "RSA")
    assert rsa["file"] == "src/auth.py"
    assert rsa["line"] == 2 and rsa["key_size"] == 2048
    assert list(tmp_path.iterdir()) == []


def test_upload_combines_source_config_and_dependencies(tmp_path, monkeypatch):
    monkeypatch.setattr(uploads.tempfile, "tempdir", str(tmp_path))
    response = post_zip(make_zip({
        "main.py": "RSA.generate(2048)",
        "server.conf": 'ssl_protocols TLSv1.2 TLSv1.3;\nssl_certificate certs/server.pem;',
        "requirements.txt": "cryptography>=42",
        "package.json": '{"dependencies":{"crypto-js":"1.0"}}',
        "certs/server.pem": "not parsed as a certificate",
        "node_modules/ignored/package.json": '{"dependencies":{"node-forge":"1.0"}}',
    }))
    assert response.status_code == 200
    result = response.json()
    assert result["total_files"] == 5
    assert result["certificate_files"] == ["certs/server.pem"]
    findings = result["crypto_findings"]
    assert result["finding_count"] == len(findings) == 6
    assert {f["type"] for f in findings} == {"algorithm", "protocol", "certificate_path", "dependency"}
    assert {f["library"] for f in findings if f["type"] == "dependency"} == {"cryptography", "crypto-js"}
    assert findings[0]["algorithm"] == "RSA" and findings[0]["key_size"] == 2048
    assert list(tmp_path.iterdir()) == []
