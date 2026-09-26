import pytest

from app.config_scanner import scan_config, unique_findings
from app.dependency_scanner import scan_dependencies
from app.metadata_scanner import scan_metadata


@pytest.mark.parametrize("value,expected", [("SSL", "SSL"), ("SSLv2", "SSL 2"),
    ("SSLv3", "SSL 3"), ("TLS", "TLS"), ("TLSv1", "TLS 1.0"), ("TLSv1.0", "TLS 1.0"),
    ("TLSv1.1", "TLS 1.1"), ("TLSv1.2", "TLS 1.2"), ("TLSv1.3", "TLS 1.3"),
    ("TLS 1.0", "TLS 1.0"), ("TLS 1.1", "TLS 1.1"),
    ("TLS 1.2", "TLS 1.2"), ("TLS 1.3", "TLS 1.3"), ("TLS1_3", "TLS 1.3")])
def test_protocols(value, expected):
    findings = scan_config(f'# header\nprotocol = "{value}"', "server.conf")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.protocol == expected
    assert finding.type == "protocol" and finding.line == 2
    assert finding.file == "server.conf"
    assert finding.evidence == f'protocol = "{value}"'
    assert finding.evidence_type == "direct" and finding.status == "confirmed"
    assert finding.usage is None and finding.key_size is None


@pytest.mark.parametrize("version", ["1.2", "1.3"])
def test_yaml_tls_version_protocol_regression(version):
    evidence = f"tls_version: TLSv{version}"
    findings = scan_config(f"# security settings\n{evidence}\n", "security.yaml")
    assert len(findings) == 1
    finding = findings[0]
    assert finding.type == "protocol" and finding.protocol == f"TLS {version}"
    assert finding.file == "security.yaml" and finding.line == 2
    assert finding.evidence == evidence
    assert finding.evidence_type == "direct" and finding.status == "confirmed"


@pytest.mark.parametrize("value", ["TLSv1.20", "TLSv1.9", "TLSv1.2.3", "a story about TLSv1.2"])
def test_tls_version_does_not_match_partial_versions_or_prose(value):
    assert scan_config(f'tls_version: "{value}"', "security.yaml") == []


@pytest.mark.parametrize("file,source", [
    ("a.json", '{"server": {"tls": {"minVersion": "TLSv1.2"}}}'),
    ("a.yaml", 'server:\n  tls:\n    minVersion: TLSv1.2'),
    ("a.yml", 'protocols:\n  - TLSv1.2'),
    ("a.toml", '[server.tls]\nminVersion = "TLSv1.2"'),
    ("a.ini", '[server]\nssl_protocol = TLSv1.2'),
    ("a.conf", 'ssl_protocols TLSv1.2;'),
])
def test_config_formats(file, source):
    assert [f.protocol for f in scan_config(source, file)] == ["TLS 1.2"]


@pytest.mark.parametrize("suite,expected", [
    ("TLS_RSA_WITH_AES_128_GCM_SHA256", {"RSA", "AES", "SHA256"}),
    ("ECDHE-RSA-AES256-GCM-SHA384", {"ECDH", "RSA", "AES", "SHA384"}),
    ("TLS_AES_256_GCM_SHA384", {"AES", "SHA384"}),
])
def test_cipher_suite(suite, expected):
    findings = scan_config(f'cipher_suites = "{suite}"', "server.toml")
    assert {f.algorithm for f in findings if f.type == "algorithm"} == expected
    assert [f.reference for f in findings if f.type == "cipher_suite"] == [suite]
    assert all(f.key_size is None and f.usage is None for f in findings)


@pytest.mark.parametrize("name,expected", [("RSA", "RSA"), ("EC", "ECC"), ("ECC", "ECC"),
    ("ECDSA", "ECDSA"), ("ECDH", "ECDH"), ("AES", "AES"), ("DES", "DES"),
    ("3DES", "3DES"), ("ChaCha20", "ChaCha20"), ("MD5", "MD5"),
    ("SHA1", "SHA1"), ("SHA256", "SHA256"), ("SHA384", "SHA384"), ("SHA512", "SHA512")])
def test_explicit_algorithm(name, expected):
    findings = scan_config(f'algorithm: "{name}"', "a.yaml")
    assert len(findings) == 1 and findings[0].algorithm == expected


@pytest.mark.parametrize("key,value,kind", [
    ("ssl_certificate", "/etc/ssl/server.crt", "certificate_path"),
    ("certificate", "certs/server.pem", "certificate_path"),
    ("caFile", "certs/ca.cer", "certificate_path"),
    ("ssl_certificate_key", "/etc/ssl/server.pem", "key_path"),
    ("private_key", "keys/private.key", "key_path"),
    ("publicKeyFile", "keys/public.pub", "key_path"),
])
def test_path_references(key, value, kind):
    findings = scan_config(f'{key} = "{value}"', "server.ini")
    assert len(findings) == 1
    assert findings[0].type == kind and findings[0].reference == value


def test_provider():
    findings = scan_config('security.provider.1=org.bouncycastle.jce.provider.BouncyCastleProvider', 'security.conf')
    assert len(findings) == 1 and findings[0].type == "provider"
    assert findings[0].library == "org.bouncycastle.jce.provider.BouncyCastleProvider"


@pytest.mark.parametrize("source,file", [
    ('{"description":"TLSv1.2 RSA AES", "name":"crypto-js"}', "package.json"),
    ('message: "RSA is a name"\nnotes: "TLSv1.3"\nprovider: AWS', "a.yaml"),
    ('# ssl_protocols TLSv1.2\nname = "AES"', "a.toml"),
    ('notes: |\n  protocol: TLSv1.2\n  cipher: RSA\nport: 443', "a.yml"),
    ('{"text": "\\\"cipher\\\": \\\"RSA\\\""}', "a.json"),
    ('{"protocol": "TLSv1.2"', "a.json"),
    ('algorithm = RSACompany\nprotocol = TLSv1.20', "a.conf"),
    ('protocol = "a story mentioning TLSv1.2"\nalgorithm = "RSA is a mascot"', "a.conf"),
    ('description = """\nprotocol = TLSv1.2\ncipher = RSA\n"""', "a.toml"),
])
def test_unrelated_config(source, file):
    assert scan_config(source, file) == []


def test_comments_and_json_line_numbers():
    assert scan_config('port = 443 # TLSv1.2\n; cipher = RSA', "a.ini") == []
    source = '{\n  "protocols": [\n    "TLSv1.2",\n    "TLSv1.3"\n  ]\n}'
    findings = scan_config(source, "a.json")
    assert [(f.protocol, f.line) for f in findings] == [("TLS 1.2", 3), ("TLS 1.3", 4)]


@pytest.mark.parametrize("package", ["cryptography", "pycryptodome", "pycrypto", "pynacl"])
def test_python_requirements(package):
    findings = scan_dependencies(f'# packages\n{package}>=1.0; python_version >= "3.10"\nrequests', "requirements.txt")
    assert len(findings) == 1 and findings[0].library == package
    assert findings[0].line == 2 and findings[0].type == "dependency"
    assert findings[0].algorithm is None and findings[0].usage is None


@pytest.mark.parametrize("source", [
    '[project]\ndependencies = ["cryptography>=42"]',
    '[project]\ndependencies = [\n "cryptography>=42",\n]',
    '[project.optional-dependencies]\nsecurity = ["cryptography>=42"]',
    '[tool.poetry.dependencies]\ncryptography = "^42"',
    '[tool.poetry.group.dev.dependencies]\ncryptography = "^42"',
    '[dependency-groups]\ntest = ["cryptography"]',
])
def test_pyproject(source):
    findings = scan_dependencies(source, "pyproject.toml")
    assert len(findings) == 1 and findings[0].library == "cryptography"


@pytest.mark.parametrize("package", ["crypto-js", "node-forge", "bcrypt", "jose"])
def test_javascript_dependencies(package):
    source = '{\n  "dependencies": {\n    "' + package + '": "^1.0.0"\n  }\n}'
    findings = scan_dependencies(source, "package.json")
    assert len(findings) == 1 and findings[0].library == package
    assert findings[0].line == 3 and findings[0].evidence_type == "direct"


def test_java_dependencies():
    source = ('<project>\n<dependencies>\n<dependency>\n'
              '<groupId>org.bouncycastle</groupId>\n<artifactId>bcprov-jdk18on</artifactId>\n'
              '</dependency>\n</dependencies>\n</project>')
    findings = scan_dependencies(source, "pom.xml")
    assert len(findings) == 1 and findings[0].library == "org.bouncycastle:bcprov-jdk18on"
    assert findings[0].line == 3
    assert '<artifactId>bcprov-jdk18on</artifactId>' in findings[0].evidence


@pytest.mark.parametrize("source,line", [
    ('module example.com/app\nrequire golang.org/x/crypto v0.30.0', 2),
    ('require (\n  golang.org/x/crypto v0.30.0 // indirect\n)', 2),
])
def test_go_dependencies(source, line):
    findings = scan_dependencies(source, "go.mod")
    assert len(findings) == 1 and findings[0].library == "golang.org/x/crypto"
    assert findings[0].line == line


@pytest.mark.parametrize("file,source", [
    ("requirements.txt", '# cryptography\nnot-cryptography==1.0\n-r cryptography.txt'),
    ("pyproject.toml", '[project]\ndescription = "cryptography"\nname = "pynacl"'),
    ("package.json", '{"name":"crypto-js", "description":"node-forge", "scripts":{"bcrypt":"test"}}'),
    ("package.json", '{"dependencies":{"not-crypto-js":"1.0"}}'),
    ("pom.xml", '<project><!-- <dependency><groupId>org.bouncycastle</groupId><artifactId>bcprov-jdk18on</artifactId></dependency> --></project>'),
    ("pom.xml", '<project><description>bcprov-jdk18on</description></project>'),
    ("go.mod", 'module golang.org/x/crypto\n// require golang.org/x/crypto v0.30.0'),
    ("go.mod", 'replace golang.org/x/crypto => example.com/replacement v1.0.0'),
])
def test_unrelated_dependency_text(file, source):
    assert scan_dependencies(source, file) == []


def test_metadata_overlap_and_dedup(tmp_path):
    source = '{"dependencies":{"crypto-js":"1.0"},"tls":{"protocols":["TLSv1.2","TLSv1.2"]}}'
    (tmp_path / "package.json").write_text(source)
    findings = scan_metadata(tmp_path, ["package.json", "package.json"], ["package.json"])
    assert len(findings) == 2
    assert {f.type for f in findings} == {"dependency", "protocol"}
    assert len(unique_findings(findings + findings)) == 2


def test_metadata_size_limit(tmp_path, monkeypatch):
    from app import metadata_scanner
    monkeypatch.setattr(metadata_scanner, "MAX_METADATA_BYTES", 10)
    (tmp_path / "a.conf").write_text('protocol TLSv1.2')
    assert scan_metadata(tmp_path, ["a.conf"], []) == []
