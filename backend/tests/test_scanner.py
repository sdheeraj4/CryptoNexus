import pytest

from app.scanner import scan_repository, scan_source


def algorithms(source, extension="py"):
    return [f for f in scan_source(source, f"src/example.{extension}") if f.type == "algorithm"]


@pytest.mark.parametrize("source,extension,algorithm,usage,size", [
    ("RSA.generate(2048)", "py", "RSA", "key_generation", 2048),
    ("hashlib.sha256(data)", "py", "SHA256", "hashing", None),
    ("AES.new(key, AES.MODE_GCM)", "py", "AES", None, None),
    ('Cipher.getInstance("AES/GCM/NoPadding")', "java", "AES", None, None),
    ('crypto.createHash("sha256")', "js", "SHA256", "hashing", None),
    ('crypto.createHash("sha256")', "ts", "SHA256", "hashing", None),
    ('crypto.createCipheriv("aes-256-gcm", key, iv)', "ts", "AES", "encryption", 256),
    ('crypto.createDecipheriv("aes-128-cbc", key, iv)', "js", "AES", "decryption", 128),
    ('crypto.generateKeyPairSync("rsa", {modulusLength: 4096})', "js", "RSA", "key_generation", 4096),
    ('crypto.createECDH("prime256v1")', "js", "ECDH", "key_exchange", None),
    ('crypto.publicEncrypt(key, data)', "js", "RSA", "encryption", None),
    ('crypto.privateDecrypt(key, data)', "js", "RSA", "decryption", None),
    ('rsa.generate_private_key(public_exponent=65537, key_size=3072)', "py", "RSA", "key_generation", 3072),
    ('rsa.generate_private_key(65537, 2048)', "py", "RSA", "key_generation", 2048),
    ('ec.generate_private_key(ec.SECP256R1())', "py", "ECC", "key_generation", None),
    ('ec.ECDSA(hashes.SHA256())', "py", "ECDSA", None, None),
    ('ec.ECDH()', "py", "ECDH", "key_exchange", None),
    ('KeyAgreement.getInstance("ECDH")', "java", "ECDH", "key_exchange", None),
    ('KeyPairGenerator.getInstance("EC")', "java", "ECC", "key_generation", None),
    ('CryptoJS.AES.encrypt(data, key)', "js", "AES", "encryption", None),
])
def test_direct_calls(source, extension, algorithm, usage, size):
    findings = algorithms(source, extension)
    finding = next(f for f in findings if f.algorithm == algorithm)
    assert finding.usage == usage
    assert finding.key_size == size
    assert finding.line == 1
    assert finding.file == f"src/example.{extension}"
    assert finding.evidence in source
    assert finding.evidence_type == "direct" and finding.status == "confirmed"


@pytest.mark.parametrize("name,expected", [("AES", "AES"), ("DES", "DES"), ("DES3", "3DES"),
    ("TripleDES", "3DES"), ("ChaCha20", "ChaCha20"), ("ECC", "ECC")])
def test_python_mechanisms(name, expected):
    method = "generate" if name == "ECC" else "new"
    assert algorithms(f"{name}.{method}(key)")[0].algorithm == expected


@pytest.mark.parametrize("name", ["md5", "sha1", "sha224", "sha256", "sha384", "sha512"])
@pytest.mark.parametrize("extension", ["py", "java", "js"])
def test_hash_algorithms(name, extension):
    source = {"py": f"hashlib.{name}(data)", "java": f'MessageDigest.getInstance("{name}")',
              "js": f'crypto.createHash("{name}")'}[extension]
    finding = algorithms(source, extension)[0]
    assert finding.algorithm == name.upper()
    assert finding.usage == "hashing"


@pytest.mark.parametrize("source,extension,expected", [
    ("import hashlib as h\nh.sha256(data)", "py", "SHA256"),
    ("from hashlib import sha512 as digest\ndigest(data)", "py", "SHA512"),
    ("from Crypto.Cipher import AES as A\nA.new(key, A.MODE_GCM)", "py", "AES"),
    ("from cryptography.hazmat.primitives.asymmetric import rsa as r\nr.generate_private_key(65537, 2048)", "py", "RSA"),
    ('const c = require("crypto"); c.createHash("md5");', "js", "MD5"),
    ('import * as c from "node:crypto"; c.createHash("sha384");', "ts", "SHA384"),
    ('import {createHash as hash} from "crypto"; hash("sha224");', "js", "SHA224"),
    ('import {createHash} from "crypto"; createHash("sha1");', "ts", "SHA1"),
    ('import C from "crypto-js"; C.TripleDES.decrypt(data, key);', "js", "3DES"),
])
def test_import_aliases(source, extension, expected):
    assert algorithms(source, extension)[0].algorithm == expected
    assert any(f.type == "library" for f in scan_source(source, f"test.{extension}"))


@pytest.mark.parametrize("source,extension,library", [
    ("import hashlib", "py", "hashlib"), ("import ssl", "py", "ssl"),
    ("from cryptography.hazmat.primitives import hashes", "py", "cryptography"),
    ("from Crypto.Cipher import AES", "py", "Crypto"),
    ("from Cryptodome.Cipher import AES", "py", "Cryptodome"),
    ("import java.security.*;", "java", "java.security"),
    ("import javax.crypto.Cipher;", "java", "javax.crypto"),
    ('import "crypto-js";', "js", "crypto-js"),
])
def test_library_imports(source, extension, library):
    findings = scan_source(source, f"test.{extension}")
    assert len(findings) == 1
    assert findings[0].library == library
    assert findings[0].algorithm is None
    assert findings[0].usage is None and findings[0].key_size is None


@pytest.mark.parametrize("source,extension", [
    ('# RSA.generate(2048)\ntext = "RSA AES SHA256"', "py"),
    ('text = "hashlib.sha256(data)"', "py"),
    ('"""RSA.generate(2048)\nimport ssl\n"""', "py"),
    ('// crypto.createHash("md5")\nconst text = "RSA";', "js"),
    ('/* Cipher.getInstance("AES"); */ String text = "RSA";', "java"),
    ('const text = `crypto.createHash("sha256")`;', "ts"),
    ('const text = "import crypto from \\"crypto\\"";', "js"),
    ('print("RSA.generate(2048)")', "py"),
    ('logger.info("RSA");', "java"),
    ('mycrypto.createHash("sha256");', "js"),
    ('crypto.createHash("a story about RSA");', "js"),
    ('text = "SHA256"\nRSA = "example"', "py"),
])
def test_comments_and_strings_are_not_findings(source, extension):
    assert scan_source(source, f"test.{extension}") == []


def test_multiline_evidence_and_line_number():
    source = '# comment\n\nkey = RSA.generate(\n    2048\n)\n'
    finding = algorithms(source)[0]
    assert finding.line == 3
    assert finding.evidence == "RSA.generate(\n    2048\n)"
    assert finding.key_size == 2048


@pytest.mark.parametrize("method,usage", [("encrypt", "encryption"), ("decrypt", "decryption"),
    ("sign", "signing"), ("verify", "verification")])
def test_simple_object_operations(method, usage):
    source = f"key = RSA.generate(2048)\nkey.{method}(data)"
    finding = algorithms(source)[-1]
    assert finding.usage == usage and finding.key_size == 2048
    assert finding.line == 2


def test_java_cipher_init_and_signature():
    source = ('Cipher c = Cipher.getInstance("AES/GCM/NoPadding");\n'
              'c.init(Cipher.ENCRYPT_MODE, key);\n'
              'Signature s = Signature.getInstance("SHA256withECDSA");\ns.initVerify(key);')
    findings = algorithms(source, "java")
    assert any(f.algorithm == "AES" and f.usage == "encryption" for f in findings)
    assert any(f.algorithm == "ECDSA" and f.usage == "verification" for f in findings)
    assert any(f.algorithm == "SHA256" for f in findings)


def test_dynamic_sizes_and_algorithms_are_unknown():
    assert algorithms("RSA.generate(bits)")[0].key_size is None
    assert algorithms('crypto.createHash(algorithm)', "js") == []
    assert algorithms('Cipher.getInstance(algorithm)', "java") == []


def test_reassignment_does_not_reuse_algorithm():
    assert len(algorithms("key = RSA.generate(2048)\nkey = other\nkey.sign(data)")) == 1


def test_bounded_file_scan_and_unsupported_languages(tmp_path, monkeypatch):
    from app import scanner
    monkeypatch.setattr(scanner, "MAX_SOURCE_BYTES", 30)
    (tmp_path / "huge.py").write_text("RSA.generate(2048)" + " " * 31)
    (tmp_path / "main.py").write_text("RSA.generate(2048)")
    (tmp_path / "ignored.go").write_text("RSA.generate(2048)")
    findings = scan_repository(tmp_path, ["huge.py", "main.py", "ignored.go"])
    assert len(findings) == 1 and findings[0].file == "main.py"


def test_token_limit(monkeypatch):
    from app import scanner
    monkeypatch.setattr(scanner, "MAX_TOKENS", 2)
    assert algorithms("RSA.generate(2048)") == []


@pytest.mark.parametrize("descriptor,expected", [("RSA/ECB/PKCS1Padding", "RSA"),
    ("DES/CBC/PKCS5Padding", "DES"), ("DESede/CBC/PKCS5Padding", "3DES"),
    ("ChaCha20", "ChaCha20")])
def test_java_cipher_algorithms(descriptor, expected):
    assert algorithms(f'Cipher.getInstance("{descriptor}")', "java")[0].algorithm == expected


def test_node_composite_signature_and_unknown_ec_size():
    findings = algorithms('crypto.createSign("RSA-SHA256")', "js")
    assert {f.algorithm for f in findings} == {"RSA", "SHA256"}
    assert all(f.usage == "signing" for f in findings)
    finding = algorithms('crypto.generateKeyPairSync("ec", {namedCurve: "P-256", length: 42})', "js")[0]
    assert finding.algorithm == "ECC" and finding.key_size is None


def test_es_import_produces_one_library_finding():
    findings = scan_source('import crypto from "node:crypto";', "test.js")
    assert len(findings) == 1
    assert findings[0].library == "node:crypto"


@pytest.mark.parametrize("options", ["{modulusLength: 2048 * 2}",
    "{nested: {modulusLength: 2048}}", "{modulusLength: 2048, ...options}",
    "{modulusLength: 2048, modulusLength: bits}"])
def test_key_size_expressions_are_not_literals(options):
    finding = algorithms(f'crypto.generateKeyPairSync("rsa", {options})', "js")[0]
    assert finding.key_size is None


@pytest.mark.parametrize("extension", ["js", "ts"])
def test_hash_finalization_does_not_duplicate_algorithm(extension):
    source = ('const hash = crypto.createHash("sha256");\n'
              'hash.update(data);\nconst result = hash.digest("hex");\n'
              'hash.final();\nresult.verify(signature);')
    findings = algorithms(source, extension)
    assert len(findings) == 1
    assert findings[0].algorithm == "SHA256"
    assert findings[0].evidence == 'crypto.createHash("sha256")'
    assert findings[0].line == 1 and findings[0].status == "confirmed"


@pytest.mark.parametrize("extension", ["py", "js", "ts", "java"])
@pytest.mark.parametrize("method", ["update", "digest", "final", "verify"])
def test_generic_operations_without_context_do_not_identify_algorithms(extension, method):
    assert algorithms(f'unknown.{method}("SHA256")', extension) == []


@pytest.mark.parametrize("extension", ["js", "ts"])
def test_verification_requires_direct_or_linked_algorithm(extension):
    direct = algorithms('crypto.verify("sha256", data, key, signature)', extension)
    assert len(direct) == 1 and direct[0].algorithm == "SHA256"
    linked = algorithms('const verifier = crypto.createVerify("RSA-SHA256");\n'
                        'verifier.verify(key, signature);', extension)
    assert {f.algorithm for f in linked if f.line == 2} == {"RSA", "SHA256"}
    reassigned = algorithms('let verifier = crypto.createVerify("RSA-SHA256");\n'
                            'verifier = other;\nverifier.verify(key, signature);', extension)
    assert all(f.line == 1 for f in reassigned)
