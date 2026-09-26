"""Deterministic, bounded source scanning. Never imports or executes repository code."""

import logging
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from pydantic import BaseModel

logger = logging.getLogger(__name__)
SUPPORTED_EXTENSIONS = {".py", ".js", ".ts", ".java"}
MAX_SOURCE_BYTES = 2 * 1024 * 1024
MAX_TOKENS = 200_000
HASHES = {"MD5", "SHA1", "SHA224", "SHA256", "SHA384", "SHA512"}
ALGORITHMS = HASHES | {"RSA", "ECC", "ECDSA", "ECDH", "AES", "DES", "3DES", "ChaCha20"}
OPERATIONS = {"encrypt": "encryption", "decrypt": "decryption", "sign": "signing",
              "verify": "verification", "exchange": "key_exchange",
              "digest": "hashing", "hexdigest": "hashing",
              "initSign": "signing", "initVerify": "verification"}
TOKEN = re.compile(
    r"(?P<space>\s+)|(?P<comment>\#[^\n]*|//[^\n]*|/\*[\s\S]*?(?:\*/|$))"
    r"|(?P<string>\"\"\"[\s\S]*?(?:\"\"\"|$)|'''[\s\S]*?(?:'''|$)"
    r"|\"(?:\\[\s\S]|[^\"\\])*\"|'(?:\\[\s\S]|[^'\\])*'|`(?:\\[\s\S]|[^`\\])*`)"
    r"|(?P<word>[A-Za-z_$][\w$]*)|(?P<number>\d+)|(?P<punct>.)"
)


class Finding(BaseModel):
    type: Literal["algorithm", "library", "protocol", "cipher_suite", "certificate_path", "key_path", "provider", "dependency", "certificate"]
    algorithm: str | None = None
    library: str | None = None
    protocol: str | None = None
    reference: str | None = None
    usage: str | None = None
    file: str
    line: int | None
    key_size: int | None = None
    evidence: str
    evidence_type: Literal["direct"] = "direct"
    status: Literal["confirmed"] = "confirmed"
    subject: str | None = None
    issuer: str | None = None
    serial_number: str | None = None
    signature_algorithm: str | None = None
    valid_from: str | None = None
    valid_until: str | None = None


@dataclass
class Token:
    value: str
    kind: str
    line: int
    start: int
    end: int


def literal(tokens: list[Token]) -> str | None:
    if len(tokens) == 1 and tokens[0].kind == "string":
        value = tokens[0].value
        if value[0] in "\"'" and not value.startswith(('"""', "'''")):
            return value[1:-1]
    return None


def mechanisms(value: str | None) -> list[str]:
    if not value:
        return []
    value = value.upper().replace("-", "").replace("_", "")
    if re.fullmatch(r"RSA(?:MD5|SHA1|SHA224|SHA256|SHA384|SHA512)", value):
        return ["RSA", value[3:]]
    # Accept algorithm descriptors, not arbitrary prose containing a name.
    if signature := re.fullmatch(r"(MD5|SHA1|SHA224|SHA256|SHA384|SHA512)WITH(RSA|ECDSA)(?:/PSS)?", value):
        return [signature[1], signature[2]]
    head = value.split("/")[0]
    aliases = {"EC": "ECC", "DESEDE": "3DES", "DES3": "3DES", "TRIPLEDES": "3DES",
               "CHACHA20": "ChaCha20", "RSA": "RSA"}
    if head in aliases:
        return [aliases[head]]
    if head in ALGORITHMS:
        return [head]
    if re.fullmatch(r"AES(?:128|192|256)(?:GCM|CBC|CTR|CFB|OFB|ECB)?", head):
        return ["AES"]
    if head == "CHACHA20POLY1305":
        return ["ChaCha20"]
    return []


def arguments(tokens: list[Token], opening: int):
    """Read a bounded call, preserving nested arguments and literal positions."""
    args: list[list[Token]] = [[]]
    depth = 0
    for index in range(opening + 1, min(len(tokens), opening + 513)):
        token = tokens[index]
        value = token.value if token.kind != "string" else ""
        if value == ")" and depth == 0:
            return args, index
        if value == "," and depth == 0:
            args.append([])
            continue
        if value in {"(", "[", "{"}:
            depth += 1
        elif value in {")", "]", "}"}:
            depth -= 1
        args[-1].append(token)
    return None


def integer(token: Token) -> int | None:
    # Bound conversion of untrusted digit sequences; sizes are literal bit counts.
    if token.kind == "number" and len(token.value) <= 6:
        value = int(token.value)
        return value if value > 0 else None
    return None


def scan_source(source: str, file: str) -> list[Finding]:
    """Scan one supported source file; findings are direct syntax evidence, not runtime proof."""
    extension = Path(file).suffix.lower()
    if extension not in SUPPORTED_EXTENSIONS:
        return []
    tokens = []
    line = 1
    for match in TOKEN.finditer(source):
        kind = match.lastgroup
        value = match.group()
        if kind not in {"space", "comment"}:
            tokens.append(Token(value, kind, line, match.start(), match.end()))
            if len(tokens) > MAX_TOKENS:
                logger.warning("Source token limit reached; file skipped")
                return []
        line += value.count("\n")
    findings: list[Finding] = []
    aliases: dict[str, str] = {}
    objects: dict[str, tuple[list[str], int | None]] = {}

    def emit(start, end, *, algorithm=None, library=None, usage=None, key_size=None):
        findings.append(Finding(type="library" if library else "algorithm", algorithm=algorithm,
            library=library, usage=usage, file=file, line=start.line, key_size=key_size,
            evidence=source[start.start:end.end].strip()[:300]))

    def library_name(module):
        return next((name for name in ("hashlib", "cryptography", "Crypto", "Cryptodome", "ssl",
                     "java.security", "javax.crypto", "node:crypto", "crypto-js", "crypto")
                     if module == name or module.startswith(name + ".")), None)

    # Python/Java imports contain no meaningful string literals.
    for i, token in enumerate(tokens):
        if token.value not in {"from", "import"} or token.kind != "word":
            continue
        if extension in {".py", ".java"}:
            row = []
            for item in tokens[i:]:
                if item.line != token.line or item.value == ";":
                    break
                row.append(item)
            text = "".join(t.value for t in row)
            if extension == ".java":
                module = text.removeprefix("import").removeprefix("static")
                if library := library_name(module):
                    emit(token, row[-1], library=library)
                continue
            # Token spacing preserves 'as' and comma separated import names.
            words = " ".join(t.value for t in row)
            match = re.fullmatch(r"from (.+?) import (.+)", words)
            module = match[1].replace(" ", "") if match else ""
            imported = match[2] if match else words.removeprefix("import ")
            if token.value == "from" and not match:
                continue
            if token.value == "import" and i and tokens[i - 1].line == token.line:
                continue
            for name in imported.split(","):
                pair = name.strip().split(" as ")
                full = (module + "." if module else "") + pair[0].replace(" ", "")
                if library := library_name(full):
                    local = pair[-1].strip() if len(pair) == 2 else (
                        pair[0].strip() if module else full.split(".")[0])
                    aliases[local] = full if module or len(pair) == 2 else local
                    emit(token, row[-1], library=library)
        else:
            # ES default, namespace, side-effect, and named imports.
            if token.value != "import":
                continue
            end = i + 1
            while end < min(len(tokens), i + 40) and tokens[end].value != ";":
                if tokens[end].kind == "string":
                    break
                end += 1
            if end >= len(tokens) or tokens[end].kind != "string":
                continue
            module = literal([tokens[end]])
            if module not in {"crypto", "node:crypto", "crypto-js"}:
                continue
            emit(token, tokens[end], library=module)
            body = tokens[i + 1:end]
            if body and body[0].kind == "word" and body[0].value != "from":
                aliases[body[0].value] = module
            for j, item in enumerate(body):
                if item.value == "as" and j + 1 < len(body):
                    original = body[j - 1].value
                    aliases[body[j + 1].value] = module if original == "*" else module + "." + original
                elif j and body[j - 1].value in {"{", ","} and item.kind == "word":
                    aliases[item.value] = module + "." + item.value

    for i, token in enumerate(tokens):
        if i + 1 < len(tokens) and tokens[i + 1].value == "=" and token.kind == "word":
            objects.pop(token.value, None)
        if token.kind != "word" or (i and tokens[i - 1].value == "."):
            continue
        end = i
        names = [token.value]
        while end + 2 < len(tokens) and tokens[end + 1].value == "." and tokens[end + 2].kind == "word":
            names.append(tokens[end + 2].value)
            end += 2
        if end + 1 >= len(tokens) or tokens[end + 1].value != "(":
            continue
        parsed = arguments(tokens, end + 1)
        if not parsed:
            continue
        args, closing = parsed
        target = tokens[i - 2].value if i >= 2 and tokens[i - 1].value == "=" else None
        canonical = ".".join([aliases.get(names[0], names[0]), *names[1:]])
        parts = canonical.split(".")
        method = parts[-1]
        owner = parts[-2] if len(parts) > 1 else ""
        first = literal(args[0])
        detected: list[str] = []
        usage = None
        key_size = None
        if extension in {".js", ".ts"} and canonical == "require" and first in {"crypto", "node:crypto", "crypto-js"}:
            emit(token, tokens[closing], library=first)
            if target:
                aliases[target] = first
            continue
        if names[0] in objects and len(names) == 2:
            detected, key_size = objects[names[0]]
            usage = OPERATIONS.get(method)
            if extension in {".js", ".ts"} and method == "digest":
                # Finalization adds no algorithm evidence beyond the hash factory.
                usage = None
            if method == "init" and extension == ".java":
                modes = {t.value for arg in args for t in arg if t.kind == "word"}
                usage = "encryption" if "ENCRYPT_MODE" in modes else "decryption" if "DECRYPT_MODE" in modes else None
            if method in {"generateKey", "generateKeyPair"}:
                usage = "key_generation"
            if method == "doPhase":
                usage = "key_exchange"
            if not usage:
                detected = []
        elif extension == ".py":
            if parts[0] == "hashlib":
                detected = mechanisms(first if method == "new" else method)
                detected = [a for a in detected if a in HASHES]
                usage = "hashing"
            elif method in {"generate", "generate_private_key", "new", "ECDSA", "ECDH"}:
                detected = mechanisms(owner if method not in {"ECDSA", "ECDH"} else method)
                if method in {"generate", "generate_private_key"}:
                    usage = "key_generation"
                elif method == "ECDSA":
                    usage = None
                elif method == "ECDH":
                    usage = "key_exchange"
                elif detected and detected[0] in HASHES:
                    usage = "hashing"
            elif "cryptography" in parts or owner in {"algorithms", "hashes"}:
                detected = mechanisms(method)
                if detected and detected[0] in HASHES:
                    usage = "hashing"
            if "RSA" in detected and usage == "key_generation":
                if method == "generate" and len(args[0]) == 1 and args[0][0].kind == "number":
                    key_size = integer(args[0][0])
                if method == "generate_private_key" and len(args) > 1 and len(args[1]) == 1:
                    key_size = integer(args[1][0])
                for arg in args:
                    if len(arg) == 3 and arg[0].value in {"key_size", "bits"} and arg[1].value == "=" and arg[2].kind == "number":
                        key_size = integer(arg[2])
        elif extension == ".java" and method == "getInstance" and owner in {"Cipher", "MessageDigest", "Signature", "KeyPairGenerator", "KeyGenerator", "KeyAgreement"}:
            detected = mechanisms(first)
            usage = {"MessageDigest": "hashing", "KeyPairGenerator": "key_generation",
                     "KeyGenerator": "key_generation", "KeyAgreement": "key_exchange"}.get(owner)
        elif extension in {".js", ".ts"}:
            if parts[0] in {"crypto", "node:crypto"}:
                usage = {"createHash": "hashing", "createHmac": "hashing", "createCipheriv": "encryption",
                    "createDecipheriv": "decryption", "createCipher": "encryption", "createDecipher": "decryption",
                    "createSign": "signing", "createVerify": "verification", "sign": "signing", "verify": "verification",
                    "generateKeyPair": "key_generation", "generateKeyPairSync": "key_generation",
                    "generateKeySync": "key_generation"}.get(method)
                if usage:
                    detected = mechanisms(first)
                if method == "createECDH":
                    detected, usage = ["ECDH"], "key_exchange"
                if method in {"publicEncrypt", "privateEncrypt", "privateDecrypt", "publicDecrypt"}:
                    detected = ["RSA"]
                    usage = "encryption" if method.endswith("Encrypt") else "decryption"
                if detected == ["AES"] and first and (size := re.search(r"(?i)^aes[-_]?(128|192|256)", first)):
                    key_size = int(size[1])
                if usage == "key_generation":
                    for arg in args[1:]:
                        depth = 0
                        if any(arg[j].value == arg[j + 1].value == arg[j + 2].value == "."
                               for j in range(len(arg) - 2)):
                            continue  # Object spreads can override a literal size.
                        for j in range(len(arg) - 2):
                            if arg[j].value in {"{", "[", "("}:
                                depth += 1
                            elif arg[j].value in {"}", "]", ")"}:
                                depth -= 1
                            size_field = "modulusLength" if detected == ["RSA"] else "length" if detected == ["AES"] else None
                            if depth == 1 and arg[j].value == size_field and arg[j + 1].value == ":":
                                key_size = integer(arg[j + 2]) if j + 3 < len(arg) and arg[j + 3].value in {",", "}"} else None
            elif parts[0] in {"crypto-js", "CryptoJS"}:
                detected = mechanisms(owner if method in {"encrypt", "decrypt"} else method)
                usage = OPERATIONS.get(method, "hashing" if detected and detected[0] in HASHES else None)
        for algorithm in detected:
            emit(token, tokens[closing], algorithm=algorithm, usage=usage, key_size=key_size)
        if target:
            objects.pop(target, None)
            if detected:
                objects[target] = (detected, key_size)
    # Imports of several members can yield the same library evidence.
    unique = {(f.line, f.type, f.algorithm, f.library, f.evidence, f.usage): f for f in findings}
    return sorted(unique.values(), key=lambda f: (f.line, f.type, f.algorithm or f.library or "", f.evidence))


def scan_repository(root: Path, source_files: list[str]) -> list[Finding]:
    findings = []
    for relative in sorted(source_files):
        path = root / relative
        if path.suffix.lower() not in SUPPORTED_EXTENSIONS:
            continue
        with path.open("rb") as stream:
            data = stream.read(MAX_SOURCE_BYTES + 1)
        if len(data) > MAX_SOURCE_BYTES:
            logger.warning("Source byte limit reached; file skipped")
            continue
        findings.extend(scan_source(data.decode("utf-8-sig", errors="replace"), relative))
    return findings
