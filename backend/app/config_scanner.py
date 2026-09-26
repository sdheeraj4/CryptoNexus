"""Conservative setting/reference detection; no certificate or key contents are read."""

import json
import re
from dataclasses import dataclass

from app.scanner import Finding


@dataclass
class Setting:
    path: tuple[str, ...]
    value: str
    line: int
    evidence: str


def strip_comment(line: str) -> str:
    # Preserve comment characters inside quoted paths/values.
    return re.sub(r'''("(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*')|[#;].*$''',
                  lambda m: m[1] or "", line).strip()


def json_settings(source: str) -> list[Setting]:
    try:
        json.loads(source)
    except (ValueError, RecursionError):
        return []
    token_re = re.compile(r'"(?:\\.|[^"\\])*"|[{}\[\]:,]|true|false|null|-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?')
    tokens = list(token_re.finditer(source))
    lines = source.splitlines()
    line_numbers = []
    previous = 0
    line = 1
    for token in tokens:
        line += source.count("\n", previous, token.start())
        line_numbers.append(line)
        previous = token.start()
    position = 0
    result = []

    def visit(path):
        nonlocal position
        token = tokens[position].group()
        position += 1
        if token == "{":
            while tokens[position].group() != "}":
                key = json.loads(tokens[position].group())
                position += 2  # Key and colon.
                visit((*path, key))
                if tokens[position].group() == ",":
                    position += 1
            position += 1
        elif token == "[":
            while tokens[position].group() != "]":
                visit(path)
                if tokens[position].group() == ",":
                    position += 1
            position += 1
        elif path:
            number = line_numbers[position - 1]
            value = json.loads(token)
            result.append(Setting(path, str(value), number, lines[number - 1].strip()[:300]))

    try:
        visit(())
    except RecursionError:
        return []
    return result


def text_settings(source: str) -> list[Setting]:
    """Common YAML/TOML/INI assignments and nginx/Apache-style directives."""
    result = []
    parents: list[tuple[int, str]] = []
    section: tuple[str, ...] = ()
    array_path = None
    block_indent = None
    multiline_quote = None
    for number, raw in enumerate(source.splitlines(), 1):
        indent = len(raw) - len(raw.lstrip())
        line = strip_comment(raw)
        if multiline_quote is not None:
            if multiline_quote in raw:
                multiline_quote = None
            continue
        if not line:
            continue
        if block_indent is not None:
            if indent > block_indent:
                continue  # YAML prose/literal blocks are not crypto settings.
            block_indent = None
        if array_path is not None:
            result.append(Setting(array_path, line, number, raw.strip()[:300]))
            if "]" in line:
                array_path = None
            continue
        if match := re.fullmatch(r"\[([^\[\]]+)\]", line):
            section = tuple(p.strip(' \"\'') for p in match[1].split("."))
            parents.clear()
            continue
        while parents and parents[-1][0] >= indent:
            parents.pop()
        if line.startswith("- ") and parents:
            result.append(Setting((*section, *(p[1] for p in parents)), line[2:].strip(),
                                  number, raw.strip()[:300]))
            continue
        match = re.match(r'''["']?([\w.-]+)["']?\s*(?:[:=]\s*|\s+)(.*)$''', line)
        if not match:
            continue
        key, value = match.groups()
        path = (*section, *(p[1] for p in parents), key)
        if value.startswith(('"""', "'''")):
            if value.count(value[:3]) == 1:
                multiline_quote = value[:3]
            continue
        if value in {"|", ">", "|-", ">-", "|+", ">+"}:
            block_indent = indent
            continue
        if not value:
            parents.append((indent, key))
            continue
        result.append(Setting(path, value.strip(), number, raw.strip()[:300]))
        if value.startswith("[") and "]" not in value:
            array_path = path
    return result


PROTOCOL = re.compile(r"(?i)(?<![\w])(?:TLS(?:[v _-]?1(?:[._][0-3])?)?|SSL(?:[v _-]?[23])?)(?![\w.])")
ALGORITHM = re.compile(r"(?i)(?<![A-Z0-9])(?:CHACHA20|TRIPLEDES|3DES|DES3|DES|ECDSA|ECDHE?|ECC?|RSA|AES(?:[-_]?(?:128|192|256))?|MD5|SHA[-_]?(?:1|256|384|512))(?![A-Z0-9])")
SUITE = re.compile(r"(?i)\b(?:TLS|SSL)_[A-Z0-9_]+\b|\b(?:ECDHE|ECDH|DHE|RSA|AES(?:128|192|256)?|DES|CHACHA20)(?:-[A-Z0-9]+)+\b")


def scan_config(source: str, file: str) -> list[Finding]:
    settings = json_settings(source) if file.lower().endswith(".json") else text_settings(source)
    findings = []
    for setting in settings:
        key = re.sub(r"[^a-z0-9]", "", setting.path[-1].lower())
        context = re.sub(r"[^a-z0-9]", "", ".".join(setting.path).lower())
        if key in {"description", "message", "notes", "comment", "title", "name", "example", "documentation"}:
            continue
        protocol_setting = "protocol" in key or key in {"tls", "ssl"} or (
            any(s in context for s in ("tls", "ssl")) and (key.endswith("version") or key == "enabled"))
        cipher_setting = any(s in key for s in ("cipher", "algorithm", "signature", "digest", "hash", "keyexchange", "keytype"))
        cert_setting = "cert" in key or key in {"cafile", "capath"}
        key_setting = any(s in key for s in ("privatekey", "publickey", "keyfile", "keypath", "certificatekey")) or key == "key"
        provider_setting = "provider" in key and (any(s in context for s in ("crypto", "security", "ssl", "tls", "jce")) or
            setting.value.strip(' \"\'') in {"BC", "SunJCE", "SunJSSE", "SunRsaSign", "BouncyCastle", "Conscrypt"})
        if not any((protocol_setting, cipher_setting, cert_setting, key_setting, provider_setting)):
            continue

        def emit(kind, **fields):
            findings.append(Finding(type=kind, file=file, line=setting.line,
                                    evidence=setting.evidence, **fields))

        # A literal mechanism/list is evidence; prose merely mentioning one is not.
        remainder = ALGORITHM.sub("", PROTOCOL.sub("", SUITE.sub("", setting.value)))
        literal_mechanisms = not re.search(r"[\w]", remainder)
        if protocol_setting and literal_mechanisms:
            for match in PROTOCOL.finditer(setting.value):
                base = "TLS" if match[0].upper().startswith("TLS") else "SSL"
                version = re.sub(r"^[v _-]+", "", match[0][3:], flags=re.I).replace("_", ".")
                if base == "TLS" and version == "1":
                    version = "1.0"
                normalized = base + (" " + version if version else "")
                emit("protocol", protocol=normalized)
        if (cipher_setting or protocol_setting) and literal_mechanisms:
            for match in ALGORITHM.finditer(setting.value):
                name = match[0].upper().replace("-", "").replace("_", "")
                name = {"EC": "ECC", "ECDHE": "ECDH", "DES3": "3DES", "TRIPLEDES": "3DES", "CHACHA20": "ChaCha20"}.get(name, name)
                if name.startswith("AES"):
                    name = "AES"
                emit("algorithm", algorithm=name)
            for match in SUITE.finditer(setting.value):
                if ALGORITHM.search(match[0]):
                    emit("cipher_suite", reference=match[0])
        # Paths are references only; do not open, resolve, or parse them.
        for match in re.finditer(r'''["']([^"'\r\n]+)["']|([^\s,;\[\]{}"']+)''', setting.value):
            value = match[1] or match[2]
            if key_setting and re.search(r"(?i)\.(?:pem|key|der|pub|p8|pk8)$", value):
                emit("key_path", reference=value)
            elif cert_setting and re.search(r"(?i)\.(?:pem|crt|cer|p12|pfx|jks)$", value):
                emit("certificate_path", reference=value)
        if provider_setting:
            value = setting.value.strip(' \"\'')
            if re.fullmatch(r"[\w.$/-]+", value) and value.lower() not in {"true", "false", "none", "null"}:
                emit("provider", library=value)
    return unique_findings(findings)


def unique_findings(findings: list[Finding]) -> list[Finding]:
    return list({(f.file, f.line, f.type, f.algorithm, f.protocol, f.library,
                  f.reference, f.usage, f.key_size, f.evidence): f for f in findings}.values())
