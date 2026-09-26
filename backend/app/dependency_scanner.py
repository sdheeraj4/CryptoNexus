"""Recognize explicitly declared security packages; no resolution or network access."""

import re
import xml.etree.ElementTree as ET
from pathlib import Path

from app.config_scanner import json_settings, text_settings, unique_findings
from app.scanner import Finding

PYTHON = {"cryptography", "pycryptodome", "pycryptodomex", "pycrypto", "pynacl", "pyopenssl", "bcrypt", "argon2-cffi"}
JAVASCRIPT = {"crypto-js", "node-forge", "bcrypt", "bcryptjs", "jose", "libsodium-wrappers", "tweetnacl"}
GO = {"golang.org/x/crypto", "github.com/cloudflare/circl", "github.com/ProtonMail/go-crypto",
      "github.com/youmark/pkcs8"}


def python_package(value: str) -> str | None:
    match = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[\w, .-]+\])?(?=\s*(?:[<>=!~;@]|$))", value.strip())
    name = re.sub(r"[-_.]+", "-", match[1]).lower() if match else None
    return name if name in PYTHON else None


def scan_dependencies(source: str, file: str) -> list[Finding]:
    name = Path(file).name.lower()
    lines = source.splitlines()
    findings = []

    def emit(library, line, evidence=None):
        findings.append(Finding(type="dependency", library=library, file=file, line=line,
                                evidence=(evidence or lines[line - 1].strip())[:300]))

    if name == "requirements.txt":
        for number, raw in enumerate(lines, 1):
            # Semicolons introduce environment markers, not comments here.
            value = raw.split("#", 1)[0].strip()
            if library := python_package(value):
                emit(library, number)
    elif name == "package.json":
        for setting in json_settings(source):
            if len(setting.path) == 2 and setting.path[0] in {
                "dependencies", "devDependencies", "optionalDependencies", "peerDependencies"
            } and setting.path[1] in JAVASCRIPT:
                emit(setting.path[1], setting.line, setting.evidence)
    elif name == "pyproject.toml":
        for setting in text_settings(source):
            path = setting.path
            poetry = (path[:3] == ("tool", "poetry", "dependencies") or
                      path[:3] == ("tool", "poetry", "dev-dependencies") or
                      (len(path) == 6 and path[:3] == ("tool", "poetry", "group") and path[4] == "dependencies"))
            if poetry:
                if library := python_package(path[-1]):
                    emit(library, setting.line, setting.evidence)
            elif (path == ("project", "dependencies") or
                  path[:2] == ("project", "optional-dependencies") or
                  path == ("build-system", "requires") or path[:1] == ("dependency-groups",)):
                for match in re.finditer(r'''["']([^"']+)["']''', setting.value):
                    if library := python_package(match[1]):
                        emit(library, setting.line, setting.evidence)
    elif name == "pom.xml":
        if re.search(r"<!DOCTYPE|<!ENTITY", source, re.I):
            return []
        try:
            ET.fromstring(source)
        except (ET.ParseError, ValueError):
            return []
        # Remove comments without shifting source offsets/line numbers.
        clean = re.sub(r"<!--[\s\S]*?-->|<!\[CDATA\[[\s\S]*?\]\]>",
                       lambda m: re.sub(r"[^\n]", " ", m[0]), source)
        for match in re.finditer(r"<dependency\b[^>]*>([\s\S]*?)</dependency\s*>", clean):
            group = re.search(r"<groupId>\s*([^<]+?)\s*</groupId>", match[1])
            artifact = re.search(r"<artifactId>\s*([^<]+?)\s*</artifactId>", match[1])
            if not group or not artifact:
                continue
            group, package = group[1], artifact[1]
            recognized = ((group == "org.bouncycastle" and package.startswith(("bcprov", "bcpkix", "bctls", "bcpg"))) or
                          (group == "org.springframework.security" and package.startswith("spring-security-")) or
                          (group == "org.conscrypt" and package.startswith("conscrypt-")) or
                          (group, package) in {("org.apache.shiro", "shiro-core"), ("com.nimbusds", "nimbus-jose-jwt")})
            if recognized:
                number = clean.count("\n", 0, match.start()) + 1
                emit(f"{group}:{package}", number, source[match.start():match.end()].strip())
    elif name == "go.mod":
        in_require = False
        for number, raw in enumerate(lines, 1):
            value = raw.split("//", 1)[0].strip()
            if value == "require (":
                in_require = True
                continue
            if value == ")":
                in_require = False
                continue
            if value.startswith("require "):
                value = value[len("require "):].strip()
            elif not in_require:
                continue
            match = re.fullmatch(r'"?([^\s"]+)"?\s+v[^\s]+', value)
            if match and match[1] in GO:
                emit(match[1], number)
    return unique_findings(findings)
