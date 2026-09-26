# CryptoNexus

Phase 1 — Stage 1.4: secure ZIP upload with source, configuration, dependency,
and X.509 certificate scanning.
Requires Python 3.10 or newer.

## Windows PowerShell

Run from the `backend` directory:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m uvicorn app.main:app --reload
```

If activation is blocked, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`
and retry activation. Stop the server with Ctrl+C, then run tests:

```powershell
python -m pytest -q
```

## API

- `GET /health`: returns `{"status":"ok","service":"CryptoNexus"}`.
- `POST /api/upload`: multipart field `file`, containing a `.zip` repository.
- Interactive API documentation: http://127.0.0.1:8000/docs

```powershell
curl.exe -F "file=@C:\path\to\repository.zip" http://127.0.0.1:8000/api/upload
```

The response contains `project_name` (sanitized ZIP filename without extension),
`total_files`, and sorted relative paths in `source_files`, `config_files`,
`certificate_files`, and `dependency_files`. Categories may overlap: `package.json`
is both config and dependency metadata. Total counts all retained regular files,
including uncategorized files. Repository root folder names are preserved.

Uploads are limited to 20 MiB, whole requests to 21 MiB, extracted content to
100 MiB, and archives to 10,000 entries. Unsafe paths, links, special files,
encrypted archives, and duplicate paths are rejected. `.git`, `node_modules`,
`__pycache__`, `.venv`, `venv`, `dist`, and `build` directories are ignored.
Temporary uploads and extracted files are removed after success or failure;
uploaded code is never executed. Abrupt process termination may prevent cleanup.
Errors use `{"error":"..."}` with HTTP 400, 413, 422, or 500.

## Direct source scanning

The upload response also contains `crypto_findings` and `finding_count` (including
source, configuration, dependency, and certificate findings). Scanning finishes before temporary
cleanup. The existing inventory remains unchanged; source scanning supports `.py`,
`.js`, `.ts`, and `.java`. Certificate parsing is described below.

Each finding includes `type`, `algorithm` or `library`, `usage`, `file`, 1-based
`line`, `key_size` in bits, `evidence`, `evidence_type: "direct"`, and
`status: "confirmed"`. Unknown usage and key size are null. Evidence starts at
the recognized import/call and is limited to 300 characters. Confirmed means
recognized source syntax, not proof that the call executes at runtime.

Supported patterns:

- Python: hashlib constructors/`new`, PyCryptodome `RSA.generate`, cipher/hash
  `.new`, ECC generation, cryptography RSA/EC key generation, algorithm/hash
  constructors, ECDSA and ECDH. Common import aliases are followed.
- Java: `Cipher`, `MessageDigest`, `Signature`, `KeyPairGenerator`, `KeyGenerator`,
  and `KeyAgreement` calls to `getInstance` with literal algorithm names.
- JavaScript/TypeScript: Node crypto hash/HMAC, cipher/decipher, sign/verify,
  RSA encrypt/decrypt, key generation, ECDH, and CryptoJS hash/encrypt/decrypt
  calls. ES default/namespace/named aliases and simple CommonJS assignments work.
- Algorithms: RSA, EC/ECC (reported as ECC), ECDSA, ECDH, AES, DES, 3DES
  (including DES3/TripleDES/DESede), ChaCha20, MD5, SHA1, SHA224, SHA256,
  SHA384, SHA512. Literal cipher transformations and signature combinations
  are recognized.
- Imports: hashlib, cryptography, Crypto/Cryptodome, ssl, java.security,
  javax.crypto, crypto, node:crypto, and crypto-js.

Simple assignments allow subsequent encrypt/decrypt/sign/verify/hash/exchange
operations to retain algorithm evidence; Java cipher/signature initialization
is recognized too. RSA literal sizes, Node modulusLength/AES length, and explicit
AES-128/192/256 descriptors are supported. Key lengths are never guessed from
variable names or buffers. Comments, docstrings, and ordinary strings are skipped;
only literal arguments to recognized crypto calls provide algorithm names.

This is a lightweight token scanner, not a compiler: no scope/type resolution,
cross-file tracking, dynamic algorithm evaluation, comprehensive alias analysis,
CommonJS destructuring, WebCrypto, or template-expression analysis. Familiar API
names may be recognized without an import; shadowed names can cause false positives.
Python multiline imports and complex call chains may be missed. Sources are
decoded as UTF-8 with replacement. Files over 2 MiB or 200,000 tokens are skipped
with a server log warning; calls longer than 512 tokens are skipped. These limits
mean an empty findings list is not a guarantee of no cryptography.

## Configuration and dependencies

Configuration scanning supports JSON objects/arrays and common YAML, TOML, INI,
and CONF assignments/directives. It recognizes explicit SSL/SSLv2/SSLv3 and TLS
1.0–1.3 values, the listed algorithms (except SHA224 in config), IANA/OpenSSL-style
cipher suites, certificate and private/public key path settings, and crypto provider
settings. Descriptions, comments, and prose are ignored. JSON must be valid; the
other formats use a small line parser, not complete format validation.

Additional finding types are `protocol`, `cipher_suite`, `certificate_path`,
`key_path`, `provider`, and `dependency`. `protocol` holds the normalized version;
`reference` holds a suite or file path; `library` holds a provider or dependency.
Evidence uses the original line (or Maven dependency block), capped at 300
characters, with a 1-based start line. Config/dependency usage and key size remain
null. A confirmed reference does not mean the setting is enabled or the declared
package is installed or used. Paths are never followed.

Dependency declarations recognized:

- `requirements.txt` and `pyproject.toml`: cryptography, pycryptodome,
  pycryptodomex, pycrypto, pynacl, pyopenssl, bcrypt, argon2-cffi. Supports PEP 621
  dependencies/extras, Poetry dependency sections/groups, build requirements,
  and dependency groups.
- `package.json`: crypto-js, node-forge, bcrypt/bcryptjs, jose, tweetnacl,
  libsodium-wrappers in dependencies, devDependencies, optionalDependencies,
  or peerDependencies.
- `pom.xml`: explicit Bouncy Castle bcprov/bcpkix/bctls/bcpg, Spring Security,
  Conscrypt, Apache Shiro core, and Nimbus JOSE JWT coordinates.
- `go.mod`: require declarations for golang.org/x/crypto,
  github.com/cloudflare/circl, github.com/ProtonMail/go-crypto, and
  github.com/youmark/pkcs8.

Exact duplicate findings are removed; files belonging to both config and dependency
categories are read once. Metadata files over 2 MiB are skipped with a log warning.
Limits: no YAML anchors/flow-map resolution, full TOML parsing, interpolation,
Maven property resolution/namespaced element prefixes, package installation,
lockfile/transitive analysis, dependency graph, or inference from arbitrary package
names. Only allowlisted packages are recognized. Advanced or dynamic declarations
may be missed. Metadata scanning adds no runtime dependencies.

## Certificate parsing

The `cryptography` library parses X.509 certificates in `.crt`, `.cer`, and `.pem`
files. Encoding is detected from contents: PEM (including bundles) or a single
DER certificate. A corrupt PEM block is skipped without losing other valid blocks.
Private keys are never loaded, and raw PEM/key bytes are never used as evidence.
Mixed PEM files yield findings only for their certificate blocks.

Each certificate adds a `type: "certificate"` finding with:

- `algorithm`: RSA, ECC, DSA, Ed25519, or Ed448 where recognized.
- `key_size`: the library-reported size for RSA, ECC, and DSA; null for Ed keys.
- `usage: "certificate_public_key"`, file, and PEM start line (null for DER).
- `subject`, `issuer`, decimal-string `serial_number`, and `signature_algorithm`
  (a cryptography signature OID constant name, or dotted OID when unknown).
- `valid_from` and `valid_until` as ISO 8601 timestamps with UTC offsets.
- `evidence`: a public certificate SHA256 fingerprint;
  `evidence_type: "direct"` and `status: "confirmed"`.

`certificate_scan_issues` lists fixed-message `status: "skipped"` results for invalid,
unsupported, non-certificate, unreadable, or oversized files/blocks. These issues
are separate from `crypto_findings` and do not increase `finding_count`. Certificate
inventory still includes all candidate extensions, including invalid/key-only PEM
files. Valid findings and inventory from other scanners are preserved.

Limits: 2 MiB and 100 PEM certificates per file. Only X.509 PEM/DER is supported;
PKCS#7, PKCS#12, and trusted-certificate wrappers are not parsed. No certificate
chain, trust, hostname, revocation, or validity-period verification is performed.
Unsupported algorithms may produce a controlled skip. No key material is returned.

No source code is executed; scanning uses no network or external API.
Individual uploads, AI/ML, dependency graphs,
migration planning, and crypto-agility features are outside this stage.
