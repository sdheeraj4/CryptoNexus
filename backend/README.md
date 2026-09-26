# CryptoNexus

Block 3 backend: crypto-agility sandbox and report data, alongside the deterministic
scanners, local classifier, and explainable migration analysis.
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
Individual uploads, full call-graph analysis, and crypto-agility sandbox features
are outside this stage.

## Local AI dataset (Stage 2.1)

The dataset tools under `app/ai` define nine behavior labels and validate the
296-record local dataset in `data/crypto_training.jsonl`. See
[data/README.md](data/README.md) for class counts, labeling rules, reproduction
commands, and limitations. The dataset builder itself does not train a model.

## Local classifier (Block 1)

Install the updated requirements, then train locally from `backend`:

```powershell
python -m pip install -r requirements.txt
python -m app.ai.train
python -m pytest -q
```

Training uses character TF-IDF (3–5 grams) plus LogisticRegression with seed 42.
Only code, context, and language enter the model; labels/family IDs/variant metadata
are excluded from input text. A stratified family split keeps related snippets and
translations together: 216 train records and 80 test records. TF-IDF is fitted on
the training partition only for evaluation. Holdout accuracy is 0.7500, macro
precision 0.7524, macro recall 0.7639, and macro F1 0.7465.

After evaluation, a fresh pipeline is fitted on all 296 records and saved to
`models/crypto_classifier.joblib`. `models/crypto_classifier.metrics.json` records
the holdout metrics/split and the final training count. The metrics describe the
holdout experiment, not independent evaluation of the all-record deployment fit.
Restart the server after retraining to refresh its cached model.

`POST /api/ai/classify` accepts:

```json
{"code":"secure_provider.sign(payload)","context":"","language":"python"}
```

It returns `label`, numeric `confidence`, and `status`: `likely` at confidence
>= 0.60, otherwise `uncertain`. `non_crypto` follows the same rule. Code is required
(up to 16,000 characters); context and language are optional (8,000 and 32 characters).
`predict_crypto_behavior(code, context="", language="unknown")` provides the same
interface for local Python callers. Missing/unreadable models return HTTP 503.

During ZIP uploads, AI considers at most 20 candidate calls across the first 100
source files; files above 64 KiB are skipped by this AI pass. Candidate selection
ignores comments/strings and already-confirmed evidence lines. It focuses on
sign/verify/protect/encrypt/decrypt and opaque key-service calls, not every line.
Non-crypto predictions are omitted from upload findings. Other candidates add
`type: "ai_behavior"`, `evidence_type: "indirect"`, `ai_label`, and `ai_confidence`,
with `likely`/`uncertain` status and no invented algorithm/key size. Deterministic
findings remain unchanged and confirmed. If the model is unavailable, deterministic
uploads still work and the AI pass logs a skip.

Inference only loads the fixed application-owned model path, never artifacts from
uploads. It makes no network calls. The joblib artifact must remain trusted since
deserialization can execute Python code. scikit-learn and joblib are pinned in
requirements; NumPy/SciPy are their transitive dependencies.

Limitations: this small synthetic corpus and one holdout split do not establish
real-world accuracy. Probabilities are uncalibrated model scores, not guarantees.
Bare calls without context can be uncertain (the wrapper example above scores
about 0.5804). Candidate selection and file/count limits intentionally miss some
indirect code. The Block 2 analysis below consumes these findings without additional
AI calls. No sandbox, UI, or reporting features are included.

## Analysis and migration intelligence (Block 2)

`POST /api/analyze` accepts a repository ZIP in multipart field `file`. It reuses
the upload pipeline, including deterministic and bounded local AI scanning, then
builds relationships, a migration checklist, and report guidance. The upload API
is unchanged. No uploaded code is executed.

```powershell
curl.exe -s -F "file=@C:\path\to\repository.zip" http://127.0.0.1:8000/api/analyze
```

The response has `findings`, `dependencies`, `migration_checklist`,
`migration_graph`, and `summary`. Each analyzed finding preserves its original
fields/status and gains `id`, `migration_concern`, `priority`, and `reason`.
Summary counts describe findings, not unique files or proven active vulnerabilities.

Dependency graph nodes use typed IDs (`file:auth.py`, `algorithm:RSA`) to avoid name
collisions. Edges include `finding_ids` and `inferred`. Implemented relationships:

- File to observed algorithm, protocol, imported library, declared package, or provider.
- Certificate file to parsed certificate, and certificate to its public-key algorithm.
- Config file to an explicit certificate/key-path reference. A unique repository-root
  or config-relative lexical match adds a file link marked **inferred** because the
  runtime working directory/base is unknown. Absolute, dynamic, ambiguous, and
  basename-only guesses are not linked. A referenced invalid certificate is only
  a file/path node, never a parsed certificate node.
- File to AI behavior via `may_use`, always inferred. No algorithm is invented.

Co-occurring imports/algorithms share their file node; the analyzer does not assume
that a particular library implements a particular algorithm. Exact duplicate input
findings are removed. Source status is evidence of syntax, not runtime reachability;
protocol references may be disabled or excluded by the surrounding configuration.

Priority rules (triage defaults, not security certification):

- High: observed RSA/EC/ECC/ECDSA/ECDH/DSA/DH/Ed/X public-key mechanisms need
  post-quantum transition attention. Legacy MD5/SHA1/DES/3DES, SSL, TLS 1.0/1.1,
  and legacy certificate signature digests also require high-priority review.
- Medium: AES/ChaCha20 parameter review, TLS/TLS 1.2 compatibility review,
  providers/packages, key/certificate references, and cipher suites.
- Informational: SHA-2 references and TLS 1.3 alone, without additional concerns.
- AI likely/uncertain evidence keeps its status and receives medium-priority
  investigation instructions before any replacement is selected. Requests claiming
  confirmed AI/indirect evidence are rejected with HTTP 422.

Rules are informed by [NIST migration guidance](https://pages.nist.gov/nccoe-migration-post-quantum-cryptography/)
and [RFC 8996's TLS 1.0/1.1 deprecation](https://www.rfc-editor.org/info/rfc8996/).
No version, library, or algorithm name alone establishes quantum safety.

Checklist items group matching mechanism/concern/status, use numeric priority
1=high, 2=medium, 3=informational, and include affected observed files, evidence IDs,
reason, and proposed steps. Public-key, legacy, inventory, and uncertain-wrapper
findings receive different steps. They are recommendations, not executed changes.

`migration_graph` extends dependency JSON with mechanism → component → proposed
migration action → validation gate edges. Proposed edges are marked inferred and
`proposed: true`; validation nodes have `status: "not_run"`. Gates are planning
items, not tests that the analyzer has run. This remains an inventory-level graph,
without call-graph, transitive dependency, reachability, or operational impact analysis.

## Sandbox and report data (Block 3 backend)

`POST /api/sandbox/run` accepts `{"provider":"rsa","message":"CryptoNexus agility test"}`.
Providers `rsa` (RSA-2048/PSS/SHA-256) and `ed25519` implement the same
`sign`, `verify`, and `provider_info` interface using `cryptography`. Each request
generates a temporary key and performs a real sign/verify round trip. The response
includes provider, algorithm, operation, verified, key_size, UTF-8 byte message_length,
and a disclaimer. No keys or signatures are returned. Messages are limited to
16,000 characters. Invalid providers receive HTTP 422.

Sandbox demonstrates crypto-agility, not quantum safety. Neither RSA nor Ed25519
is a post-quantum algorithm. The sandbox has no persistence or production key management.

Analysis includes `report.limitations`, `report.compatibility_risks`,
`report.testing_steps`, and `report.disclaimer`. Compatibility/testing guidance
is selected from actual findings; it does not mean those checks have been executed.
The disclaimer is: **A CryptoNexus scan does not prove that a system is quantum-safe.**

FastAPI serves the existing `MicroCode/frontend` UI at `/`, after registering all
API and documentation routes. Scan, Inventory, Evidence, Dependency Map,
Certificates, Migration, Agility, and Reports use backend responses. Upload a ZIP
to analyze it, run either sandbox provider with an editable message, or download
the complete analysis as JSON. Results stay in browser memory until refresh.
The dependency preview shows up to 40 relationships; the table includes all edges.

From the workspace root in PowerShell, run:

```powershell
.\.venv\Scripts\python.exe -m uvicorn app.main:app --app-dir backend --reload
```

Open http://127.0.0.1:8000/ for the UI or http://127.0.0.1:8000/docs for Swagger.
