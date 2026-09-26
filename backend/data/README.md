# CryptoNexus local behavior dataset

Stage 2.1 dataset: **296 synthetic supervised examples**. The dataset builder does
not train or infer; Block 1 training/inference is documented in [../README.md](../README.md).
The committed `crypto_training.jsonl` is produced entirely from curated local seeds
and deterministic templates. No external AI service, remote corpus, or ML framework
is involved. No snippets are executed and no real keys/customer data are included.

## Classes and annotation rules

| Label | Count | Meaning |
|---|---:|---|
| encryption | 32 | Explicit plaintext-to-ciphertext operation |
| decryption | 32 | Explicit recovery of plaintext |
| hashing | 32 | Cryptographic digest, HMAC, or password hash/check |
| digital_signature | 32 | Cryptographic signing or signature verification |
| key_generation | 32 | Explicit creation of cryptographic key material |
| key_exchange | 32 | Shared-secret agreement, including DH/ECDH/X25519/X448 |
| tls_certificate | 32 | TLS context/connection setup or X.509 handling |
| crypto_wrapper | 32 | Opaque crypto-oriented service without an established mechanism |
| non_crypto | 40 | Ordinary behavior despite crypto-looking identifiers or text |

Python, Java, JavaScript, and TypeScript each have 74 examples. Every class appears
in every language. The taxonomy is defined in `app/ai/labels.py`.

Use both `code` and `context` to determine the primary operation. Context provides
imports or object types that may be omitted from a snippet. For example,
`private_key.sign(payload)` with an established cryptographic key type is a
digital signature, while an undocumented `secure_provider.sign(payload)` is an
opaque wrapper. A form-acceptance method with the same vocabulary is non-crypto.
Do not infer behavior from names, comments, strings, or an algorithm constructor
alone. Cipher examples include the actual encrypt/decrypt operation or mode.

When setup and an operation coexist, label the primary operation performed, not
an incidental digest/algorithm argument. For example an RSA key-generation call
whose options contain `sign` is key_generation, and a SHA-256 signature is
digital_signature. Both signature creation and verification share one class;
password comparison using bcrypt belongs to hashing. This is a single-label
dataset, not an algorithm/risk/strength classifier.

`indirect: true` identifies the opaque crypto_wrapper examples. A helper function
that visibly calls a known crypto API retains its specific behavior label and
`indirect: false`. Non-crypto examples also have `indirect: false`.

## Reproduction and validation

From `backend`, using the project's activated environment:

```powershell
python -m app.ai.build_dataset
python -m app.ai.build_dataset --check
python -m app.ai.dataset
python -m pytest -q
```

The builder writes UTF-8 JSONL with stable order/newlines and no randomness. There
are 148 curated snippet/context pairs, each paired with a function-scope variant.
The original examples vary API, operation, library, data handling, and language;
variants add structural/formatting diversity without changing the class.

Every record has `code`, `context`, `language`, `label`, and boolean `indirect`.
Additional `family_id` and `variant` fields are **metadata, never model inputs**.
Related translations and helper variants share a family ID. Any future split
must keep an entire family together to avoid train/test leakage. No train/test
split is created by the dataset builder. The Block 1 trainer splits whole families.
Closely related families may still warrant broader grouping
or a separate independently collected evaluation corpus.

Validation checks fields/types, labels, languages, at least 250 examples, at least
24 per class, direct/indirect coverage, and duplicate records/examples. Tests also
check reproducibility, per-language balance, required examples, and Python syntax.

## Limits

This is a compact synthetic starter corpus, not evidence of classification accuracy.
The 296 records are not 296 independent behaviors: helper variants reuse their
148 base snippets. Context descriptions and recurring templates may become model
shortcuts; future evaluation needs independently authored real-world examples.
Opaque calls require contextual assumptions; their names alone are not proof of
cryptography. Snippets often omit imports, input definitions, error handling, and
security configuration. They are illustrative fragments, not runnable applications
or recommended cryptographic implementations. Java/JS/TS compilation is not checked.
