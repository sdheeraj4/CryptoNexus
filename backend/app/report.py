"""Report guidance derived from observed findings; no safety certification."""

DISCLAIMER = "A CryptoNexus scan does not prove that a system is quantum-safe."


def build_report(findings) -> dict:
    limitations = [
        "Static analysis cannot observe every runtime cryptographic operation.",
        "Indirect and wrapper findings may require human validation; AI confidence is not proof.",
        "External services may not be visible in the repository.",
        "Provider and deployment compatibility must be tested.",
        "File-size and candidate limits can skip evidence; an empty scan is not a security guarantee.",
        "Scanning does not prove quantum safety.",
    ]
    risks, tests = [], []
    if any(f.type in {"certificate", "certificate_path", "key_path"} for f in findings):
        risks.append("Certificate, key-format, trust-store, and consuming-client compatibility may change.")
        tests.append("Validate certificate chains, trust stores, key loading, and TLS client/server compatibility.")
    if any(f.protocol or f.type == "cipher_suite" for f in findings):
        risks.append("Protocol and cipher-policy changes may prevent existing peers from connecting.")
        tests.append("Test protocol/cipher negotiation and expected rejection of unsupported peers.")
    if any(f.migration_concern == "post_quantum_transition_attention" or f.usage in {"signing", "verification"} for f in findings):
        risks.append("Public-key and signature formats may require application and provider changes.")
        tests.append("Run sign/verify interoperability tests, including tampered-message and invalid-signature rejection where relevant.")
    if any(f.algorithm in {"AES", "DES", "3DES", "ChaCha20"} or f.usage in {"encryption", "decryption"} for f in findings):
        risks.append("Ciphertext formats, parameters, and stored-data compatibility may change.")
        tests.append("Run encryption/decryption round trips and invalid-ciphertext tests against existing data formats.")
    if any(f.library for f in findings):
        risks.append("Library/provider API, version, and deployment support may differ between environments.")
        tests.append("Test provider interoperability on supported deployment environments.")
    if any(f.status != "confirmed" for f in findings):
        risks.append("Unconfirmed wrappers may hide different operations or dependent service behavior.")
        tests.append("Inspect wrapper implementations before choosing operation-specific migration tests.")
    if findings:
        risks.append("Dependent application behavior may change even when individual crypto operations succeed.")
        tests.extend(["Run dependent service regression tests.", "Validate rollback before deployment."])
    return {"limitations": limitations, "compatibility_risks": risks,
            "testing_steps": tests, "disclaimer": DISCLAIMER}
