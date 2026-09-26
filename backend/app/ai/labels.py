"""Single-label taxonomy for the primary behavior of a snippet and its context."""

from enum import Enum


class CryptoLabel(str, Enum):
    ENCRYPTION = "encryption"
    DECRYPTION = "decryption"
    HASHING = "hashing"
    DIGITAL_SIGNATURE = "digital_signature"
    KEY_GENERATION = "key_generation"
    KEY_EXCHANGE = "key_exchange"
    TLS_CERTIFICATE = "tls_certificate"
    CRYPTO_WRAPPER = "crypto_wrapper"
    NON_CRYPTO = "non_crypto"


LABELS = tuple(label.value for label in CryptoLabel)
LABEL_DESCRIPTIONS = {
    "encryption": "An established crypto API transforms plaintext into ciphertext.",
    "decryption": "An established crypto API recovers plaintext from ciphertext.",
    "hashing": "Cryptographic digests, HMACs, or password hashing/checking; not table hashes.",
    "digital_signature": "Cryptographic signature creation or verification; not form approval.",
    "key_generation": "Explicit generation or derivation of cryptographic key material.",
    "key_exchange": "Agreement on shared key material, such as DH or ECDH.",
    "tls_certificate": "TLS context/connection setup or X.509 certificate handling.",
    "crypto_wrapper": "An opaque crypto-oriented service call with an unestablished mechanism.",
    "non_crypto": "No established cryptographic behavior, including misleading names or prose.",
}
