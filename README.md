# 🔐 CryptoNexus

## Post-Quantum Cryptography Migration & Crypto-Agility Scanner

> **Discover the cryptography. Understand the dependencies. Plan the migration. Build for change.**

CryptoNexus is a repository-analysis platform designed to help developers and security teams understand how cryptography is being used inside an application and prepare that application for future post-quantum migration.

It scans source code, configuration files, dependencies, protocol settings, and digital certificates, combines deterministic evidence with a locally trained machine-learning model, builds a dependency-aware view of the cryptographic surface, and generates a prioritized migration roadmap.

CryptoNexus does **not** claim that scanning a repository proves that the system is quantum-safe. Instead, it provides evidence, relationships, migration guidance, compatibility considerations, and testing recommendations.

---

# 🚨 The Problem

Modern applications use cryptography in many different places.

A project may contain:

```text
Application Source Code
        │
        ├── RSA / ECC
        ├── AES
        ├── SHA-256
        │
        ├── Crypto Libraries
        │
        ├── Configuration Files
        │       └── TLS / Cipher Suites
        │
        ├── Certificates
        │       └── RSA / ECC Public Keys
        │
        └── Dependencies
                └── cryptography / crypto-js / node-forge / etc.
