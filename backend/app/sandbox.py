"""Interchangeable signing providers backed exclusively by cryptography."""

from abc import ABC, abstractmethod
from typing import Literal

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa
from pydantic import BaseModel, Field

NOTE = "Crypto-agility sandbox demonstration; this does not prove quantum safety. RSA and Ed25519 are not post-quantum algorithms."


class CryptoProvider(ABC):
    @abstractmethod
    def sign(self, message: bytes) -> bytes: ...

    @abstractmethod
    def verify(self, message: bytes, signature: bytes) -> bool: ...

    @abstractmethod
    def provider_info(self) -> dict: ...


class RSAProvider(CryptoProvider):
    def __init__(self):
        self._key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self._padding = padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.DIGEST_LENGTH)

    def sign(self, message):
        return self._key.sign(message, self._padding, hashes.SHA256())

    def verify(self, message, signature):
        try:
            self._key.public_key().verify(signature, message, self._padding, hashes.SHA256())
            return True
        except InvalidSignature:
            return False

    def provider_info(self):
        return {"provider": "rsa", "algorithm": "RSA", "key_size": 2048}


class Ed25519Provider(CryptoProvider):
    def __init__(self):
        self._key = ed25519.Ed25519PrivateKey.generate()

    def sign(self, message):
        return self._key.sign(message)

    def verify(self, message, signature):
        try:
            self._key.public_key().verify(signature, message)
            return True
        except InvalidSignature:
            return False

    def provider_info(self):
        return {"provider": "ed25519", "algorithm": "Ed25519", "key_size": None}


class SandboxRequest(BaseModel):
    provider: Literal["rsa", "ed25519"]
    message: str = Field(default="CryptoNexus agility test", max_length=16_000)


class SandboxResult(BaseModel):
    provider: Literal["rsa", "ed25519"]
    algorithm: str
    operation: Literal["sign_verify"] = "sign_verify"
    verified: bool
    key_size: int | None
    message_length: int
    note: str = NOTE


def run_sandbox(request: SandboxRequest) -> SandboxResult:
    provider: CryptoProvider = {"rsa": RSAProvider, "ed25519": Ed25519Provider}[request.provider]()
    message = request.message.encode("utf-8")
    signature = provider.sign(message)
    return SandboxResult(**provider.provider_info(), verified=provider.verify(message, signature),
                         message_length=len(message))
