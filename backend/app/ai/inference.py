"""Cached inference from a trusted application-owned local pipeline."""

from functools import lru_cache
from pathlib import Path
from pickle import UnpicklingError
from typing import Literal

import joblib
from pydantic import BaseModel, Field

from app.ai.labels import CryptoLabel

MODEL_PATH = Path(__file__).resolve().parents[2] / "models" / "crypto_classifier.joblib"


class ModelUnavailable(RuntimeError):
    pass


class Prediction(BaseModel):
    label: CryptoLabel
    confidence: float = Field(ge=0, le=1)
    status: Literal["likely", "uncertain"]


def input_text(code: str, context: str = "", language: str = "unknown") -> str:
    return f"language: {language.lower()}\ncode:\n{code}\ncontext:\n{context}"


@lru_cache(maxsize=1)
def load_model():
    # Never accept an upload/user-supplied model path: joblib artifacts are executable.
    try:
        return joblib.load(MODEL_PATH)
    except (OSError, ValueError, EOFError, ImportError, UnpicklingError, KeyError, IndexError) as exc:
        raise ModelUnavailable("Local classifier is unavailable; run python -m app.ai.train") from exc


def prediction_from_probabilities(classes, probabilities) -> dict:
    index = max(range(len(probabilities)), key=lambda i: probabilities[i])
    confidence = float(probabilities[index])
    return Prediction(label=str(classes[index]), confidence=confidence,
                      status="likely" if confidence >= 0.60 else "uncertain").model_dump(mode="json")


def predict_crypto_behavior(code: str, context: str = "", language: str = "unknown") -> dict:
    if not isinstance(code, str) or not code.strip():
        raise ValueError("code must be a nonempty string")
    if len(code) > 16_000 or len(context) > 8_000 or len(language) > 32:
        raise ValueError("Classifier input is too large")
    pipeline = load_model()
    probabilities = pipeline.predict_proba([input_text(code, context, language)])[0]
    return prediction_from_probabilities(pipeline.classes_, probabilities)
