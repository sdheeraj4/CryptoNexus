"""Load and validate the local JSONL dataset without executing any snippets."""

import json
from collections import Counter
from pathlib import Path

from app.ai.labels import LABELS

DATASET_PATH = Path(__file__).resolve().parents[2] / "data" / "crypto_training.jsonl"
LANGUAGES = ("python", "java", "javascript", "typescript")
REQUIRED_FIELDS = {"code", "context", "language", "label", "indirect"}


def load_dataset(path: Path = DATASET_PATH) -> list[dict]:
    records = []
    with path.open(encoding="utf-8") as stream:
        for number, line in enumerate(stream, 1):
            try:
                records.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise ValueError(f"Invalid JSON on dataset line {number}") from exc
    return records


def validate_dataset(records: list[dict], min_records: int = 250,
                     min_per_class: int = 24) -> dict:
    """Raise ValueError for invalid data; return compact distribution statistics."""
    labels, languages = Counter(), Counter()
    indirect = set()
    seen, examples = set(), set()
    for index, record in enumerate(records, 1):
        if not isinstance(record, dict) or not REQUIRED_FIELDS <= record.keys():
            raise ValueError(f"Record {index}: missing required fields or not an object")
        if any(not isinstance(record[field], str) or not record[field].strip()
               for field in ("code", "context", "language", "label")):
            raise ValueError(f"Record {index}: expected nonempty string fields")
        if type(record["indirect"]) is not bool:
            raise ValueError(f"Record {index}: indirect must be boolean")
        if record["label"] not in LABELS:
            raise ValueError(f"Record {index}: invalid label")
        if record["language"] not in LANGUAGES:
            raise ValueError(f"Record {index}: unsupported language")
        if record["label"] == "crypto_wrapper" and not record["indirect"]:
            raise ValueError(f"Record {index}: opaque wrapper must be indirect")
        identity = json.dumps(record, sort_keys=True, ensure_ascii=False)
        example = (record["language"], record["code"], record["context"])
        if identity in seen or example in examples:
            raise ValueError(f"Record {index}: duplicate example")
        seen.add(identity)
        examples.add(example)
        labels[record["label"]] += 1
        languages[record["language"]] += 1
        indirect.add(record["indirect"])
    if len(records) < min_records:
        raise ValueError(f"Dataset needs at least {min_records} records")
    if any(labels[label] < min_per_class for label in LABELS):
        raise ValueError(f"Each required label needs at least {min_per_class} examples")
    if set(languages) != set(LANGUAGES):
        raise ValueError("All four required languages must be represented")
    if indirect != {False, True}:
        raise ValueError("Both direct and indirect examples must exist")
    return {"total": len(records), "labels": dict(sorted(labels.items())),
            "languages": dict(sorted(languages.items()))}


if __name__ == "__main__":
    print(json.dumps(validate_dataset(load_dataset()), indent=2))
