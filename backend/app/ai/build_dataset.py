"""Rebuild the committed dataset deterministically from curated local examples."""

import argparse
import json
from textwrap import indent

from app.ai.dataset import DATASET_PATH, LANGUAGES, validate_dataset
from app.ai.dataset_seeds import SEEDS
from app.ai.labels import LABELS


def build_records() -> list[dict]:
    records = []
    for label in LABELS:
        for language in LANGUAGES:
            for index, (context, code) in enumerate(SEEDS[label][language]):
                # Related variants/translations must stay together in a future split.
                base = {"context": context, "language": language, "label": label,
                        "indirect": label == "crypto_wrapper", "family_id": f"{label}-{index + 1:02d}"}
                records.append({**base, "code": code, "variant": "fragment"})
                name = ("process_item", "handle_input", "run_step", "apply_action", "inspect_item")[index]
                if language == "python":
                    wrapped = f"def {name}():\n" + indent(code, "    ")
                else:
                    header = {"java": f"void {name}() throws Exception",
                              "javascript": f"async function {name}()",
                              "typescript": f"async function {name}(): Promise<void>"}[language]
                    wrapped = header + " {\n" + indent(code, "    ") + "\n}"
                records.append({**base, "code": wrapped, "variant": "helper",
                    "context": context + " This helper uses bindings supplied by the surrounding module or class."})
    validate_dataset(records)
    return records


def render_dataset(records: list[dict]) -> str:
    return "".join(json.dumps(record, ensure_ascii=False, sort_keys=True) + "\n" for record in records)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Verify the committed dataset without changing it")
    args = parser.parse_args()
    records = build_records()
    rendered = render_dataset(records)
    if args.check:
        if not DATASET_PATH.exists() or DATASET_PATH.read_bytes() != rendered.encode("utf-8"):
            raise SystemExit("Dataset differs from the local builder; regenerate it.")
    else:
        DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
        with DATASET_PATH.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(rendered)
    print(json.dumps(validate_dataset(records), indent=2))


if __name__ == "__main__":
    main()
