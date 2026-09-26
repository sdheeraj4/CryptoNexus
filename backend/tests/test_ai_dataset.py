import copy
from collections import Counter, defaultdict

import pytest

from app.ai.build_dataset import build_records, render_dataset
from app.ai.dataset import DATASET_PATH, LANGUAGES, load_dataset, validate_dataset
from app.ai.labels import LABELS, LABEL_DESCRIPTIONS


@pytest.fixture(scope="module")
def records():
    return load_dataset()


def test_dataset_size_balance_and_languages(records):
    stats = validate_dataset(records)
    assert stats["total"] == 296
    assert set(stats["labels"]) == set(LABELS) == set(LABEL_DESCRIPTIONS)
    assert stats["labels"] == {label: 40 if label == "non_crypto" else 32 for label in LABELS}
    assert stats["languages"] == {language: 74 for language in LANGUAGES}
    counts = Counter((r["label"], r["language"]) for r in records)
    assert min(counts.values()) >= 8
    assert {r["indirect"] for r in records} == {False, True}


def test_committed_dataset_is_reproducible(records):
    expected = build_records()
    assert records == expected
    assert DATASET_PATH.read_bytes() == render_dataset(expected).encode("utf-8")
    assert build_records() == expected


def test_examples_are_unique_and_have_grouping_metadata(records):
    examples = {(r["language"], r["code"], r["context"]) for r in records}
    assert len(examples) == len(records)
    families = defaultdict(list)
    for record in records:
        families[record["family_id"]].append(record)
    assert len(families) == 37
    for family in families.values():
        assert len({r["label"] for r in family}) == 1
        assert {r["variant"] for r in family} == {"fragment", "helper"}
        assert {r["language"] for r in family} == set(LANGUAGES)


@pytest.mark.parametrize("needle,label", [
    ("hashlib.sha256", "hashing"), ("RSA.generate", "key_generation"),
    ("AES.new", "encryption"), ("private_key.sign", "digital_signature"),
    ("Cipher.getInstance", "encryption"), ('crypto.createHash("sha256")', "hashing"),
    ("secure_provider.sign(payload)", "crypto_wrapper"),
    ("crypto_manager.protect(data)", "crypto_wrapper"),
    ("key_service.create()", "crypto_wrapper"), ("vault.encrypt_record", "crypto_wrapper"),
    ("user.sign_form()", "non_crypto"), ("database_key = record.id", "non_crypto"),
    ("hash_table.insert", "non_crypto"), ("secure_filename", "non_crypto"),
    ('message = "RSA documentation"', "non_crypto"), ('sign = "+"', "non_crypto"),
    ('key = "customer_id"', "non_crypto"),
])
def test_required_behavior_and_hard_negative_examples(records, needle, label):
    assert any(needle in r["code"] and r["label"] == label for r in records)


def test_visible_crypto_inside_helpers_is_not_opaque(records):
    for record in records:
        assert record["indirect"] == (record["label"] == "crypto_wrapper")
    assert any(r["variant"] == "helper" and r["label"] == "digital_signature" and not r["indirect"]
               for r in records)


def test_python_examples_have_valid_syntax_without_execution(records):
    import ast
    for record in records:
        if record["language"] == "python":
            ast.parse(record["code"])


@pytest.mark.parametrize("field", ["code", "context", "language", "label", "indirect"])
def test_missing_fields_rejected(records, field):
    changed = copy.deepcopy(records)
    del changed[0][field]
    with pytest.raises(ValueError, match="missing required fields"):
        validate_dataset(changed)


@pytest.mark.parametrize("field,value,message", [
    ("label", "unknown", "invalid label"), ("language", "ruby", "unsupported language"),
    ("indirect", "false", "must be boolean"), ("indirect", 0, "must be boolean"),
    ("code", "   ", "nonempty string"), ("context", None, "nonempty string"),
])
def test_invalid_field_values_rejected(records, field, value, message):
    changed = copy.deepcopy(records)
    changed[0][field] = value
    with pytest.raises(ValueError, match=message):
        validate_dataset(changed)


def test_duplicate_rejected_even_with_different_metadata(records):
    duplicate = {**records[0], "family_id": "different"}
    with pytest.raises(ValueError, match="duplicate"):
        validate_dataset([*records, duplicate])


def test_missing_class_and_small_class_rejected(records):
    for keep in (0, 23):
        filtered = [r for r in records if r["label"] != "hashing"]
        filtered += [r for r in records if r["label"] == "hashing"][:keep]
        with pytest.raises(ValueError, match="Each required label"):
            validate_dataset(filtered)


def test_small_dataset_rejected(records):
    with pytest.raises(ValueError, match="at least 250"):
        validate_dataset(records[:249])


def test_missing_language_rejected(records):
    filtered = [r for r in records if r["language"] != "java"]
    with pytest.raises(ValueError, match="All four required languages"):
        validate_dataset(filtered, min_records=200)


def test_missing_direct_examples_rejected(records):
    changed = [{**r, "indirect": True} for r in records]
    with pytest.raises(ValueError, match="Both direct and indirect"):
        validate_dataset(changed)


def test_json_errors_have_dataset_line_number(tmp_path):
    path = tmp_path / "invalid.jsonl"
    path.write_text('{}\nnot-json\n', encoding="utf-8")
    with pytest.raises(ValueError, match="line 2"):
        load_dataset(path)
