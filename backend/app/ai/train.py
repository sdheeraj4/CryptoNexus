"""Train/evaluate locally with family-disjoint, reproducible holdout evaluation."""

import json

import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, precision_recall_fscore_support
from sklearn.model_selection import train_test_split
from sklearn.pipeline import make_pipeline

from app.ai.dataset import load_dataset, validate_dataset
from app.ai.inference import MODEL_PATH, input_text
from app.ai.labels import LABELS

SEED = 42


def split_records(records):
    families = {}
    for record in records:
        family = record["family_id"]
        if family in families and families[family] != record["label"]:
            raise ValueError("A family must have one label")
        families[family] = record["label"]
    groups = sorted(families)
    train_groups, test_groups = train_test_split(groups, test_size=0.25, random_state=SEED,
                                                stratify=[families[g] for g in groups])
    train_groups, test_groups = set(train_groups), set(test_groups)
    return ([r for r in records if r["family_id"] in train_groups],
            [r for r in records if r["family_id"] in test_groups])


def new_pipeline():
    return make_pipeline(
        TfidfVectorizer(analyzer="char_wb", ngram_range=(3, 5), sublinear_tf=True, max_features=30_000),
        LogisticRegression(C=10, max_iter=1000, random_state=SEED),
    )


def training_inputs(records):
    return ([input_text(r["code"], r["context"], r["language"]) for r in records],
            [r["label"] for r in records])


def train():
    records = load_dataset()
    validate_dataset(records)
    train_rows, test_rows = split_records(records)
    pipeline = new_pipeline()
    pipeline.fit(*training_inputs(train_rows))
    test_text, test_labels = training_inputs(test_rows)
    predicted = pipeline.predict(test_text)
    precision, recall, f1, _ = precision_recall_fscore_support(
        test_labels, predicted, labels=list(LABELS), average="macro", zero_division=0)
    metrics = {"accuracy": float(accuracy_score(test_labels, predicted)),
               "macro_precision": float(precision), "macro_recall": float(recall), "macro_f1": float(f1),
               "random_seed": SEED, "train_records": len(train_rows), "test_records": len(test_rows),
               "split": "stratified family holdout; related variants/translations stay together",
               "test_families": sorted({r["family_id"] for r in test_rows}),
               "saved_model_training_records": len(records)}
    # Evaluation above is held out; the deployment artifact then learns the complete starter corpus.
    pipeline = new_pipeline()
    pipeline.fit(*training_inputs(records))
    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(pipeline, MODEL_PATH, compress=3)
    MODEL_PATH.with_suffix(".metrics.json").write_text(json.dumps(metrics, indent=2) + "\n", encoding="utf-8")
    return metrics


if __name__ == "__main__":
    print(json.dumps(train(), indent=2))
