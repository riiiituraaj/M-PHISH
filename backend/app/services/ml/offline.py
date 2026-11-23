"""Explicit offline training/evaluation. Never imported by the API request path.

Input: provenance manifest + labelled JSONL observation records. All model families
share the same domain/campaign-disjoint splits; the final test is evaluated once.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import platform
import time
from datetime import UTC, datetime
from pathlib import Path

import numpy as np
from sklearn.calibration import calibration_curve
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.preprocessing import StandardScaler

from ..observations import normalized_host, registrable_domain
from .dataset import FEATURE_GROUPS, FEATURE_NAMES, single_feature_shortcuts
from .model import FEATURE_VERSION, extract_features_vector

RELEASE_TARGETS = {
    "precision_lower_95": 0.95,
    "recall_lower_95": 0.90,
    "fpr_upper_95": 0.01,
}


def canonical_hash(value) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
    ).hexdigest()


def wilson(successes: int, total: int) -> list[float | None]:
    if not total:
        return [None, None]
    z = 1.959963984540054
    p = successes / total
    denominator = 1 + z * z / total
    center = (p + z * z / (2 * total)) / denominator
    half = z * np.sqrt(p * (1 - p) / total + z * z / (4 * total * total)) / denominator
    return [max(0.0, float(center - half)), min(1.0, float(center + half))]


def metrics(labels, probabilities, threshold=0.5) -> dict:
    predicted = np.asarray(probabilities) >= threshold
    tn, fp, fn, tp = map(int, confusion_matrix(labels, predicted, labels=[0, 1]).ravel())
    fraction, average = calibration_curve(labels, probabilities, n_bins=10, strategy="uniform")
    return {
        "accuracy": float(accuracy_score(labels, predicted)),
        "precision": float(precision_score(labels, predicted, zero_division=0)),
        "recall": float(recall_score(labels, predicted, zero_division=0)),
        "f1": float(f1_score(labels, predicted, zero_division=0)),
        "roc_auc": float(roc_auc_score(labels, probabilities)),
        "pr_auc": float(average_precision_score(labels, probabilities)),
        "brier_score": float(brier_score_loss(labels, probabilities)),
        "false_positive_rate": fp / (fp + tn),
        "false_negative_rate": fn / (fn + tp),
        "confusion_matrix": {"tn": tn, "fp": fp, "fn": fn, "tp": tp},
        "precision_interval_95": wilson(tp, tp + fp),
        "recall_interval_95": wilson(tp, tp + fn),
        "fpr_interval_95": wilson(fp, fp + tn),
        "support": {"benign": tn + fp, "phishing": tp + fn},
        "reliability_bins": {
            "mean_prediction": average.tolist(),
            "observed_fraction": fraction.tolist(),
        },
        "threshold": float(threshold),
    }


def release_gate(result: dict) -> bool:
    precision = result["precision_interval_95"][0]
    recall = result["recall_interval_95"][0]
    fpr = result["fpr_interval_95"][1]
    return (
        precision is not None
        and recall is not None
        and fpr is not None
        and precision >= 0.95
        and recall >= 0.90
        and fpr <= 0.01
    )


def load_dataset(dataset: Path, manifest: Path):
    raw = dataset.read_bytes()
    provenance = json.loads(manifest.read_text(encoding="utf-8"))
    required = {
        "dataset_version",
        "source",
        "license",
        "usage_permission",
        "collected_at",
        "label_methodology",
        "sha256",
        "kind",
    }
    if required - provenance.keys() or any(not provenance[k] for k in required):
        raise ValueError("Dataset manifest lacks required provenance/permission fields")
    if hashlib.sha256(raw).hexdigest() != provenance["sha256"]:
        raise ValueError("Dataset checksum mismatch")
    records, seen = [], set()
    for line in raw.decode("utf-8").splitlines():
        if not line.strip():
            continue
        record = json.loads(line)
        if (
            record.get("label") not in {0, 1}
            or not record.get("target_url")
            or not record.get("observed_at")
        ):
            raise ValueError(
                "Every record requires explicit binary label, target_url and observation timestamp"
            )
        datetime.fromisoformat(record["observed_at"])
        # Exact observation duplicates are removed before any split, including URL variants.
        fingerprint = canonical_hash(
            {
                key: record.get(key)
                for key in [
                    "url_features",
                    "domain_analysis",
                    "page_analysis",
                    "context",
                ]
            }
        )
        if fingerprint in seen:
            continue
        seen.add(fingerprint)
        record["record_id"] = canonical_hash({"fingerprint": fingerprint, "label": record["label"]})
        records.append(record)
    if len(records) < 80:
        raise ValueError(
            "At least 80 unique labelled observations are required for four disjoint splits"
        )
    # Union campaigns and registrable domains. Either relationship prevents split leakage.
    parent = {}

    def find(item):
        parent.setdefault(item, item)
        if parent[item] != item:
            parent[item] = find(parent[item])
        return parent[item]

    for record in records:
        domain = "domain:" + registrable_domain(normalized_host(record["target_url"]))
        campaign = "campaign:" + str(record.get("campaign_id") or domain)
        parent[find(campaign)] = find(domain)
        record["group"] = domain
    groups = np.array([find(record["group"]) for record in records])
    vectors = np.vstack(
        [
            extract_features_vector(
                record.get("url_features", {}),
                record.get("domain_analysis"),
                record.get("page_analysis"),
                record.get("context"),
            )
            for record in records
        ]
    )
    labels = np.array([record["label"] for record in records])
    return vectors, labels, groups, records, provenance


def split_indices(labels, groups, seed=42):
    indices = np.arange(len(labels))
    remaining, test = next(
        GroupShuffleSplit(n_splits=1, test_size=0.15, random_state=seed).split(
            indices, labels, groups
        )
    )
    remaining_local, validation_local = next(
        GroupShuffleSplit(n_splits=1, test_size=0.15 / 0.85, random_state=seed + 1).split(
            remaining, labels[remaining], groups[remaining]
        )
    )
    validation, remaining = remaining[validation_local], remaining[remaining_local]
    train_local, calibration_local = next(
        GroupShuffleSplit(n_splits=1, test_size=0.15 / 0.70, random_state=seed + 2).split(
            remaining, labels[remaining], groups[remaining]
        )
    )
    splits = {
        "train": remaining[train_local],
        "calibration": remaining[calibration_local],
        "validation": validation,
        "test": test,
    }
    for name, subset in splits.items():
        if len(np.unique(labels[subset])) != 2:
            raise ValueError(f"{name} lacks class support; obtain more independent labelled groups")
    return splits


def preprocess_fit(X):
    median = np.array(
        [
            float(np.median(column[np.isfinite(column)])) if np.any(np.isfinite(column)) else 0.0
            for column in X.T
        ]
    )
    expanded = np.concatenate([np.where(np.isfinite(X), X, median), ~np.isfinite(X)], axis=1)
    scaler = StandardScaler().fit(expanded)
    return median, scaler


def preprocess(X, median, scaler):
    return scaler.transform(
        np.concatenate([np.where(np.isfinite(X), X, median), ~np.isfinite(X)], axis=1)
    )


def select_threshold(labels, probabilities):
    candidates = []
    for threshold in np.unique(probabilities):
        predicted = probabilities >= threshold
        precision = precision_score(labels, predicted, zero_division=0)
        recall = recall_score(labels, predicted, zero_division=0)
        negative = labels == 0
        fpr = float(np.mean(predicted[negative]))
        if precision >= 0.95 and recall >= 0.90 and fpr <= 0.01:
            candidates.append((recall, precision, float(threshold)))
    return max(candidates)[2] if candidates else 0.5


def train_evaluate(dataset: Path, manifest: Path, output: Path, seed=42) -> dict:
    if output.exists() and any(output.iterdir()):
        raise ValueError(
            "Output must be empty; preserve previous runs and untouched test decisions"
        )
    output.mkdir(parents=True, exist_ok=True)
    X, y, groups, records, provenance = load_dataset(dataset, manifest)
    splits = split_indices(y, groups, seed)
    # Targets are written before accessing final test metrics.
    (output / "release_targets.json").write_text(json.dumps(RELEASE_TARGETS, indent=2))
    split_manifest = {
        name: [records[i]["record_id"] for i in subset] for name, subset in splits.items()
    }
    (output / "splits.json").write_text(json.dumps(split_manifest, indent=2))
    shortcuts = single_feature_shortcuts(X[splits["train"]], y[splits["train"]])
    experiments = []
    deployment = None
    # URL->full ablations share exactly the same eligible rows and splits. Missing data remains visible.
    conditions = [
        ("EXP-" + chr(65 + i), list(FEATURE_GROUPS)[: i + 1], "logistic") for i in range(5)
    ]
    conditions += [
        ("BASE-RF", list(FEATURE_GROUPS), "random_forest"),
        ("BASE-XGB", list(FEATURE_GROUPS), "xgboost"),
    ]
    for experiment_id, group_names, family in conditions:
        indices = [i for group in group_names for i in FEATURE_GROUPS[group]]
        subset = X[:, indices]
        median, scaler = preprocess_fit(subset[splits["train"]])
        transformed = {
            name: preprocess(subset[split], median, scaler) for name, split in splits.items()
        }
        if family == "logistic":
            model = LogisticRegression(max_iter=2000, random_state=seed)
        elif family == "random_forest":
            model = RandomForestClassifier(
                n_estimators=100,
                max_depth=8,
                min_samples_leaf=5,
                random_state=seed,
                n_jobs=1,
            )
        else:
            from xgboost import XGBClassifier

            model = XGBClassifier(
                n_estimators=100,
                max_depth=4,
                learning_rate=0.05,
                random_state=seed,
                n_jobs=1,
                eval_metric="logloss",
            )
        model.fit(transformed["train"], y[splits["train"]])

        def margins(values, model=model):
            if hasattr(model, "decision_function"):
                return model.decision_function(values)
            probabilities = np.clip(model.predict_proba(values)[:, 1], 1e-8, 1 - 1e-8)
            return np.log(probabilities / (1 - probabilities))

        calibrator = LogisticRegression(C=1e6, max_iter=1000).fit(
            margins(transformed["calibration"]).reshape(-1, 1), y[splits["calibration"]]
        )
        validation_probs = calibrator.predict_proba(
            margins(transformed["validation"]).reshape(-1, 1)
        )[:, 1]
        threshold = select_threshold(y[splits["validation"]], validation_probs)
        start = time.perf_counter()
        test_probs = calibrator.predict_proba(margins(transformed["test"]).reshape(-1, 1))[:, 1]
        elapsed = time.perf_counter() - start
        result = metrics(y[splits["test"]], test_probs, threshold)
        result.update(
            {
                "experiment_id": experiment_id,
                "name": family + ": " + " + ".join(group_names),
                "feature_groups": group_names,
                "num_features": len(indices),
                "inference_latency_ms": elapsed / len(test_probs) * 1000,
                "latency_scope": "batch inference divided by sample count; not single-request p95",
                "hypothesis_confirmed": "Measured comparison only; no causal claim.",
                "dataset_kind": provenance["kind"],
                "dataset_version": provenance["dataset_version"],
                "model_family": family,
                "split_support": {name: len(split) for name, split in splits.items()},
                "modality_observed_fraction": {
                    group: float(np.mean(np.isfinite(X[splits["test"]][:, FEATURE_GROUPS[group]])))
                    for group in group_names
                },
                "release_gate": "passed"
                if release_gate(result) and not shortcuts and provenance["kind"] == "real_labelled"
                else "failed",
            }
        )
        errors = [
            records[i]["record_id"]
            for i, prob in zip(splits["test"], test_probs, strict=True)
            if (prob >= threshold) != bool(y[i])
        ]
        result["error_record_ids"] = errors[:100]
        experiments.append(result)
        if experiment_id == "EXP-E":
            ranges = [
                [float(np.nanmin(column)), float(np.nanmax(column))]
                if np.any(np.isfinite(column))
                else [None, None]
                for column in X[splits["train"]].T
            ]
            patterns = sorted(
                {
                    "".join("1" if not np.isfinite(v) else "0" for v in row)
                    for row in X[splits["train"]]
                }
            )
            deployment = {
                "format": "m-phish-linear-v1",
                "feature_version": FEATURE_VERSION,
                "feature_names": FEATURE_NAMES,
                "model_version": provenance["dataset_version"] + "-lr-v2",
                "release_gate": result["release_gate"],
                "median": median.tolist(),
                "mean": scaler.mean_.tolist(),
                "scale": scaler.scale_.tolist(),
                "coefficients": model.coef_[0].tolist(),
                "intercept": float(model.intercept_[0]),
                "calibration_slope": float(calibrator.coef_[0, 0]),
                "calibration_intercept": float(calibrator.intercept_[0]),
                "threshold": float(threshold),
                "supported_missingness_patterns": patterns,
                "feature_ranges": ranges,
                "dataset_manifest": provenance,
                "split_manifest_sha256": canonical_hash(split_manifest),
                "release_targets": RELEASE_TARGETS,
            }
    # A transparent one-rule baseline audits the legacy synthetic shortcut on the same test set.
    dot_baseline = metrics(y[splits["test"]], (X[splits["test"], 3] > 3).astype(float))
    artifact_bytes = json.dumps(deployment, sort_keys=True, indent=2, allow_nan=False).encode()
    (output / "model.json").write_bytes(artifact_bytes)
    report = {
        "schema_version": "evaluation-v2",
        "created_at": datetime.now(UTC).isoformat(),
        "provenance": provenance,
        "experiments": experiments,
        "shortcut_findings_train_only": shortcuts,
        "dot_count_gt_3_baseline": dot_baseline,
        "release_targets": RELEASE_TARGETS,
        "model_sha256": hashlib.sha256(artifact_bytes).hexdigest(),
        "hardware": {
            "platform": platform.platform(),
            "processor": platform.processor(),
            "python": platform.python_version(),
        },
        "dependencies": {
            name: importlib.metadata.version(name) for name in ["numpy", "scikit-learn", "xgboost"]
        },
        "limitations": [
            "Random grouped holdout; temporal generalization has not been established.",
            "Runtime abstains for missingness patterns or feature ranges absent from training.",
            "Source licensing/labels require human verification; a manifest alone is not legal approval.",
        ],
    }
    (output / "results.json").write_text(
        json.dumps(report, indent=2, allow_nan=False), encoding="utf-8"
    )
    (output / "checksums.txt").write_text(
        "\n".join(
            hashlib.sha256(p.read_bytes()).hexdigest() + "  " + p.name
            for p in sorted(output.iterdir())
            if p.is_file()
        )
    )
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset", type=Path, required=True)
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    report = train_evaluate(args.dataset, args.manifest, args.output, args.seed)
    print(
        json.dumps(
            {
                "output": str(args.output),
                "artifact_sha256": report["model_sha256"],
                "deployment_gate": report["experiments"][4]["release_gate"],
            }
        )
    )


if __name__ == "__main__":
    main()
