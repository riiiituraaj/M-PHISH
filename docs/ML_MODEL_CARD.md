# M-PHISH model card

Status: **no validated deployed model**. Runtime returns unavailable/null probability unless an operator configures `ML_ARTIFACT_PATH` plus matching `ML_ARTIFACT_SHA256`, and the JSON artifact passes its schema and release-gate checks. No pickle/joblib upload or deserialization endpoint exists.

`observations-v2` uses 31 URL/domain/page/behavior/context features plus explicit missingness indicators. Unknown domain age is NaN before train-fitted imputation; it is never 365 by assumption. Inference abstains for unsupported missingness patterns and values outside training ranges. Origin-only product scanning reduces URL coverage and must also be reflected in any supplied training records.

The deployment format is logistic regression coefficients with held-out sigmoid calibration; raw probability, calibrated probability, intercept and per-prediction raw-log-odds contributions are separate. Contributions are additive arithmetic explanations, not causality. Random forest and XGBoost remain offline comparison baselines. A deployed model's validation-selected threshold controls model warnings; policy rules can warn independently.

Training lives in `backend/app/services/ml/offline.py`; HTTP research reads stored `evaluation-v2` JSON only. No startup, scan or GET trains a model. Group splits combine registrable domains and supplied campaign IDs; train, calibration, validation and test sets are disjoint. Ablations share the same records and splits, with modality coverage disclosed. Exact observation duplicates are removed. Temporal generalization and near-template deduplication beyond supplied campaign grouping remain limitations.

Initial gates are fixed before final-test access: 95% precision, 90% recall and at most 1% legitimate false-positive rate. The implementation uses the corresponding 95% interval lower/lower/upper bounds, so small samples cannot silently pass. Threshold selection uses validation only. Reports include confusion matrix, Brier, PR/ROC-AUC, reliability bins, support, Wilson intervals, error record IDs, model/split checksums and dependency/hardware metadata. Final-test outcomes are not used to tune a threshold.

No real precision, recall, accuracy, false-positive rate or latency claim is made. Synthetic generators are labelled controlled fixtures; single-feature threshold audits catch the original dot-count separability. Remaining evaluation work includes licensed independently labelled records, temporal and subgroup evaluation, legitimate SSO/payment false warnings, end-to-end policy evaluation, cold/steady-state inference and uncertainty-supported operating points. The JSON metadata's `release_gate` is not a substitute for operator review of provenance and reproduced results.

Command and input provenance requirements are in `DATASETS.md`. A real-world benchmark cannot be completed with the sample HTML fixtures in this repository.
