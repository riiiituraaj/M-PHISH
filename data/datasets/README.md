# Optional real-world phishing benchmark

M-PHISH X ships with a synthetic development benchmark so the project remains self-contained and safe to run.
That benchmark is useful for regression tests and architecture demos, but it must not be presented as evidence of
real-world phishing detection accuracy.

To evaluate with an independently sourced dataset, provide a CSV via `MPHISH_DATASET_PATH`. The CSV must contain:

- `label`: `0` for benign and `1` for phishing
- any subset of the feature columns listed in `backend/app/services/ml/dataset.py`

Missing feature columns are filled with neutral defaults. Keep the dataset outside version control when its license or
contents do not permit redistribution. Record the dataset name, acquisition date, provenance, and license in your report.

The application will expose the provenance in the ML prediction and research response instead of calling synthetic
results production accuracy.
