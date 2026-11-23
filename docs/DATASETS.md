# Dataset and evaluation procedure

No external dataset was downloaded or labelled during this upgrade. A user's dataset/license/ownership must be established before ingestion. Absence from a phishing feed is not a benign label.

Supply a local UTF-8 JSONL file with `target_url`, explicit binary `label`, ISO `observed_at`, `url_features`, `domain_analysis`, `page_analysis`, `context`, and optional `campaign_id`. Records must be actual consented observations, use the same origin-only input preprocessing and `extract_features_vector` schema as production, and exclude credential values/tokens/private URLs.

The separate manifest requires `dataset_version`, `source`, `license`, `usage_permission`, `collected_at`, `label_methodology`, immutable file `sha256`, and `kind` (`real_labelled` for eligible real observations; synthetic runs cannot pass deployment gates). Record collection, label adjudication, uncertainty, grouping and population limitations before evaluation. Review source terms; a manifest is not legal approval.

```powershell
.venv/Scripts/python -m pip install -r backend/requirements-evaluation.lock
.venv/Scripts/python -m backend.app.services.ml.offline --dataset <private-observations.jsonl> --manifest <provenance.json> --output <new-empty-run-directory>
```

The command preserves an existing output directory and writes targets/splits before test evaluation. Outputs include `release_targets.json`, `splits.json`, `model.json`, `results.json` and checksums. Keep datasets and reports outside source control. Review shortcut findings, failure examples, supports and confidence intervals before considering deployment. Configure research reads with `ML_RESEARCH_RESULTS`; do not expose private input records through the research artifact.

Unfinished evaluation: temporal holdout, manually reviewed near-template grouping, source-specific and language/device subgroups, warning-policy performance including deterministic rules, coverage/abstention population estimates, and independent replication. These are launch blockers for real-world detection claims, not zero-error results.
