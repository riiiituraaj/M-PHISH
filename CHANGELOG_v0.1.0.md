# M-PHISH X Changelog

## Version 0.1.0

This release captures the current state of the project as a working digital trust and web safety platform built on top of the original phishing detection baseline.

### Overview

M-PHISH X has evolved from a conventional phishing detector into a broader digital trust and safety platform. The product now assesses website authenticity, credential routing, privacy risk, suspicious download behavior, synthetic/AI-assisted web indicators, and multifactor trust state transitions before a user takes risky actions.

### Core Product Updates

- Reframed the project as an intelligent digital trust and web safety layer rather than a single phishing classifier.
- Added trust-focused product messaging around:
  - Who am I giving this to?
  - What is this website asking from me?
  - Can I trust it?
  - What should I do next?
- Introduced human-readable explanations and actionable recommendations based on evidence rather than raw technical dumps.
- Preserved the original phishing detection architecture while expanding it into a broader trust model.

### Architecture and backend updates

- FastAPI backend remains the central orchestration layer for investigations, quick checks, report storage, and contextual analysis.
- Added modular service structure for:
  - identity analysis
  - privacy analysis
  - synthetic content analysis
  - deceptive claim analysis
  - download safety analysis
  - campaign similarity analysis
  - digital trust scoring
  - calibrated ML inference
- Added investigation persistence through SQLite with evidence, timeline, features, and context graph storage.
- Added versioned API endpoints under /api/v1 for quick-checks, investigations, reports, timeline, graph, and dynamic trust evaluations.
- Added structured report output with trust profile, authenticity score, evidence, explanations, and recommendations.

### Digital trust and protection features

- Implemented dynamic trust transitions across states:
  - TRUSTED
  - CAUTION
  - HIGH_RISK
  - STOP
- Added trust-before-you-act logic for sensitive interactions such as credential entry and payment flows.
- Added identity mismatch analysis to compare claimed service identity with the actual destination or website address.
- Added safe-route recommendations to guide users toward verified official services.
- Included risk escalation based on cross-origin credential submission, password fields, suspicious form behavior, and external data destinations.

### Identity, privacy, and synthetic analysis

- Added identity analysis that can detect likely impersonation or brand mismatch using observed claims and form destinations.
- Added privacy assessment for requested personal information, including passwords, OTPs, account data, identity documents, and payment information.
- Added contextual synthetic content detection to identify AI-assisted or templated web patterns without labeling AI-generated content as inherently malicious.
- Added deceptive claim analysis that compares page claims with observable domain and behavior signals.
- Added download safety heuristics for executable or script-like file downloads.

### ML and research components

- Integrated a primary XGBoost-based phishing model with calibrated probability output.
- Added Platt scaling calibration method for probability output.
- Included baseline model comparisons using:
  - Logistic Regression
  - Random Forest
- Added research experiment infrastructure for ablation studies across:
  - URL only
  - URL + Domain
  - URL + Domain + Web
  - URL + Domain + Web + Behavior
  - Full multimodal M-PHISH
- Added experimental metrics including accuracy, precision, recall, F1, ROC-AUC, PR-AUC, false positive rate, false negative rate, Brier score, and inference latency.

### Frontend and extension updates

- Dashboard now presents a premium digital trust report with a trust score, investigation summary, timeline, evidence, and technical details.
- Extension UI provides quick trust verdicts and can surface deep investigation results for suspicious pages.
- Popup and background logic now support trust state updates and risk badges for browser navigation.

### Security and validation

- Kept security guardrails for private network and local target rejection.
- Enforced allowlist handling for supported schemes.
- Prevented credential submission and automated sensitive interaction by default.
- Applied rate limiting and request lifecycle tracking to investigation endpoints.
- Maintained evidence-based decisioning so explanations are grounded in structured signals rather than invented facts.

### Test coverage

- Added and maintained automated tests covering:
  - safe website behavior
  - phishing and risky pages
  - identity mismatch and safe-route logic
  - synthetic content detection context
  - privacy-heavy form detection
  - dangerous download analysis
  - dynamic trust evaluation
  - model calibration bounds
  - multimodal experiment output
  - demo scenarios and API contract checks

### Notes for this release

This version is not a generic malware scanner or a claim of absolute safety. It remains a bounded, evidence-driven digital trust assistant that prioritizes explainability, user safety, and sensible guidance.

The project is intentionally designed as a transparent web-safety platform with strong academic and product framing rather than a single-score phishing-only detector.

---

## Summary

Version 0.1.0 marks the shift from a basic phishing prototype to a broader, modular, evidence-based digital trust platform with academic research hooks, human-readable decision support, and a more user-friendly safety workflow.
