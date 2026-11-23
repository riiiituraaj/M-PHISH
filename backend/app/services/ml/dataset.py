import numpy as np

FEATURE_NAMES = [
    # URL Features (indices 0 - 10)
    "url_length",
    "hostname_length",
    "subdomain_count",
    "dot_count",
    "hyphen_count",
    "special_char_count",
    "is_ip_address",
    "is_https",
    "has_unusual_port",
    "suspicious_keyword_count",
    "percent_encoded",
    # Domain Features (indices 11 - 15)
    "has_a_record",
    "has_aaaa_record",
    "has_valid_tls",
    "domain_age_days",
    "tls_subject_mismatch",
    # Webpage Features (indices 16 - 21)
    "form_count",
    "password_input_count",
    "text_input_count",
    "hidden_input_count",
    "login_keyword_present",
    "has_urgency_text",
    # Behavior Features (indices 22 - 26)
    "external_form_action",
    "redirect_count",
    "external_domain_count",
    "initiates_download",
    "script_heavy_dom",
    # Context Features (indices 27 - 30)
    "sensitive_field_plus_untrusted_domain",
    "external_credential_destination",
    "brand_name_mismatch",
    "claimed_org_unverified",
]

FEATURE_GROUPS = {
    "URL": list(range(11)),
    "Domain": list(range(11, 16)),
    "Webpage": list(range(16, 22)),
    "Behavior": list(range(22, 27)),
    "Context": list(range(27, 31)),
}


def generate_synthetic_dataset(
    n_samples: int = 1200, random_state: int = 42
) -> tuple[np.ndarray, np.ndarray]:
    """Controlled algorithm fixtures only; no real-world label or realism claim.

    Both classes share count ranges. Labels combine noisy contextual rules rather
    than disjoint dot-count/age ranges. Never load this generator at inference.
    """
    rng = np.random.RandomState(random_state)
    X = rng.binomial(1, 0.3, size=(n_samples, len(FEATURE_NAMES))).astype(float)
    for i, scale in {
        0: 70,
        1: 25,
        2: 2,
        3: 3,
        4: 2,
        5: 4,
        9: 2,
        14: 500,
        16: 2,
        17: 1,
        18: 3,
        19: 2,
        23: 1,
        24: 3,
    }.items():
        X[:, i] = rng.poisson(scale, n_samples)
    X[:, 0] = np.maximum(X[:, 0], X[:, 1] + 8)
    X[:, 27] = (X[:, 17] > 0) & ((X[:, 7] == 0) | (X[:, 6] > 0))
    X[:, 28] = (X[:, 17] > 0) & (X[:, 22] > 0)
    probability = np.clip(0.1 + 0.25 * X[:, 28] + 0.25 * X[:, 29] + 0.15 * X[:, 21], 0.05, 0.95)
    y = rng.binomial(1, probability).astype(int)
    return X, y


def single_feature_shortcuts(X: np.ndarray, y: np.ndarray, threshold: float = 0.97) -> list[dict]:
    """Audit both threshold orientations using balanced accuracy, on labelled input only."""
    findings = []
    for index, name in enumerate(FEATURE_NAMES):
        values = X[:, index]
        observed = np.isfinite(values)
        if np.sum(observed) < 10 or len(np.unique(y[observed])) < 2:
            continue
        candidates = np.unique(values[observed])
        if len(candidates) > 512:
            candidates = np.quantile(candidates, np.linspace(0, 1, 512))
        best = (0.0, None, None)
        for cutoff in candidates:
            for direction in (1, -1):
                predictions = (
                    values[observed] > cutoff if direction == 1 else values[observed] <= cutoff
                )
                labels = y[observed]
                balanced = 0.5 * (
                    np.mean(predictions[labels == 1]) + np.mean(~predictions[labels == 0])
                )
                if balanced > best[0]:
                    best = (
                        float(balanced),
                        float(cutoff),
                        ">" if direction == 1 else "<=",
                    )
        if best[0] >= threshold:
            findings.append(
                {
                    "feature": name,
                    "balanced_accuracy": best[0],
                    "threshold": best[1],
                    "operator": best[2],
                    "note": "Investigate shortcut/leakage; this audit is not independent performance evidence.",
                }
            )
    return findings
