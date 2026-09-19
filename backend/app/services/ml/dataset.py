from pathlib import Path
import csv
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
    "URL": list(range(0, 11)),
    "Domain": list(range(11, 16)),
    "Webpage": list(range(16, 22)),
    "Behavior": list(range(22, 27)),
    "Context": list(range(27, 31)),
}


def generate_synthetic_dataset(n_samples: int = 1200, random_state: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """
    Generate a realistic, balanced dataset of web interactions reflecting:
    - Benign portals, news sites, universities, public services
    - Credential harvesting, deceptive login clones, fake banking, malicious downloads
    """
    rng = np.random.RandomState(random_state)
    half = n_samples // 2
    
    # Benign samples: label = 0
    benign_X = np.zeros((half, len(FEATURE_NAMES)), dtype=np.float32)
    benign_X[:, 0] = rng.uniform(15, 60, half)        # url_length
    benign_X[:, 1] = rng.uniform(8, 22, half)         # hostname_length
    benign_X[:, 2] = rng.poisson(0.3, half)           # subdomain_count
    benign_X[:, 3] = rng.uniform(1, 3, half)          # dot_count
    benign_X[:, 4] = rng.poisson(0.2, half)           # hyphen_count
    benign_X[:, 5] = rng.poisson(1.0, half)           # special_char_count
    benign_X[:, 6] = 0.0                              # is_ip_address
    benign_X[:, 7] = (rng.rand(half) > 0.05).astype(float)  # is_https (95% https)
    benign_X[:, 8] = 0.0                              # has_unusual_port
    benign_X[:, 9] = rng.poisson(0.1, half)           # suspicious_keyword_count
    benign_X[:, 10] = (rng.rand(half) > 0.9).astype(float) # percent_encoded
    
    benign_X[:, 11] = 1.0                             # has_a_record
    benign_X[:, 12] = (rng.rand(half) > 0.4).astype(float) # has_aaaa_record
    benign_X[:, 13] = benign_X[:, 7]                  # has_valid_tls
    benign_X[:, 14] = rng.uniform(365, 5000, half)    # domain_age_days
    benign_X[:, 15] = 0.0                             # tls_subject_mismatch
    
    benign_X[:, 16] = rng.poisson(1.2, half)          # form_count
    benign_X[:, 17] = rng.choice([0, 1], p=[0.75, 0.25], size=half) # password_input_count
    benign_X[:, 18] = rng.poisson(2.5, half)          # text_input_count
    benign_X[:, 19] = rng.poisson(1.0, half)          # hidden_input_count
    benign_X[:, 20] = benign_X[:, 17]                 # login_keyword_present
    benign_X[:, 21] = (rng.rand(half) > 0.95).astype(float) # has_urgency_text
    
    benign_X[:, 22] = 0.0                             # external_form_action (rare/0 in benign)
    benign_X[:, 23] = rng.poisson(0.4, half)          # redirect_count
    benign_X[:, 24] = rng.poisson(1.5, half)          # external_domain_count
    benign_X[:, 25] = (rng.rand(half) > 0.97).astype(float) # initiates_download
    benign_X[:, 26] = (rng.rand(half) > 0.8).astype(float)  # script_heavy_dom
    
    benign_X[:, 27] = 0.0                             # sensitive_field_plus_untrusted_domain
    benign_X[:, 28] = 0.0                             # external_credential_destination
    benign_X[:, 29] = 0.0                             # brand_name_mismatch
    benign_X[:, 30] = 0.0                             # claimed_org_unverified
    
    # Phishing / Deceptive samples: label = 1
    phish_X = np.zeros((half, len(FEATURE_NAMES)), dtype=np.float32)
    phish_X[:, 0] = rng.uniform(45, 160, half)        # url_length
    phish_X[:, 1] = rng.uniform(18, 55, half)         # hostname_length
    phish_X[:, 2] = rng.poisson(2.2, half)           # subdomain_count
    phish_X[:, 3] = rng.uniform(3, 7, half)           # dot_count
    phish_X[:, 4] = rng.poisson(1.8, half)           # hyphen_count
    phish_X[:, 5] = rng.poisson(4.0, half)           # special_char_count
    phish_X[:, 6] = (rng.rand(half) > 0.75).astype(float)  # is_ip_address
    phish_X[:, 7] = (rng.rand(half) > 0.45).astype(float)  # is_https
    phish_X[:, 8] = (rng.rand(half) > 0.8).astype(float)   # has_unusual_port
    phish_X[:, 9] = rng.poisson(2.3, half)           # suspicious_keyword_count
    phish_X[:, 10] = (rng.rand(half) > 0.5).astype(float)  # percent_encoded
    
    phish_X[:, 11] = (rng.rand(half) > 0.05).astype(float) # has_a_record
    phish_X[:, 12] = (rng.rand(half) > 0.8).astype(float)  # has_aaaa_record
    phish_X[:, 13] = (rng.rand(half) > 0.6).astype(float)  # has_valid_tls
    phish_X[:, 14] = rng.exponential(45, half)        # domain_age_days (new domains)
    phish_X[:, 15] = (rng.rand(half) > 0.35).astype(float) # tls_subject_mismatch
    
    phish_X[:, 16] = rng.poisson(1.8, half) + 1       # form_count
    phish_X[:, 17] = (rng.rand(half) > 0.25).astype(float) # password_input_count (75% have password)
    phish_X[:, 18] = rng.poisson(3.0, half)          # text_input_count
    phish_X[:, 19] = rng.poisson(2.5, half)          # hidden_input_count
    phish_X[:, 20] = (rng.rand(half) > 0.15).astype(float) # login_keyword_present
    phish_X[:, 21] = (rng.rand(half) > 0.3).astype(float)  # has_urgency_text
    
    phish_X[:, 22] = (rng.rand(half) > 0.35).astype(float) # external_form_action
    phish_X[:, 23] = rng.poisson(2.1, half)          # redirect_count
    phish_X[:, 24] = rng.poisson(3.5, half)          # external_domain_count
    phish_X[:, 25] = (rng.rand(half) > 0.7).astype(float)  # initiates_download
    phish_X[:, 26] = (rng.rand(half) > 0.3).astype(float)  # script_heavy_dom
    
    phish_X[:, 27] = phish_X[:, 17] * (rng.rand(half) > 0.2).astype(float) # sensitive field + untrusted
    phish_X[:, 28] = phish_X[:, 22] * phish_X[:, 17] # external_credential_destination
    phish_X[:, 29] = (rng.rand(half) > 0.3).astype(float)  # brand_name_mismatch
    phish_X[:, 30] = (rng.rand(half) > 0.25).astype(float) # claimed_org_unverified
    
    X = np.vstack([benign_X, phish_X])
    y = np.hstack([np.zeros(half, dtype=np.int32), np.ones(half, dtype=np.int32)])
    
    # Shuffle
    indices = rng.permutation(len(y))
    return X[indices], y[indices]



def load_external_dataset(path: str | None) -> tuple[np.ndarray, np.ndarray, str]:
    """Load an independently sourced CSV benchmark when configured.

    Expected schema: one column named ``label`` (0/1) plus any subset of FEATURE_NAMES.
    Missing feature columns are filled with neutral defaults. The file is intentionally
    external to the repository so users cannot confuse demo data with real-world evidence.
    """
    if not path:
        X, y = generate_synthetic_dataset(n_samples=2000, random_state=42)
        return X, y, "synthetic-development-benchmark"
    csv_path = Path(path)
    if not csv_path.exists():
        raise FileNotFoundError(f"Configured phishing dataset not found: {csv_path}")
    rows = list(csv.DictReader(csv_path.open("r", encoding="utf-8", newline="")))
    if not rows or "label" not in rows[0]:
        raise ValueError("External benchmark CSV must contain a 'label' column.")
    X = np.zeros((len(rows), len(FEATURE_NAMES)), dtype=np.float32)
    y = np.zeros(len(rows), dtype=np.int32)
    for row_idx, row in enumerate(rows):
        try:
            y[row_idx] = int(float(row["label"]))
        except (TypeError, ValueError) as exc:
            raise ValueError(f"Invalid label at row {row_idx + 2}") from exc
        if y[row_idx] not in (0, 1):
            raise ValueError(f"Labels must be 0 or 1; row {row_idx + 2} has {y[row_idx]}")
        for col_idx, name in enumerate(FEATURE_NAMES):
            value = row.get(name)
            if value in (None, ""):
                continue
            try:
                X[row_idx, col_idx] = float(value)
            except ValueError as exc:
                raise ValueError(f"Invalid numeric value for '{name}' at row {row_idx + 2}") from exc
    if len(np.unique(y)) < 2:
        raise ValueError("External benchmark must contain both benign (0) and phishing (1) labels.")
    return X, y, f"external-csv:{csv_path.name}"
