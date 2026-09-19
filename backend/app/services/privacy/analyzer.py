from dataclasses import dataclass, field
import re


@dataclass
class RequestedField:
    name: str
    label: str
    is_sensitive: bool
    risk_weight: int
    detected: bool


@dataclass
class PrivacyAssessment:
    privacy_risk_score: int       # 0 - 100 (0 = zero data asked, 100 = extreme collection)
    risk_level: str               # MINIMAL, MODERATE, ELEVATED, HIGH
    requested_fields: list[dict]  # list of field dicts
    sensitive_count: int
    total_count: int
    summary: str


SENSITIVE_PATTERNS = [
    {
        "name": "password",
        "label": "Password / Security PIN",
        "patterns": [r'type=["\']password["\']', r'name=["\'][^"\']*(pass|pwd|pin)[^"\']*["\']', r'placeholder=["\'][^"\']*(password|pin)[^"\']*["\']'],
        "is_sensitive": True,
        "risk_weight": 35,
    },
    {
        "name": "payment_card",
        "label": "Payment Card / CVV",
        "patterns": [r'name=["\'][^"\']*(card|cvv|cvc|expir)[^"\']*["\']', r'placeholder=["\'][^"\']*(card number|cvv|security code)[^"\']*["\']'],
        "is_sensitive": True,
        "risk_weight": 40,
    },
    {
        "name": "bank_account",
        "label": "Bank Account / Routing / UPI",
        "patterns": [r'name=["\'][^"\']*(bank|account_no|routing|upi|ifsc)[^"\']*["\']', r'placeholder=["\'][^"\']*(bank account|routing|upi id|ifsc)[^"\']*["\']'],
        "is_sensitive": True,
        "risk_weight": 35,
    },
    {
        "name": "otp",
        "label": "One-Time Password (OTP)",
        "patterns": [r'name=["\'][^"\']*(otp|one_time|token|2fa)[^"\']*["\']', r'placeholder=["\'][^"\']*(otp|verification code|one-time)[^"\']*["\']'],
        "is_sensitive": True,
        "risk_weight": 30,
    },
    {
        "name": "government_id",
        "label": "Identity Document / SSN / Aadhaar",
        "patterns": [r'name=["\'][^"\']*(ssn|aadhaar|passport|license|gov_id)[^"\']*["\']', r'placeholder=["\'][^"\']*(ssn|social security|aadhaar|passport|identity doc)[^"\']*["\']'],
        "is_sensitive": True,
        "risk_weight": 30,
    },
    {
        "name": "email",
        "label": "Email Address",
        "patterns": [r'type=["\']email["\']', r'name=["\'][^"\']*(email|mail)[^"\']*["\']', r'placeholder=["\'][^"\']*(email|e-mail)[^"\']*["\']'],
        "is_sensitive": False,
        "risk_weight": 8,
    },
    {
        "name": "phone",
        "label": "Phone Number",
        "patterns": [r'type=["\']tel["\']', r'name=["\'][^"\']*(phone|mobile|cell)[^"\']*["\']', r'placeholder=["\'][^"\']*(phone|mobile)[^"\']*["\']'],
        "is_sensitive": False,
        "risk_weight": 10,
    },
    {
        "name": "full_name",
        "label": "Full Name",
        "patterns": [r'name=["\'][^"\']*(name|firstname|lastname)[^"\']*["\']', r'placeholder=["\'][^"\']*(full name|first name)[^"\']*["\']'],
        "is_sensitive": False,
        "risk_weight": 5,
    },
    {
        "name": "physical_address",
        "label": "Physical Address / Postal Code",
        "patterns": [r'name=["\'][^"\']*(address|street|zip|postal|city)[^"\']*["\']', r'placeholder=["\'][^"\']*(address|postal code|zip)[^"\']*["\']'],
        "is_sensitive": False,
        "risk_weight": 10,
    },
]


def analyze_privacy(html_sample: str = "", page_data: dict | None = None) -> PrivacyAssessment:
    """Detect information requested from the user on this webpage."""
    text = (html_sample or "").lower()
    page = page_data or {}
    
    detected_fields = []
    total_risk = 0
    sensitive_count = 0
    
    # Check if page analyzer already found password inputs
    if page.get("password_inputs", 0) > 0 and "password" not in text:
        text += ' <input type="password" name="password"> '

    for item in SENSITIVE_PATTERNS:
        is_detected = any(bool(re.search(pat, text, re.IGNORECASE)) for pat in item["patterns"])
        if is_detected:
            total_risk += item["risk_weight"]
            if item["is_sensitive"]:
                sensitive_count += 1
        detected_fields.append({
            "name": item["name"],
            "label": item["label"],
            "is_sensitive": item["is_sensitive"],
            "detected": is_detected,
        })

    risk_score = min(100, total_risk)
    total_detected = sum(1 for f in detected_fields if f["detected"])

    if risk_score >= 60 or sensitive_count >= 2:
        level = "HIGH"
        summary = f"This website requests {sensitive_count} sensitive information categories (such as passwords or financial tokens). Exercise heightened caution."
    elif risk_score >= 30 or sensitive_count >= 1:
        level = "ELEVATED"
        summary = f"This page asks for sensitive authentication data. Confirm the website identity before entering credentials."
    elif total_detected > 0:
        level = "MODERATE"
        summary = f"Standard contact information requested ({total_detected} fields detected). No high-risk credentials required."
    else:
        level = "MINIMAL"
        summary = "No noticeable user data collection forms detected on this page."

    return PrivacyAssessment(
        privacy_risk_score=risk_score,
        risk_level=level,
        requested_fields=detected_fields,
        sensitive_count=sensitive_count,
        total_count=total_detected,
        summary=summary,
    )

