from dataclasses import dataclass
from urllib.parse import urlparse
import re


@dataclass
class DownloadSafetyAssessment:
    has_download: bool
    file_name: str | None
    file_extension: str | None
    is_executable_or_script: bool
    risk_level: str  # SAFE, ATTENTION, HIGH_RISK
    explanation: str


RISKY_EXTENSIONS = {
    ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".scr", ".pif",
    ".iso", ".apk", ".dll", ".hta", ".wsf", ".cpl"
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz"
}


def analyze_download(
    url: str,
    page_data: dict,
    html_sample: str = "",
    overall_trust: int = 100,
) -> DownloadSafetyAssessment:
    """Evaluate download links detected on the page or direct URL download target."""
    parsed = urlparse(url)
    path = parsed.path.lower()
    text = (html_sample or "").lower()

    # Find download links in sample HTML or URL path
    download_url = None
    file_name = None
    file_ext = None

    # Check direct URL
    for ext in RISKY_EXTENSIONS | ARCHIVE_EXTENSIONS:
        if path.endswith(ext):
            download_url = url
            file_name = path.split("/")[-1]
            file_ext = ext
            break

    # Check in page sample links
    if not download_url:
        match = re.search(r'href=["\']([^"\']+\.([a-z0-9]{2,4}))["\'](?:\s+download)?', text)
        if match:
            cand_url = match.group(1)
            ext = f".{match.group(2).lower()}"
            if ext in RISKY_EXTENSIONS or ext in ARCHIVE_EXTENSIONS:
                download_url = cand_url
                file_name = cand_url.split("/")[-1]
                file_ext = ext

    if not download_url:
        return DownloadSafetyAssessment(
            has_download=False,
            file_name=None,
            file_extension=None,
            is_executable_or_script=False,
            risk_level="SAFE",
            explanation="No direct executable or binary file downloads detected on this webpage.",
        )

    is_risky = file_ext in RISKY_EXTENSIONS

    if is_risky and overall_trust < 60:
        risk_level = "HIGH_RISK"
        explanation = (
            f"The download target '{file_name}' is an executable or script ({file_ext}) "
            f"originating from a website with low digital trust signals. We recommend not running this file."
        )
    elif is_risky:
        risk_level = "ATTENTION"
        explanation = (
            f"The file '{file_name}' ({file_ext}) can execute code directly on your computer. "
            f"Confirm that you specifically intended to download this application."
        )
    elif file_ext in ARCHIVE_EXTENSIONS and overall_trust < 50:
        risk_level = "ATTENTION"
        explanation = (
            f"An archive file '{file_name}' ({file_ext}) is offered by an unverified source. "
            f"Inspect its contents carefully before extracting or executing programs."
        )
    else:
        risk_level = "SAFE"
        explanation = f"Standard document or media download '{file_name}' detected."

    return DownloadSafetyAssessment(
        has_download=True,
        file_name=file_name,
        file_extension=file_ext,
        is_executable_or_script=is_risky,
        risk_level=risk_level,
        explanation=explanation,
    )

