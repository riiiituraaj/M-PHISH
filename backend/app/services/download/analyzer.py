from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urlparse

from ..observations import page_available


@dataclass
class DownloadSafetyAssessment:
    has_download: bool
    file_name: str | None
    file_extension: str | None
    is_executable_or_script: bool
    risk_level: str  # SAFE, ATTENTION, HIGH_RISK
    explanation: str
    availability: str = "available"
    content_scanned: bool = False


RISKY_EXTENSIONS = {
    ".exe",
    ".msi",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".js",
    ".scr",
    ".pif",
    ".iso",
    ".apk",
    ".dll",
    ".hta",
    ".wsf",
    ".cpl",
}

ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".tar", ".gz"}


def analyze_download(
    url: str,
    page_data: dict,
    html_sample: str = "",
    overall_trust: int | None = None,
) -> DownloadSafetyAssessment:
    """Evaluate download links detected on the page or direct URL download target."""
    parsed = urlparse(url)
    path = parsed.path.lower()

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

    class Links(HTMLParser):
        def __init__(self):
            super().__init__()
            self.links = []

        def handle_starttag(self, tag, attrs):
            if tag == "a":
                value = dict(attrs).get("href")
                if value and len(self.links) < 200:
                    self.links.append(value)

    parser = Links()
    parser.feed((html_sample or "")[:250000])
    for cand_url in parser.links + page_data.get("download_urls", [])[:100]:
        if download_url or not isinstance(cand_url, str):
            continue
        candidate_path = urlparse(cand_url).path.lower()
        ext = next(
            (ext for ext in RISKY_EXTENSIONS | ARCHIVE_EXTENSIONS if candidate_path.endswith(ext)),
            None,
        )
        if ext:
            download_url, file_name, file_ext = (
                cand_url,
                candidate_path.split("/")[-1][:100],
                ext,
            )

    if not download_url:
        return DownloadSafetyAssessment(
            has_download=False,
            file_name=None,
            file_extension=None,
            is_executable_or_script=False,
            risk_level="NO_DOWNLOAD_OBSERVED"
            if page_available(page_data) or html_sample
            else "UNKNOWN",
            explanation="No supported download link observed in the completed checks. No file contents were scanned.",
            availability="available" if page_available(page_data) or html_sample else "partial",
        )

    is_risky = file_ext in RISKY_EXTENSIONS
    file_name = "redacted-file" + str(file_ext)

    if is_risky and overall_trust is not None and overall_trust < 60:
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
    elif file_ext in ARCHIVE_EXTENSIONS and (overall_trust is None or overall_trust < 50):
        risk_level = "ATTENTION"
        explanation = (
            f"An archive file '{file_name}' ({file_ext}) is offered by an unverified source. "
            f"Inspect its contents carefully before extracting or executing programs."
        )
    else:
        risk_level = "NO_ADDITIONAL_RISK_OBSERVED"
        explanation = (
            f"Archive download '{file_name}' detected. Its contents have not been scanned."
        )

    return DownloadSafetyAssessment(
        has_download=True,
        file_name=file_name,
        file_extension=file_ext,
        is_executable_or_script=is_risky,
        risk_level=risk_level,
        explanation=explanation,
    )
