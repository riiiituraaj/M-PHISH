"""Package an explicit source allowlist, inventory and limited secret-pattern scan."""
import hashlib
import json
import re
import zipfile
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parents[1]
output = root / "artifacts" / "release"
output.mkdir(parents=True, exist_ok=True)
directories = ["backend/app", "backend/tests", "backend/alembic", "web/app", "web/components",
               "web/lib", "web/tests", "extension/src", "extension/tests", "extension/scripts",
               "extension/icons", "deploy", "docs", "scripts", ".github", "data/samples"]
suffixes = {".py", ".ts", ".tsx", ".js", ".cjs", ".mjs", ".json", ".md", ".yml",
            ".yaml", ".sh", ".html", ".css", ".png", ".ini", ".mako", ".xml", ".lock"}
files = set()
for directory in directories:
    for path in (root / directory).rglob("*"):
        if path.is_file() and path.suffix in suffixes and "__pycache__" not in path.parts:
            files.add(path)
for directory in [root, root / "backend", root / "web", root / "extension"]:
    for path in directory.iterdir():
        if path.is_file() and (path.suffix in suffixes or path.name in {
            "Dockerfile", ".dockerignore", ".gitignore", ".env.example", "pyproject.toml"
        } or path.name.startswith("requirements")):
            files.add(path)
patterns = [re.compile(rb"-----BEGIN " + rb"(?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
            re.compile(rb"\bAKIA" + rb"[A-Z0-9]{16}\b"),
            re.compile(rb"\bgh[pousr]_" + rb"[A-Za-z0-9]{30,}\b"),
            re.compile(rb"\bgsk_" + rb"[A-Za-z0-9]{30,}\b")]
findings = []
inventory = []
for path in sorted(files):
    data = path.read_bytes()
    name = path.relative_to(root).as_posix()
    if any(pattern.search(data) for pattern in patterns):
        findings.append(name)
    inventory.append({"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
(output / "secret-scan.json").write_text(json.dumps({
    "at": datetime.now(timezone.utc).isoformat(), "files": len(files), "findings": findings,
    "scope": "Release allowlist; private-key/AWS/GitHub/Groq patterns only. Not an entropy or comprehensive secret audit."
}, indent=2))
if findings:
    raise SystemExit("Potential secret patterns in release files; inspect secret-scan.json.")
(output / "source-inventory.json").write_text(json.dumps(inventory, indent=2))
archive = output / "m-phish-source-0.2.0.zip"
with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
    for entry in inventory:
        info = zipfile.ZipInfo(entry["path"], (2020, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        bundle.writestr(info, (root / entry["path"]).read_bytes())
(output / "SHA256SUMS").write_text(hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + archive.name + "\n")
print(f"Packaged {len(files)} allowlisted source files; no configured secret patterns found.")
