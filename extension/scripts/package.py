"""Deterministic extension archive; no source, credentials, caches or dev dependencies."""
import hashlib
import json
from pathlib import Path
import zipfile

root = Path(__file__).resolve().parents[1]
manifest = json.loads((root / "manifest.json").read_text())
files = ["manifest.json", "background.js", "content.js", "popup.js", "options.js", "popup.html", "options.html", "popup.css"]
files += [f"icons/icon{size}.png" for size in (16, 32, 48, 128)]
output = root / "release"
output.mkdir(exist_ok=True)
archive = output / f"m-phish-{manifest['version']}.zip"
with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
    for name in sorted(files):
        info = zipfile.ZipInfo(name, (2020, 1, 1, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        info.external_attr = 0o100644 << 16
        z.writestr(info, (root / name).read_bytes())
digest = hashlib.sha256(archive.read_bytes()).hexdigest()
(output / "SHA256SUMS").write_text(f"{digest}  {archive.name}\n")
print(f"Packaged {archive.name}; SHA256 {digest}")
