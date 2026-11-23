"""Local rule benchmark, not a service capacity or detection claim."""
import json
import platform
import statistics
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

root = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(root))
from backend.app.analysis import quick_check

samples = []
for index in range(1010):
    start = time.perf_counter()
    result = quick_check("https://example.com/")
    assert result["tier"] == "UNKNOWN"
    if index >= 10:
        samples.append((time.perf_counter() - start) * 1000)
samples.sort()
output = root / "artifacts" / "verification" / "rule-benchmark.json"
output.parent.mkdir(parents=True, exist_ok=True)
output.write_text(json.dumps({"at": datetime.now(timezone.utc).isoformat(),
    "scope": "In-process origin-only quick_check; no HTTP, authentication, queue, collection or ML; not production capacity.",
    "platform": platform.platform(), "processor": platform.processor(), "python": platform.python_version(),
    "concurrency": 1, "warmup": 10, "samples": len(samples),
    "milliseconds": {"median": statistics.median(samples), "p95": samples[949], "p99": samples[989]}
}, indent=2))
print(output.read_text())
