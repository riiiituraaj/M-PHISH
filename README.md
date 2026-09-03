# M-PHISH X

Contextual digital threat intelligence for safer decisions. This v0.1 prototype connects URL, page, behavior, and context observations into a transparent risk assessment with human-readable guidance.

The extension is always-on when `Protection ON` is enabled. It listens only for top-level HTTP(S) navigations, performs a quick URL check, remains quiet for low-risk pages, and performs the deeper API investigation only for medium/high or uncertain results. Results are cached locally for five minutes per URL.

## Run locally

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r backend/requirements.txt
uvicorn app.main:app --app-dir backend --reload
```

In another terminal:

```bash
cd web
npm install
npm run dev
```

Open `http://localhost:3000`. If the API is unavailable, the dashboard keeps a safe demo report available for the product walkthrough.

## Extension

```bash
cd extension
npm install
npm run build
```

Load the `extension` directory as an unpacked extension in Chrome. Start the backend and dashboard before investigating a tab.

Open the extension menu and choose **Options** to change protection, automatic notifications, low-risk badges, and explanation level. After changing extension source, run `npm run build` and click **Reload** in `chrome://extensions`.

After loading it, click the extension once to confirm `Protection ON`. Navigate to a normal site to see a quiet green badge. Navigate to a suspicious-looking test URL such as `https://login-verify.example.com/account` to trigger the deeper check and a notification. The popup shows the latest result and links to the dashboard report.

The analyzer refuses localhost, loopback, private, link-local, and reserved IP targets. It never submits credentials or automatically interacts with authentication systems. Remote Playwright crawling is intentionally isolated from this lightweight first slice and should run in a disposable, restricted worker before being enabled.

## Groq explanations

Groq is optional. Put a replacement key in the local `.env` file, not `.env.example`:

```env
AI_PROVIDER=groq
GROQ_API_KEY=your_new_key_here
AI_MODEL=llama-3.3-70b-versatile
```

Restart the backend after changing `.env`. Deep investigations will call Groq only to phrase the structured evidence. Risk scoring remains deterministic, and timeouts or provider errors automatically use the local fallback. Never submit API keys to source control.

## Verification

```bash
py -m py_compile backend/app/main.py backend/tests/test_api.py
cd web && npm run build
cd ../extension && npm run build
```

The current crawler stage is intentionally deterministic and safe. Playwright, remote screenshots, DNS enrichment, ML inference, and LLM explanation are extension points for the next isolated worker iteration; the rule-based evidence and explanation path remains the source of truth when those services are unavailable.

Versioned deep investigations use a queued contract: `POST /api/v1/investigations` returns an investigation ID and `QUEUED`; poll `GET /api/v1/investigations/{id}` for `ANALYZING`, `COMPLETED`, or `FAILED`. The unversioned route remains synchronous for local compatibility.

Run database migrations when using the migration-backed deployment:

```powershell
cd backend
..\.venv\Scripts\python.exe -m alembic upgrade head
```
