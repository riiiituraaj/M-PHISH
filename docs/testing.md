# Testing

Backend unit and API tests run with:

```powershell
.venv\Scripts\python.exe -m pytest backend\tests
```

Frontend and extension builds run with `npm run build` in their respective directories. Harmless files in `data/samples` are intended for analyzer and future Playwright integration tests. Do not use live credential pages as test fixtures.
