# Security Controls

- Allowlist URL schemes and reject private-network targets.
- Do not submit forms, authenticate, upload files, or download executables.
- Keep AI explanations downstream of structured evidence.
- Treat unavailable modules as unavailable, never as safe.
- Use environment variables for deployment secrets.
- Run future crawlers in a non-root disposable worker with bounded resources.
- Keep `ENABLE_PLAYWRIGHT=false` until the crawler has a restricted worker network policy.
