# CodeGuard AI

Security agent that finds, proves, fixes, and verifies Broken Object Level Authorization (BOLA) bugs in FastAPI applications.

## Setup

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
```

## Changelog

### Unreleased

- Day 4: real-model provider (Muse Spark Open via Baseten) with a read-only tool-calling agent loop and a strict plan schema; scan prints a model-run summary.
- Day 3: executor, finding classifier and SQLite store, scan command; vulnerable app 2 Confirmed, secure app none.
- Day 2: AST route analyzer, authorization heuristics, authorization matrix and target config, provider interface with mock, plan validator.
- Repository layout, environment config, and package skeleton.
