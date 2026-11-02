# CodeGuard AI

CodeGuard AI finds, proves, fixes, verifies, and regression-tests Broken Object Level Authorization (BOLA, OWASP API1) bugs in FastAPI apps. It is an entry for the Meta Global AI Developer Hackathon, Indie Developer track, theme "Push the Frontier" (software). A scan reads the app with the Python `ast` module, asks a model for a test plan, sends those tests only to localhost, and records a finding as Confirmed only when deterministic code sees unauthorized access and a passing owner control. A fix is applied only on a temporary copy, and only after a typed `y`.

## The problem

Changing an object id in a request can return another user's record. Ordinary tests usually call the route as the owner, so they do not show what a different user can do. This repository does not claim that AI-written code often lacks authorization checks. In the sample under `experiments/ai_written/`, the hand-check in `experiments/ai_written/review.yaml` records an owner comparison on every `GET /{id}` and `DELETE /{id}` handler (bookmarks uses the field `user`). The generation prompt in `experiments/ai_written/PROMPT.md` says each item belongs to a user and tells the model to seed owner data, which may have primed those checks.

## What it does

There is no separate `verify` subcommand. `fix` proposes a patch and runs the Verified Fix Gate.

1. Scan: `python -m app.cli scan --config fixtures/codeguard.vulnerable.yaml`
2. The scan stores findings in SQLite. Confirmed is decided by `app/findings/classifier.py`, not by the model.
3. Fix: `python -m app.cli fix --config fixtures/codeguard.vulnerable.yaml`
4. Verify: the same `fix` command re-tests the patch on a temporary copy. Approval is the prompt `Apply this fix for {id}? Type y to approve:` in `app/remediation/verifier.py`.
5. Regress: `python -m app.cli regress --config fixtures/codeguard.vulnerable.yaml`
6. Report: `python -m app.cli report --config fixtures/codeguard.vulnerable.yaml`

## Demo

The fixture commands above are the ones in the `app/cli.py` module docstring. With `USE_MOCK_AI=true` (development only; see `app/ai/factory.py`), a scan of `fixtures/codeguard.vulnerable.yaml` prints two Confirmed routes. One evidence line is:

```text
EXPLOIT: GET /documents/101 as bob -> 200, body shows owner alice
```

The same scan prints `2 findings, 2 confirmed`. `reports/latest.html` is the single static page written by `report` (default `--out reports/latest.html`). The copy committed at `d7f85ab` contains both of these lines:

```text
EXPLOIT (non-owner bob): GET /documents/101 as bob -> 200, body shows owner alice
Attempt 1: VERIFIED and HARDENED
```

The copy of `reports/latest.html` at the current commit instead says `No Confirmed findings` and `0 routes scanned, 0 confirmed`. The fixtures are intentionally vulnerable and are for local use only.

## Models

`app/config.py` selects `meta`, `baseten`, or `fireworks` from `--provider` or `PROVIDER`. Each provider reads its own `*_API_KEY`, `*_MODEL`, and `*_BASE_URL`. If no provider is set, `MODEL_API_KEY`, `MODEL_NAME`, and `MODEL_BASE_URL` are used. The base URL is not hardcoded. `app/ai/factory.py` sends Meta, Baseten, and Fireworks through one OpenAI-compatible client. `MockProvider` is used only when `USE_MOCK_AI` is true, and a model failure is not replaced with the mock.

Measured reports name two models. Meta runs use `muse-spark-1.3` (`reports/benchmark_meta_after_reset.md`, `reports/reliability_meta.md`). Baseten runs use `meta-models/muse-spark-open-1026` (`reports/benchmark_baseten_after_reset.md`, `reports/reliability_baseten.md`). The generated apps were also written with `muse-spark-1.3` (`experiments/ai_written/PROMPT.md`). Fireworks is accepted by configuration and by `--provider`. No report under `reports/` records a Fireworks run.

The model does three things. During a scan it may call only `list_routes`, `read_handler`, `get_matrix`, and `submit_plan` (`app/ai/llm_provider.py`) and must finish with `submit_plan`. For a fix it proposes a structured text edit. `app/remediation/verifier.py` repairs a rejected or failed fix at most twice (`_MAX_REPAIR_ATTEMPTS = 2`). Confirmed and Verified are decided by the classifier and the fix gate, not by the model.

On detection, the required-tests ablation matched the model runs. From `reports/benchmark_comparison_after_reset.md` (commit `97e81aed1f7dea4299461f5d994ea3ac4902fa20`), meta and `required tests only (no model)` both have 21 true positives, 0 false positives, 0 false negatives, and 21 true negatives. The reliability reports are where the model is measured writing and repairing patches.

## How it works

```mermaid
flowchart TD
  discover[Static AST route discovery] --> heuristics[Heuristics]
  heuristics --> matrix[Authorization matrix and codeguard.yaml]
  matrix --> plan[Test plan from the model]
  plan --> validator[Plan validator]
  validator --> executor[Localhost-only executor]
  executor --> classifier[Classifier]
  classifier --> sqlite[SQLite]
  sqlite --> patcher[Patcher]
  patcher --> approval[Human approval]
  approval --> gate[Verified Fix Gate with owner control]
  gate --> bypass[Bypass variants]
  bypass --> export[Regression test export]
  export --> report[HTML report]
```

Safety rules checked in this repository:

- Analysis parses source with `ast`. `app/analyzer/auth_checks.py` says target code is never imported or executed.
- The planning tools are the four names above. `submit_plan` has a strict schema, and `app/ai/validator.py` checks the plan against known routes, users, resources, and the policy before anything is sent.
- `app/runner/executor.py` and `app/target_config.py` allow only `http://127.0.0.1` and `http://localhost`.
- Evidence stored by the classifier is redacted. The `Authorization` header is not stored (`app/runner/executor.py`).
- `app/remediation/patcher.py` and `app/remediation/verifier.py` say the original source directory is never modified. Patches are written on a temporary copy.
- A patch starts only after approval. The product prompt accepts only a typed `y`. Reliability reports instead print `AUTO-APPROVED (measurement mode, temporary copies only)`.
- Timeouts, HTTP 5xx, and a body of `resource deleted earlier in this session` are Inconclusive. The classifier module says they are never exploit evidence.
- Each destructive test runs only after the target is restored, in its own session (`execute_plan` in `app/runner/executor.py`).

## Results

Report headers cite commits from the private development branch, which was squashed into the final commit. Report dates below are the `Date` fields in those files. `experiments/ai_written/PROMPT.md` says the dates in that file are UTC.

### Benchmark

Eight apps are listed in `benchmarks/labels.yaml`. That file says `Pairs used while building the tool: none.` It does not define a held-out split. The counts below are every labeled route-run in the named file.

Before the destructive-state fix, from `reports/benchmark_after_dependency_fix.md`, commit `b7744ab1115061137525061404c4d94b385d5517`, date 2026-10-30, model `meta-models/muse-spark-open-1026`, 3 runs:

| TP | FP | FN | TN | Precision | Recall | Errors |
| --- | --- | --- | --- | --- | --- | --- |
| 18 | 0 | 3 | 21 | 1.00 | 0.86 | 0 |

All 3 false negatives are `Suspected not reproduced`. `DELETE /documents/{id}` on uuid-ids-vulnerable is Suspected on all 3 runs in that file.

After the reset, from `reports/benchmark_comparison_after_reset.md`, commit `97e81aed1f7dea4299461f5d994ea3ac4902fa20`:

| Source | TP | FP | FN | TN | Precision | Recall | Plan validity |
| --- | --- | --- | --- | --- | --- | --- | --- |
| meta | 21 | 0 | 0 | 21 | 1.00 (21/21) | 1.00 (21/21) | 1.00 (94/94) |
| baseten | 20 | 0 | 0 | 21 | 1.00 (20/20) | 1.00 (20/20) | 1.00 (123/123) |
| required tests only (no model) | 21 | 0 | 0 | 21 | 1.00 (21/21) | 1.00 (21/21) | n/a (0/0) |

`reports/benchmark_baseten_after_reset.md` (same commit, date 2026-11-01) records `Errors: 1` and `Run 1: error: model request failed` for nested-resource-vulnerable `GET /invoices/{invoice_id}/items`. The comparison file shows that run as `error` and the other two as Confirmed. An error is not counted as a true positive, false positive, false negative, or true negative.

### Fix-loop reliability

Each file says `Measured on the benchmark fixtures only; not a claim of real-world reliability.` Each header says `AUTO-APPROVED (measurement mode, temporary copies only)`. The product path still requires a typed `y`.

Baseline, commit `65b73161fedead5411dd27874bdb59733a4f3775`, date 2026-10-30, 10 runs, 20 findings, 10 valid runs, 0 failed runs. `git log` places this commit before `56b40c4`.

| Report | Verified and Hardened on the first attempt | After repair | Not verified and hardened | Patches with at least one style flag |
| --- | --- | --- | --- | --- |
| `reports/reliability_meta.md` | 20 (20/20) | 0 | 0 | 15 of 20 |
| `reports/reliability_baseten.md` | 20 (20/20) | 0 | 0 | 10 of 20 |

Style flags in `reports/reliability_meta.md`: import inside a function 5, owner lookup fallback chain 4, changes more than 8 lines 3, docstring still says ownership is not checked 10. In `reports/reliability_baseten.md`: 3, 3, 0, and 8 for those same four flags.

After the patch-quality guard, commit `56b40c45a5793e463dcb2d964310dc47c6ff61d1`, date 2026-10-30, same outcome shape: 20 of 20 Verified and Hardened on the first attempt, 0 after repair, 0 not verified. `reports/reliability_meta_after_guard.md` and `reports/reliability_baseten_after_guard.md` both say `patches with at least one style flag: 0 of 20`, and all four flag counts are 0.

### AI-written apps

`reports/ai_written_apps_run3.md` is the latest of the committed experiment reports (commit `5ff4ec4d6db1cf200920dd13f06dbfc5089ac349`, date 2026-11-02, provider baseten, scan model `meta-models/muse-spark-open-1026`, generation model `muse-spark-1.3`, generation date 2026-11-01). The file says: `Small sample of 10 apps from one model and one prompt; not a claim about AI-written code in general.`

| Generated | Runnable | Routes scanned | Confirmed | Not applicable | tool call limit | target did not start |
| --- | --- | --- | --- | --- | --- | --- |
| 10 | 10 | 35 | 0 | 14 | 1 | 2 |

Not applicable is the status `Not applicable: collection route (no resource id)`. The tool-call-limit row is journal (`tool call limit of 6 exceeded`). The two apps that did not become ready are invoices and support-tickets. The hand-check column uses `experiments/ai_written/review.yaml`, which records `checks_owner` for every listed `GET /{id}` and `DELETE /{id}` route and says there is no false negative. The hand-check was recorded by the author.

Earlier committed reports, not the final one:

| File | Commit in the header | Confirmed | Routes scanned | Notes in that file |
| --- | --- | --- | --- | --- |
| `reports/ai_written_apps_run1.md` (same header commit as `reports/ai_written_apps.md`) | `fbf687991ecf6456b626e3a039a33deaebd16492` | 0 | 35 | Generated 10, Runnable 10. No Not applicable total and no error-category totals. |
| `reports/ai_written_apps_run2.md` | `f44d3dc68e556a583a35cb4441f0047800dcc3b0` | 0 | 35 | `tool call limit: 0`, `target did not start: 2` (invoices and support-tickets). |

## Limits and known issues

- Targets are localhost fixtures and the benchmark apps. Reports say they are not a claim of real-world coverage.
- A route with no path parameter is not tested for object-level access. Run 3 counts 14 of those as Not applicable.
- `reports/ai_written_apps_run3.md` states: destructive routes on slow-starting apps time out. Invoices and support-tickets did not become ready.
- Heuristics follow calls in the same file and one level of `Depends`. `app/analyzer/auth_checks.py` says nested dependencies are not entered.
- `async def` handlers are included: `app/analyzer/routes.py` walks `AsyncFunctionDef`. A module-level `APIRouter(prefix=...)` is applied to decorators on that name in the same file. The analyzer does not mention `include_router`, so a prefix passed only there is not read.
- The repository does not mention BFLA or BOPLA. The shipped matrix in `app/target_config.py` is owner-only object access.
- Hosted-model runs are not identical every time. The Baseten benchmark above has one `model request failed` run, and journal stopped on a tool-call limit in run 3 but not in run 2.
- The tool does not replace a security review.

## Getting started

`.cursor/rules/codeguard.mdc` names Python 3.11. From the repository root, in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
Copy-Item .env.example .env
```

Fill names only, in `.env`: `PROVIDER`, `MODEL_API_KEY`, `MODEL_NAME`, `MODEL_BASE_URL`, `USE_MOCK_AI`, `META_API_KEY`, `META_MODEL`, `META_BASE_URL`, `BASETEN_API_KEY`, `BASETEN_MODEL`, `BASETEN_BASE_URL`, `FIREWORKS_API_KEY`, `FIREWORKS_MODEL`, `FIREWORKS_BASE_URL`. Do not commit `.env`.

A first scan without a hosted model:

```powershell
$env:USE_MOCK_AI = "true"
.\.venv\Scripts\python.exe -m app.cli scan --config fixtures/codeguard.vulnerable.yaml
```

A hosted scan uses the same command with `USE_MOCK_AI` false and `--provider meta`, `--provider baseten`, or `--provider fireworks`. The default SQLite file is `data/codeguard.db`. `fixtures/` and `benchmarks/` are intentionally vulnerable in the apps marked vulnerable, and they are for local use only.

## Related work

BOLABuster, from Palo Alto Networks Unit 42, is an LLM-assisted multi-user BOLA tester. Pynt and APIsec are commercial API security testing products. As far as we know, the difference to describe from this repository is what it does here: static analysis tied to source lines, a model-proposed patch that is accepted only after the verification gate, and regression tests exported from a verified fix. This README does not claim that the other tools lack any of those.

## How this was built

The work was done during the hackathon, 27 October through 4 November 2026, by one person, with Cursor and AI assistance. The tool calls Meta models at runtime when a provider is configured. Commit dates below are from `git log --date=short`. The log ends on 2026-11-02.

History note: on 2026-11-02, commit messages on main were rewritten to remove an automated co-author trailer; file contents are unchanged. The short hashes `d7f85ab`, `a4df472`, `b7744ab`, and `521e483` in this file are those commits before that rewrite.

- 2026-10-27: scaffold, vulnerable and secure fixtures, baseline tests, AST route analyzer, authorization heuristics, matrix and target config, mock provider, plan validator, executor, classifier, SQLite, scan command.
- 2026-10-28: real model provider, tool-calling loop, patch proposal on a temporary copy, Verified Fix Gate, model-written fixes.
- 2026-10-29: regression tests and `regress`, bypass variants, one-page HTML report, MVP checkpoint, benchmark baselines (`a4df472`, `b7744ab`, `521e483`).
- 2026-10-30: provider selector, reliability measurement (`65b7316`, `56b40c4`, `1226c8f`), benchmark provider option and no-model ablation, benchmark committed before the destructive-state fix (`de69c8e`).
- 2026-11-01: destructive tests reset target state (`5f69ef0`); benchmark after that reset (`97e81ae`, `a8772a3`); experiment command and 10 generated apps; tool-call limits, portable configs, readiness retry (`f44d3dc`).
- 2026-11-02: collection routes reported as not applicable and restart timeouts named (`5ff4ec4`); experiment run 3, hand-check, and the key-shaped-string check (`5014714`).

## Repository map

- `app/`: scan, model, executor, classifier, patcher, verifier, benchmark, reliability, and experiment code.
- `benchmarks/`: four pairs of local apps and `labels.yaml`.
- `experiments/ai_written/`: ten generated apps, `PROMPT.md`, and `review.yaml`.
- `fixtures/`: the vulnerable and secure document apps and their `codeguard` YAML files.
- `regression_tests/`: tests exported after a verified fix.
- `reports/`: committed measurement files.
- `scripts/`: `check_all.ps1`, `generate_ai_apps.py`, and provider smoke scripts.
- `tests/`: pytest suite.
- `.env.example`: variable names. `.gitignore` ignores `.env`.

License: MIT. See `LICENSE`.

## Future work

- Judge collection routes, or keep them explicitly out of object-level testing.
- Make destructive tests finish on slow-starting apps, including invoices and support-tickets.
- Follow more than one level of `Depends`, and read a prefix passed only to `include_router`.
- Decide whether function-level or property-level authorization belongs in this tool.
- Treat hosted-model variance (a failed request, a tool-call limit) as part of the reported result, not as a silent retry.
