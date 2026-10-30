<!-- Local testing only. Benchmark apps were not used to build the tool. -->

# Benchmarks

These eight FastAPI apps are intentionally small pairs for measuring CodeGuard on localhost after the MVP was frozen. Each vulnerable app has a secure twin. Tokens and records are synthetic and live in memory.

Pairs used while building the tool: none.

Results are reported as measured. This directory does not contain scores. A number belongs here only after a run of the frozen tool produces it.

## Pairs

1. **helper-check.** The handler calls a helper. The secure helper compares the caller with the document owner. The vulnerable helper only loads the record.
2. **dependency-check.** A `Depends()` dependency loads the document. The secure dependency enforces ownership. The vulnerable dependency only authenticates and loads.
3. **uuid-ids.** Documents are addressed by UUID strings. Each app has GET and DELETE.
4. **nested-resource.** `GET /invoices/{invoice_id}/items` must check ownership on the parent invoice. The vulnerable app does not.

## Run one app

Every app listens on `127.0.0.1` and takes `--port`. The default port is the one in that app's `codeguard.yaml`.

```text
uvicorn benchmarks.helper_check.vulnerable.app:app --host 127.0.0.1 --port 8101
python -m benchmarks.helper_check.secure.app --port 8102
```

| App | Default port |
| --- | --- |
| helper-check vulnerable | 8101 |
| helper-check secure | 8102 |
| dependency-check vulnerable | 8103 |
| dependency-check secure | 8104 |
| uuid-ids vulnerable | 8105 |
| uuid-ids secure | 8106 |
| nested-resource vulnerable | 8107 |
| nested-resource secure | 8108 |

`labels.yaml` is the hand-written ground truth for each app and route. The pytest file next to it checks those labels through ASGI and does not run CodeGuard.
