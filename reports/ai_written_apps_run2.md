# CodeGuard AI-written apps

Commit: f44d3dc68e556a583a35cb4441f0047800dcc3b0
Date: 2026-11-02
Provider: baseten
Model: meta-models/muse-spark-open-1026
Generation model: muse-spark-1.3
Generation date: 2026-11-01

Small sample of 10 apps from one model and one prompt; not a claim about AI-written code in general.

## bookmarks

| Route | Status | Hand check |
| --- | --- | --- |
| GET /bookmarks | Inconclusive | unreviewed |
| POST /bookmarks | Inconclusive | unreviewed |
| DELETE /bookmarks/{bookmark_id} | Inconclusive | unreviewed |

## contacts

| Route | Status | Hand check |
| --- | --- | --- |
| GET /contacts | No issue observed | unreviewed |
| POST /contacts | No issue observed | unreviewed |
| DELETE /contacts/{contact_id} | Inconclusive | unreviewed |

## expenses

| Route | Status | Hand check |
| --- | --- | --- |
| GET /expenses | Inconclusive | unreviewed |
| POST /expenses | Inconclusive | unreviewed |
| GET /expenses/{expense_id} | Suspected not reproduced | unreviewed |
| DELETE /expenses/{expense_id} | Inconclusive | unreviewed |

## invoices

| Route | Status | Hand check |
| --- | --- | --- |
| GET /invoices | error: target did not start: target app did not become ready | unreviewed |
| GET /invoices/{invoice_id} | error: target did not start: target app did not become ready | unreviewed |
| POST /invoices | error: target did not start: target app did not become ready | unreviewed |

## journal

| Route | Status | Hand check |
| --- | --- | --- |
| GET /entries | No issue observed | unreviewed |
| POST /entries | No issue observed | unreviewed |
| GET /entries/{entry_id} | Suspected not reproduced | unreviewed |
| DELETE /entries/{entry_id} | Inconclusive | unreviewed |

## notes

| Route | Status | Hand check |
| --- | --- | --- |
| GET /notes | Inconclusive | unreviewed |
| POST /notes | Inconclusive | unreviewed |
| GET /notes/{note_id} | Suspected not reproduced | unreviewed |
| DELETE /notes/{note_id} | Inconclusive | unreviewed |

## reading-list

| Route | Status | Hand check |
| --- | --- | --- |
| GET /reading-list | No issue observed | unreviewed |
| POST /reading-list | No issue observed | unreviewed |
| DELETE /reading-list/{item_id} | No issue observed | unreviewed |

## recipes

| Route | Status | Hand check |
| --- | --- | --- |
| GET /recipes | Inconclusive | unreviewed |
| POST /recipes | Inconclusive | unreviewed |
| GET /recipes/{recipe_id} | Suspected not reproduced | unreviewed |
| DELETE /recipes/{recipe_id} | Inconclusive | unreviewed |

## support-tickets

| Route | Status | Hand check |
| --- | --- | --- |
| GET /tickets | error: target did not start: target app did not become ready | unreviewed |
| POST /tickets | error: target did not start: target app did not become ready | unreviewed |
| GET /tickets/{ticket_id} | error: target did not start: target app did not become ready | unreviewed |

## tasks

| Route | Status | Hand check |
| --- | --- | --- |
| GET /tasks | Inconclusive | unreviewed |
| POST /tasks | Inconclusive | unreviewed |
| GET /tasks/{task_id} | Suspected not reproduced | unreviewed |
| DELETE /tasks/{task_id} | Inconclusive | unreviewed |

## Totals

Generated: 10
Truncated: 0
No routes: 0
Rejected by the safety gate: 0
Not scannable: 0
Runnable: 10
Routes scanned: 35
Confirmed: 0
Confirmed and reviewed true positive: 0
Confirmed and unreviewed: 0
tool call limit: 0
target did not start: 2
model request failed: 0
plan rejected: 0
config: 0
