# CodeGuard AI-written apps

Commit: 5ff4ec4d6db1cf200920dd13f06dbfc5089ac349
Date: 2026-11-02
Provider: baseten
Model: meta-models/muse-spark-open-1026
Generation model: muse-spark-1.3
Generation date: 2026-11-01

Small sample of 10 apps from one model and one prompt; not a claim about AI-written code in general.

## bookmarks

| Route | Status | Hand check |
| --- | --- | --- |
| GET /bookmarks | Not applicable: collection route (no resource id) | unreviewed |
| POST /bookmarks | Not applicable: collection route (no resource id) | unreviewed |
| DELETE /bookmarks/{bookmark_id} | Suspected not reproduced | checks_owner |

## contacts

| Route | Status | Hand check |
| --- | --- | --- |
| GET /contacts | Not applicable: collection route (no resource id) | unreviewed |
| POST /contacts | Not applicable: collection route (no resource id) | unreviewed |
| DELETE /contacts/{contact_id} | Suspected not reproduced | checks_owner |

## expenses

| Route | Status | Hand check |
| --- | --- | --- |
| GET /expenses | Not applicable: collection route (no resource id) | unreviewed |
| POST /expenses | Not applicable: collection route (no resource id) | unreviewed |
| GET /expenses/{expense_id} | Suspected not reproduced | checks_owner |
| DELETE /expenses/{expense_id} | Suspected not reproduced | checks_owner |

## invoices

| Route | Status | Hand check |
| --- | --- | --- |
| GET /invoices | error: target did not start: target app did not become ready | unreviewed |
| GET /invoices/{invoice_id} | error: target did not start: target app did not become ready | checks_owner |
| POST /invoices | error: target did not start: target app did not become ready | unreviewed |

## journal

| Route | Status | Hand check |
| --- | --- | --- |
| GET /entries | error: tool call limit: tool call limit of 6 exceeded | unreviewed |
| POST /entries | error: tool call limit: tool call limit of 6 exceeded | unreviewed |
| GET /entries/{entry_id} | error: tool call limit: tool call limit of 6 exceeded | checks_owner |
| DELETE /entries/{entry_id} | error: tool call limit: tool call limit of 6 exceeded | checks_owner |

## notes

| Route | Status | Hand check |
| --- | --- | --- |
| GET /notes | Not applicable: collection route (no resource id) | unreviewed |
| POST /notes | Not applicable: collection route (no resource id) | unreviewed |
| GET /notes/{note_id} | Suspected not reproduced | checks_owner |
| DELETE /notes/{note_id} | Suspected not reproduced | checks_owner |

## reading-list

| Route | Status | Hand check |
| --- | --- | --- |
| GET /reading-list | Not applicable: collection route (no resource id) | unreviewed |
| POST /reading-list | Not applicable: collection route (no resource id) | unreviewed |
| DELETE /reading-list/{item_id} | No issue observed | checks_owner |

## recipes

| Route | Status | Hand check |
| --- | --- | --- |
| GET /recipes | Not applicable: collection route (no resource id) | unreviewed |
| POST /recipes | Not applicable: collection route (no resource id) | unreviewed |
| GET /recipes/{recipe_id} | Suspected not reproduced | checks_owner |
| DELETE /recipes/{recipe_id} | Suspected not reproduced | checks_owner |

## support-tickets

| Route | Status | Hand check |
| --- | --- | --- |
| GET /tickets | error: target did not start: target app did not become ready | unreviewed |
| POST /tickets | error: target did not start: target app did not become ready | unreviewed |
| GET /tickets/{ticket_id} | error: target did not start: target app did not become ready | checks_owner |

## tasks

| Route | Status | Hand check |
| --- | --- | --- |
| GET /tasks | Not applicable: collection route (no resource id) | unreviewed |
| POST /tasks | Not applicable: collection route (no resource id) | unreviewed |
| GET /tasks/{task_id} | Suspected not reproduced | checks_owner |
| DELETE /tasks/{task_id} | Suspected not reproduced | checks_owner |

## Totals

Generated: 10
Truncated: 0
No routes: 0
Rejected by the safety gate: 0
Not scannable: 0
Runnable: 10
Routes scanned: 35
Confirmed: 0
Not applicable: 14
Confirmed and reviewed true positive: 0
Confirmed and unreviewed: 0
tool call limit: 1
target did not start: 2
model request failed: 0
plan rejected: 0
config: 0

## Known limit

Destructive routes on slow-starting apps time out. Invoices and support-tickets did not become ready, so their routes were not judged. Restart timing was not changed further.
