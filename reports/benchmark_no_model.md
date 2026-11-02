# CodeGuard benchmark

WARNING: THE WORKING TREE IS DIRTY

Commit: 6e6b15f39daca97d53dd1d3c3e76e38146fabc95
Date: 2026-10-30
required tests only (no model)
Model: -
Working tree: dirty
Measured on this benchmark only; not a claim of real-world coverage.

## Definitions

- A route counts as DETECTED when its status is Confirmed.
- True positive: labeled vulnerable and Confirmed.
- False negative: labeled vulnerable and not Confirmed.
- False negatives are counted separately as not discovered, discovered not flagged, Suspected not reproduced, or Inconclusive.
- True negatives are counted separately as discovered not flagged, or flagged but not reproduced.
- not discovered: static route discovery did not find the route.
- discovered, not flagged: static route discovery found the route and the static heuristics did not mark it Suspected.
- Suspected not reproduced: the static heuristics marked the route Suspected and the scan did not Confirm it.
- flagged by static analysis is yes when the static heuristics marked the route Suspected, and no otherwise.
- False positive: labeled secure and Confirmed.
- True negative: labeled secure and not Confirmed.
- Each run of a labeled route counts once.
- An error is recorded in the table and is not a true positive, false positive, false negative, or true negative.
- Plan-validity rate: accepted tests divided by proposed tests.

## helper-check-vulnerable

Routes the static analyzer discovered: 2. Routes labeled: 2.

| Route | flagged by static analysis | Run 1 | Run 2 | Run 3 | Consistent |
| --- | --- | --- | --- | --- | --- |
| GET /documents/{id} | yes | Confirmed | Confirmed | Confirmed | agreed |
| PUT /documents/{id} | yes | Confirmed | Confirmed | Confirmed | agreed |

## helper-check-secure

Routes the static analyzer discovered: 2. Routes labeled: 2.

| Route | flagged by static analysis | Run 1 | Run 2 | Run 3 | Consistent |
| --- | --- | --- | --- | --- | --- |
| GET /documents/{id} | no | discovered, not flagged | discovered, not flagged | discovered, not flagged | agreed |
| PUT /documents/{id} | no | discovered, not flagged | discovered, not flagged | discovered, not flagged | agreed |

## dependency-check-vulnerable

Routes the static analyzer discovered: 2. Routes labeled: 2.

| Route | flagged by static analysis | Run 1 | Run 2 | Run 3 | Consistent |
| --- | --- | --- | --- | --- | --- |
| GET /documents/{id} | yes | Confirmed | Confirmed | Confirmed | agreed |
| PUT /documents/{id} | yes | Confirmed | Confirmed | Confirmed | agreed |

## dependency-check-secure

Routes the static analyzer discovered: 2. Routes labeled: 2.

| Route | flagged by static analysis | Run 1 | Run 2 | Run 3 | Consistent |
| --- | --- | --- | --- | --- | --- |
| GET /documents/{id} | no | discovered, not flagged | discovered, not flagged | discovered, not flagged | agreed |
| PUT /documents/{id} | no | discovered, not flagged | discovered, not flagged | discovered, not flagged | agreed |

## uuid-ids-vulnerable

Routes the static analyzer discovered: 2. Routes labeled: 2.

| Route | flagged by static analysis | Run 1 | Run 2 | Run 3 | Consistent |
| --- | --- | --- | --- | --- | --- |
| GET /documents/{id} | yes | Confirmed | Confirmed | Confirmed | agreed |
| DELETE /documents/{id} | yes | Suspected | Suspected | Suspected | agreed |

## uuid-ids-secure

Routes the static analyzer discovered: 2. Routes labeled: 2.

| Route | flagged by static analysis | Run 1 | Run 2 | Run 3 | Consistent |
| --- | --- | --- | --- | --- | --- |
| GET /documents/{id} | no | discovered, not flagged | discovered, not flagged | discovered, not flagged | agreed |
| DELETE /documents/{id} | no | discovered, not flagged | discovered, not flagged | discovered, not flagged | agreed |

## nested-resource-vulnerable

Routes the static analyzer discovered: 1. Routes labeled: 1.

| Route | flagged by static analysis | Run 1 | Run 2 | Run 3 | Consistent |
| --- | --- | --- | --- | --- | --- |
| GET /invoices/{invoice_id}/items | yes | Confirmed | Confirmed | Confirmed | agreed |

## nested-resource-secure

Routes the static analyzer discovered: 1. Routes labeled: 1.

| Route | flagged by static analysis | Run 1 | Run 2 | Run 3 | Consistent |
| --- | --- | --- | --- | --- | --- |
| GET /invoices/{invoice_id}/items | yes | Suspected | Suspected | Suspected | agreed |

## Totals

Runs: 3
True positives: 18
False positives: 0
False negatives: 3
- not discovered: 0
- discovered, not flagged: 0
- Suspected not reproduced: 3
- Inconclusive: 0
True negatives: 21
- discovered, not flagged: 18
- flagged but not reproduced: 3
- not discovered: 0
Errors: 0
Precision: 1.00 (18/18)
Recall: 0.86 (18/21)
Plan-validity rate: n/a (0/0)
Plan submissions: 0
Tool calls: 0
Tokens: -
Latency: 0 ms
Routes the static analyzer discovered: 14
Routes labeled: 14

## Misses and false alarms

uuid-ids-vulnerable DELETE /documents/{id} run 1: Suspected: Suspected, not reproduced
uuid-ids-vulnerable DELETE /documents/{id} run 2: Suspected: Suspected, not reproduced
uuid-ids-vulnerable DELETE /documents/{id} run 3: Suspected: Suspected, not reproduced
