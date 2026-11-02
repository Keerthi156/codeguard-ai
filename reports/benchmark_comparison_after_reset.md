# CodeGuard benchmark comparison

Commit: 97e81aed1f7dea4299461f5d994ea3ac4902fa20
Working tree: clean
Measured on this benchmark only; not a claim of real-world coverage.

## Results

| Source | TP | FP | FN | TN | Precision | Recall | Plan validity | Mean tokens per scan | Mean latency per scan |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| meta | 21 | 0 | 0 | 21 | 1.00 (21/21) | 1.00 (21/21) | 1.00 (94/94) | 3834.9 (92038/24) | 4471.7 ms (107321/24) |
| baseten | 20 | 0 | 0 | 21 | 1.00 (20/20) | 1.00 (20/20) | 1.00 (123/123) | 3974.7 (95393/24) | 6143.8 ms (147451/24) |
| required tests only (no model) | 21 | 0 | 0 | 21 | 1.00 (21/21) | 1.00 (21/21) | n/a (0/0) | n/a | 0 ms (0/24) |

## Routes that differ

nested-resource-vulnerable GET /invoices/{invoice_id}/items: meta=Confirmed, Confirmed, Confirmed; baseten=error, Confirmed, Confirmed; required tests only (no model)=Confirmed, Confirmed, Confirmed
