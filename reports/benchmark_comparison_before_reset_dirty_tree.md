# CodeGuard benchmark comparison

WARNING: THE WORKING TREE IS DIRTY

Working tree: dirty
Measured on this benchmark only; not a claim of real-world coverage.

## Results

| Source | TP | FP | FN | TN | Precision | Recall | Plan validity | Mean tokens per scan | Mean latency per scan |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| meta | 18 | 0 | 3 | 21 | 1.00 (18/18) | 0.86 (18/21) | 1.00 (103/103) | 3939.2 (94541/24) | 5551.9 ms (133246/24) |
| baseten | 18 | 0 | 3 | 21 | 1.00 (18/18) | 0.86 (18/21) | 1.00 (126/126) | 4113.5 (98725/24) | 4999.2 ms (119981/24) |
| required tests only (no model) | 18 | 0 | 3 | 21 | 1.00 (18/18) | 0.86 (18/21) | n/a (0/0) | n/a | 0 ms (0/24) |

## Routes that differ

(none)
