# CodeGuard benchmark comparison

Commit: e8358e1284d475f5d174fce93a1cd28c1de275f8
Working tree: clean
Measured on this benchmark only; not a claim of real-world coverage.

## Results

| Source | TP | FP | FN | TN | Precision | Recall | Plan validity | Mean tokens per scan | Mean latency per scan |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| meta | 21 | 0 | 0 | 21 | 1.00 (21/21) | 1.00 (21/21) | 1.00 (96/96) | 3927.2 (94253/24) | 10371 ms (248903/24) |
| baseten | 21 | 0 | 0 | 21 | 1.00 (21/21) | 1.00 (21/21) | 1.00 (136/136) | 4322 (103727/24) | 5600.1 ms (134403/24) |
| required tests only (no model) | 21 | 0 | 0 | 21 | 1.00 (21/21) | 1.00 (21/21) | n/a (0/0) | n/a | 0 ms (0/24) |

## Routes that differ

(none)
