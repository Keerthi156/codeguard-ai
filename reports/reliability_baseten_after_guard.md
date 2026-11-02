# CodeGuard reliability

AUTO-APPROVED (measurement mode, temporary copies only)

Commit: 56b40c45a5793e463dcb2d964310dc47c6ff61d1
Date: 2026-10-30
Provider: baseten
Model: meta-models/muse-spark-open-1026
Runs: 10
Valid runs: 10
Failed runs: 0
Source hash: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250 (unchanged)

Measured on the benchmark fixtures only; not a claim of real-world reliability.

## Outcomes

Findings: 20

| Outcome | Count | Share |
| --- | --- | --- |
| Verified and Hardened on the first attempt | 20 | 20/20 (100%) |
| Verified and Hardened after repair | 0 | 0/20 (0%) |
| Not verified and hardened | 0 | 0/20 (0%) |

## Failure reasons

| Reason | Count |
| --- | --- |
| not JSON | 0 |
| exploit still works | 0 |
| owner control failed | 0 |
| bypass found | 0 |

## Tokens and latency

| Measure | Mean | Max |
| --- | --- | --- |
| Tokens | 11835.8 | 13732 |
| Latency | 15732.9 ms | 18703 ms |

## Patch style

| Flag | Patches |
| --- | --- |
| import inside a function | 0 |
| owner lookup fallback chain | 0 |
| changes more than 8 lines | 0 |
| docstring still says ownership is not checked | 0 |

patches with at least one style flag: 0 of 20

## Runs

### Run 1

Tokens: 11833
Latency: 16527 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 2

Tokens: 11687
Latency: 17060 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 3

Tokens: 12308
Latency: 18138 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 4

Tokens: 13732
Latency: 16911 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 5

Tokens: 11539
Latency: 15567 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 6

Tokens: 12628
Latency: 18703 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 7

Tokens: 11943
Latency: 15791 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 8

Tokens: 10213
Latency: 10942 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 9

Tokens: 11646
Latency: 15156 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 10

Tokens: 10829
Latency: 12534 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |
