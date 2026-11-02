# CodeGuard reliability

AUTO-APPROVED (measurement mode, temporary copies only)

Commit: 65b73161fedead5411dd27874bdb59733a4f3775
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
| Tokens | 12860.9 | 14399 |
| Latency | 20870.2 ms | 23794 ms |

## Patch style

| Flag | Patches |
| --- | --- |
| import inside a function | 3 |
| owner lookup fallback chain | 3 |
| changes more than 8 lines | 0 |
| docstring still says ownership is not checked | 8 |

patches with at least one style flag: 10 of 20

## Runs

### Run 1

Tokens: 13370
Latency: 23417 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 2

Tokens: 13095
Latency: 23794 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 3

Tokens: 14399
Latency: 22489 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 4

Tokens: 12589
Latency: 20071 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 5

Tokens: 12772
Latency: 19671 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 6

Tokens: 11884
Latency: 17279 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 7

Tokens: 11900
Latency: 18345 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 8

Tokens: 12946
Latency: 22300 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 9

Tokens: 12812
Latency: 20420 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 10

Tokens: 12842
Latency: 20916 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |
