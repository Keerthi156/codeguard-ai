# CodeGuard reliability

AUTO-APPROVED (measurement mode, temporary copies only)

Commit: 65b73161fedead5411dd27874bdb59733a4f3775
Date: 2026-10-30
Provider: meta
Model: muse-spark-1.3
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
| Tokens | 13560.7 | 17980 |
| Latency | 33295.9 ms | 49542 ms |

## Patch style

| Flag | Patches |
| --- | --- |
| import inside a function | 5 |
| owner lookup fallback chain | 4 |
| changes more than 8 lines | 3 |
| docstring still says ownership is not checked | 10 |

patches with at least one style flag: 15 of 20

## Runs

### Run 1

Tokens: 13084
Latency: 29782 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 2

Tokens: 12087
Latency: 26121 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 3

Tokens: 17980
Latency: 49542 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 4

Tokens: 12745
Latency: 30053 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 5

Tokens: 12494
Latency: 27061 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 6

Tokens: 13068
Latency: 30423 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 7

Tokens: 13214
Latency: 29741 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 8

Tokens: 12086
Latency: 29502 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 9

Tokens: 13599
Latency: 34156 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |

### Run 10

Tokens: 15250
Latency: 46578 ms
Source hash after: bd771e1d75ef3d9c5ba11f557f6cf3e3efd9093ad6db0a2247c4acc0e097a250

| Finding | Status | Attempts | Failed attempts |
| --- | --- | --- | --- |
| GET /documents/{id} | Verified and Hardened | 1 | - |
| PUT /documents/{id} | Verified and Hardened | 1 | - |
