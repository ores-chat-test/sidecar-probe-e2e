# sidecar-probe-e2e

Status: **contract-only**. This suite specifies sidecar readiness, liveness, provider health, backpressure, and degraded-mode behavior.

This repository is an executable acceptance-suite boundary, not evidence that the corresponding product capability is complete. The suite must target both `ores-chat` and the isolated `ores-chat-test` fixture. Promotion to `live` requires hosted execution, deterministic assertions, and redacted retained evidence.

The machine-readable plan is in `suite.json` and is validated by the organization policy action pinned to an immutable commit. Public, customer, administrator, and internal-service identities are never interchangeable.
