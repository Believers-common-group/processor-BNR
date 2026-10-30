# GSC-001 R0.5 — Local pending evidence custody

Extends canonical [processor-BNR PR #4](https://github.com/Believers-common-group/processor-BNR/pull/4), retaining its detached hash-linked receipt reference. `PendingOutbox` is a Linux-only, single-writer staging component: validates source evidence bytes, binds the candidate, checks duplicate identities and receipt chain, appends one local JSONL record, flushes to disk with `fsync`, and verifies the local outbox on read. It rejects symlink files and partial/corrupted records.

Every record remains `PENDING_EXTERNAL_CUSTODY`; **no RiverOS admission, no independently signed external ACK, no persistent third-party witness and no Warden grant**. The outbox never turns local disk persistence into legal or organisational evidence custody.

This is an **unsent outbox**, not a background dispatcher. An authorised external evidence service must later implement idempotent delivery, independent validation of exact evidence bytes, signed receiver acknowledgement, journaling and reconciliation before any `RIVEROS_ADMITTED` status can exist. Never infer admitted from local `fsync` success.

Platform limits: uses Linux `flock` and local filesystem trust. A privileged administrator can replace the whole file; this is not append-only object storage, signed custody or external anchoring. No automatic reconciliation or repair.

Run `go test ./pkg/gsc001 -v`. Keep in draft. Existing Go linter/toolchain issues are separate release blockers.
