# GSC-001 R0.2 — BNR processor evidence candidates
Change Envelope `GEN-CHG-20261028-GSC001`; parent governance draft [genesis-stack PR #80](https://github.com/Believers-common-group/genesis-stack/pull/80).

The `receipt.go` reference produces a detached SHA-256-linked receipt chain and detects alteration, broken linkage and duplicate event IDs. `admission.go` verifies candidate source bytes against the supplied SHA-256 before producing a receipt marked **EVIDENCE_CANDIDATE_PENDING_RIVEROS**. This check cannot label evidence independently verified and cannot establish causality or grant authority.

Run `go test ./pkg/gsc001 -v` under the repository-pinned Go toolchain. Scoped GitHub CI runs the same package tests.

**No durable RiverOS writer, external timestamp, institutional attestation, signed trusted identity, or real persistence is implemented.** Existing repository-wide Go linter/toolchain CI problems remain separate and unresolved.
