# GSC-001 receipt prototype for BNR processor
Genesis Change Envelope: GEN-CHG-20261028-GSC001; parent draft genesis-stack PR #80.

The Go receipt library creates and verifies detached hash-linked receipts for event provenance and auditability. It does not write to RiverOS, sign evidence, issue an authority grant, or perform an external timestamp. It cannot prove that an observation is true; it only establishes whether the serialized local receipt chain has changed. Receipts may be used as candidates for the *future* RiverOS evidence adapter, contingent on Warden approval and verified identity. No independently available repository named `Believers-common-group/RiverOS` was found.

Run `go test ./pkg/gsc001 -v` using the repository-pinned Go toolchain (go.mod requires Go 1.24). 
