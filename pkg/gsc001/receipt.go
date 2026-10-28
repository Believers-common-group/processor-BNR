// Package gsc001 provides a no-network, no-storage, tamper-evident receipt reference.
// This is not an actual RiverOS writer, admission authority, or a signing service.
package gsc001

import (
    "crypto/sha256"
    "encoding/hex"
    "encoding/json"
    "errors"
)

const Schema = "genesis.gsc001.evidence-receipt/v1"
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

type Receipt struct {
    Schema string `json:"schema"`
    EventID string `json:"event_id"`
    ChangeID string `json:"change_id"`
    SourceRef string `json:"source_ref"`
    SourceRevision string `json:"source_revision"`
    EvidenceRef string `json:"evidence_ref"`
    Outcome string `json:"outcome"`
    PreviousHash string `json:"previous_hash"`
    Hash string `json:"hash"`
}

func makeHash(r Receipt) (string,error) {
    r.Hash = ""
    raw,err := json.Marshal(r)
    if err != nil {return "",err}
    sum := sha256.Sum256(raw)
    return hex.EncodeToString(sum[:]),nil
}

func validContent(r Receipt) bool {
    return r.Schema==Schema && r.EventID!="" && r.ChangeID!="" && r.SourceRef!="" &&
        r.SourceRevision!="" && r.EvidenceRef!="" && (r.Outcome=="OBSERVED" || r.Outcome=="HELD" ||
        r.Outcome=="DENIED" || r.Outcome=="VERIFIED" || r.Outcome=="CONTROL_BREACH")
}

// Issue constructs a detached receipt. It does not write to a durable ledger.
func Issue(input Receipt, previousHash string) (Receipt,error) {
    if !validContent(input) {return Receipt{},errors.New("invalid receipt input")}
    if len(previousHash)!=64 {return Receipt{},errors.New("invalid previous hash")}
    if _,err := hex.DecodeString(previousHash); err!=nil {return Receipt{},err}
    input.PreviousHash=previousHash
    input.Hash=""
    h,err:=makeHash(input)
    if err!=nil {return Receipt{},err}
    input.Hash=h
    return input,nil
}

// VerifyChain verifies order, content integrity, and identifier uniqueness.
// A matching local hash is NOT an external timestamp or institutional attestation.
func VerifyChain(receipts []Receipt) error {
    prior:=Genesis
    eventIDs:=map[string]bool{}
    for _,r:=range receipts {
        if !validContent(r) || eventIDs[r.EventID] {return errors.New("invalid or repeated receipt")}
        if r.PreviousHash!=prior {return errors.New("broken receipt link")}
        h,err:=makeHash(r)
        if err!=nil || h!=r.Hash {return errors.New("receipt hash mismatch")}
        eventIDs[r.EventID]=true
        prior=r.Hash
    }
    return nil
}
