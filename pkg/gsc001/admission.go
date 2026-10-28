package gsc001

import (
    "crypto/sha256"
    "encoding/hex"
    "errors"
)

const EvidenceCandidateSchema = "genesis.gsc001.evidence-candidate/v1"

type EvidenceCandidate struct {
    Schema string `json:"schema"`
    EventID string `json:"event_id"`
    ChangeID string `json:"change_id"`
    SourceRef string `json:"source_ref"`
    SourceRevision string `json:"source_revision"`
    EvidenceRef string `json:"evidence_ref"`
    SHA256 string `json:"sha256"`
    Outcome string `json:"outcome"`
}
type AdmissionResult struct {
    State string `json:"state"`
    Receipt Receipt `json:"receipt"`
    Persisted bool `json:"persisted"`
    RiverOSAdmitted bool `json:"riveros_admitted"`
    GrantsAuthority bool `json:"grants_authority"`
}

// CheckCandidate checks actual bytes and yields a detached receipt; it never persists evidence.
func CheckCandidate(candidate EvidenceCandidate, evidenceBytes []byte, preceding string) (AdmissionResult,error) {
    if candidate.Schema!=EvidenceCandidateSchema ||
       candidate.EventID=="" || candidate.ChangeID=="" ||
       candidate.SourceRef=="" || candidate.SourceRevision=="" || candidate.EvidenceRef=="" {
        return AdmissionResult{},errors.New("invalid evidence identity")
    }
    if candidate.Outcome!="OBSERVED" && candidate.Outcome!="HELD" && candidate.Outcome!="DENIED" && candidate.Outcome!="CONTROL_BREACH" {
        return AdmissionResult{},errors.New("unsupported evidence outcome")
    }
    if len(evidenceBytes)==0 {return AdmissionResult{},errors.New("missing source bytes")}
    digest:=sha256.Sum256(evidenceBytes)
    if candidate.SHA256!=hex.EncodeToString(digest[:]) {return AdmissionResult{},errors.New("source hash mismatch")}
    receipt,err:=Issue(Receipt{
      Schema:Schema, EventID:candidate.EventID, ChangeID:candidate.ChangeID,
      SourceRef:candidate.SourceRef, SourceRevision:candidate.SourceRevision,
      EvidenceRef:candidate.EvidenceRef, Outcome:candidate.Outcome,
    },preceding)
    if err!=nil {return AdmissionResult{},err}
    return AdmissionResult{State:"EVIDENCE_CANDIDATE_PENDING_RIVEROS",
       Receipt:receipt, Persisted:false,RiverOSAdmitted:false,GrantsAuthority:false},nil
}
