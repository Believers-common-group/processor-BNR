package gsc001
import (
    "crypto/sha256"
    "encoding/hex"
    "testing"
)
func fixture(b []byte) EvidenceCandidate {
   h:=sha256.Sum256(b)
   return EvidenceCandidate{Schema:EvidenceCandidateSchema,EventID:"evt-R02",
      ChangeID:"GEN-CHG-20261028-GSC001",SourceRef:"Alpha-observer",
      SourceRevision:"abc123", EvidenceRef:"sha256:source-file",SHA256:hex.EncodeToString(h[:]),Outcome:"OBSERVED"}
}
func TestCandidateAdmissionPending(t *testing.T) {
    b:=[]byte("synthetic test observation")
    r,err:=CheckCandidate(fixture(b),b,Genesis)
    if err!=nil {t.Fatal(err)}
    if r.Persisted||r.RiverOSAdmitted||r.GrantsAuthority {t.Fatal("false admission claim")}
    if r.Receipt.Hash=="" {t.Fatal("missing receipt digest")}
    if err:=VerifyChain([]Receipt{r.Receipt});err!=nil {t.Fatal(err)}
}
func TestCandidateTamperRejected(t *testing.T) {
    b:=[]byte("original")
    if _,err:=CheckCandidate(fixture(b),[]byte("modified"),Genesis);err==nil {t.Fatal("tamper accepted")}
}
func TestCandidateMissingBytes(t *testing.T) {
    if _,err:=CheckCandidate(fixture([]byte("hello")),nil,Genesis);err==nil {t.Fatal("empty evidence accepted")}
}
func TestCandidateUnsupportedVerified(t *testing.T) {
    b:=[]byte("original")
    e:=fixture(b)
    e.Outcome="VERIFIED"
    if _,err:=CheckCandidate(e,b,Genesis);err==nil {t.Fatal("unapproved verified claim accepted")}
}
func TestCandidateMissingIdentity(t *testing.T) {
    b:=[]byte("original")
    e:=fixture(b)
    e.EventID=""
    if _,err:=CheckCandidate(e,b,Genesis);err==nil {t.Fatal("missing identity accepted")}
}
func TestCandidateBrokenPreviousHash(t *testing.T) {
    b:=[]byte("original")
    if _,err:=CheckCandidate(fixture(b),b,"BAD");err==nil {t.Fatal("bad predecessor accepted")}
}
func TestCandidateInvalidSchema(t *testing.T) {
    b:=[]byte("original")
    e:=fixture(b)
    e.Schema="unknown"
    if _,err:=CheckCandidate(e,b,Genesis);err==nil {t.Fatal("unknown schema accepted")}
}
