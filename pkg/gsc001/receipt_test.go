package gsc001
import "testing"
func example(id string) Receipt {
    return Receipt{Schema:Schema,EventID:id,ChangeID:"GEN-CHG-20261028-GSC001",SourceRef:"Alpha-observer@genesis",SourceRevision:"abc123",EvidenceRef:"sha256:abc",Outcome:"OBSERVED"}
}
func TestReceipts(t *testing.T){
    one,err:=Issue(example("e1"),Genesis)
    if err!=nil {t.Fatal(err)}
    two,err:=Issue(example("e2"),one.Hash)
    if err!=nil {t.Fatal(err)}
    if err:=VerifyChain([]Receipt{one,two});err!=nil {t.Fatal(err)}
}
func TestTamperDetected(t *testing.T){
    one,_:=Issue(example("e1"),Genesis)
    one.Outcome="VERIFIED"
    if VerifyChain([]Receipt{one})==nil {t.Fatal("tampered record accepted")}
}
func TestBrokenLink(t *testing.T){
    one,_:=Issue(example("e1"),Genesis)
    two,_:=Issue(example("e2"),Genesis)
    if VerifyChain([]Receipt{one,two})==nil {t.Fatal("broken sequence accepted")}
}
func TestDuplicateEvent(t *testing.T){
    one,_:=Issue(example("e1"),Genesis)
    two,_:=Issue(example("e1"),one.Hash)
    if VerifyChain([]Receipt{one,two})==nil {t.Fatal("duplicate accepted")}
}
func TestMissingEvidence(t *testing.T){
    x:=example("e1");x.EvidenceRef=""
    if _,err:=Issue(x,Genesis);err==nil {t.Fatal("accepted missing evidence")}
}
func TestInvalidOutcome(t *testing.T){
    x:=example("e1");x.Outcome="PUBLIC_CAUSAL_CLAIM"
    if _,err:=Issue(x,Genesis);err==nil {t.Fatal("accepted unsupported outcome")}
}
func TestInvalidPrev(t *testing.T){
    if _,err:=Issue(example("e1"),"malformed");err==nil {t.Fatal("accepted malformed prev")}
}
func TestNoBuiltinAuthority(t *testing.T){
    one,_:=Issue(example("e1"),Genesis)
    if one.Outcome!="OBSERVED" {t.Fatal("receipt changed outcome")}
}
