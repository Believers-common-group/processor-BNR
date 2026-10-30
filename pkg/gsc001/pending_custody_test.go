package gsc001

import (
 "crypto/sha256"
 "encoding/hex"
 "os"
 "path/filepath"
 "strings"
 "testing"
)

func candidate(id string) (EvidenceCandidate,[]byte) {
 b:=[]byte("evidence:"+id)
 h:=sha256.Sum256(b)
 return EvidenceCandidate{Schema:EvidenceCandidateSchema,EventID:id,
  ChangeID:"GEN-CHG-20261028-GSC001",SourceRef:"Believers-common-group/Alpha-observer",
  SourceRevision:strings.Repeat("a",40),EvidenceRef:"github-run:"+id,
  SHA256:hex.EncodeToString(h[:]),Outcome:"OBSERVED"},b
}
func outbox(t *testing.T) PendingOutbox {
 t.Helper()
 return PendingOutbox{Path:filepath.Join(t.TempDir(),"pending.jsonl")}
}
func TestAppendAndVerify(t *testing.T) {
 o:=outbox(t);c,b:=candidate("100")
 r,err:=o.Append(c,b);if err!=nil {t.Fatal(err)}
 if r.State!=pendingState || r.RiverOSAdmitted || r.GrantsAuthority || r.EvidencePersistence {t.Fatalf("unsafe claims: %+v",r)}
 n,err:=o.Verify();if err!=nil || n!=1 {t.Fatalf("%d %v",n,err)}
 s,err:=o.FileStatus();if err!=nil || s["riveros_writer"]!="NOT_PROVISIONED" {t.Fatalf("status: %+v %v",s,err)}
}
func TestChainAcrossThreeRecords(t *testing.T) {
 o:=outbox(t)
 for _,id:=range []string{"1","2","3"} {c,b:=candidate(id);if _,err:=o.Append(c,b);err!=nil {t.Fatal(err)}}
 n,err:=o.Verify();if err!=nil || n!=3 {t.Fatalf("%d %v",n,err)}
}
func TestDuplicateRejected(t *testing.T) {
 o:=outbox(t);c,b:=candidate("1")
 if _,err:=o.Append(c,b);err!=nil {t.Fatal(err)}
 if _,err:=o.Append(c,b);err==nil {t.Fatal("duplicate was accepted")}
 n,err:=o.Verify();if err!=nil || n!=1 {t.Fatal(n,err)}
}
func TestWrongEvidenceRejected(t *testing.T) {
 o:=outbox(t);c,_:=candidate("1")
 if _,err:=o.Append(c,[]byte("wrong bytes"));err==nil {t.Fatal("hash mismatch admitted")}
}
func TestPendingCustodyTamperDetected(t *testing.T) {
 o:=outbox(t);c,b:=candidate("1")
 if _,err:=o.Append(c,b);err!=nil {t.Fatal(err)}
 data,err:=os.ReadFile(o.Path);if err!=nil {t.Fatal(err)}
 data=[]byte(strings.ReplaceAll(string(data),"OBSERVED","CONTROL_BREACH"))
 if err:=os.WriteFile(o.Path,data,0600);err!=nil {t.Fatal(err)}
 if _,err:=o.Verify();err==nil {t.Fatal("tampered record accepted")}
}
func TestTruncatedRecordRejected(t *testing.T) {
 o:=outbox(t);c,b:=candidate("1")
 if _,err:=o.Append(c,b);err!=nil {t.Fatal(err)}
 data,err:=os.ReadFile(o.Path);if err!=nil {t.Fatal(err)}
 if err:=os.WriteFile(o.Path,data[:len(data)-1],0600);err!=nil {t.Fatal(err)}
 if _,err:=o.Verify();err==nil {t.Fatal("partial log accepted")}
}
func TestExtraClaimsRejected(t *testing.T) {
 o:=outbox(t);c,b:=candidate("1")
 if _,err:=o.Append(c,b);err!=nil {t.Fatal(err)}
 data,_:=os.ReadFile(o.Path)
 modified:=strings.ReplaceAll(string(data),`"riveros_admitted":false`,`"riveros_admitted":true`)
 if err:=os.WriteFile(o.Path,[]byte(modified),0600);err!=nil {t.Fatal(err)}
 if _,err:=o.Verify();err==nil {t.Fatal("false riveros claim accepted")}
}
func TestSymlinkRejected(t *testing.T) {
 root:=t.TempDir();target:=filepath.Join(root,"actual")
 if err:=os.WriteFile(target,[]byte(""),0600);err!=nil {t.Fatal(err)}
 link:=filepath.Join(root,"link")
 if err:=os.Symlink(target,link);err!=nil {t.Skip(err)}
 o:=PendingOutbox{Path:link};c,b:=candidate("1")
 if _,err:=o.Append(c,b);err==nil {t.Fatal("symlink accepted")}
}
func TestUnsafeStateNeverAdmitted(t *testing.T) {
 o:=outbox(t);c,b:=candidate("1")
 r,err:=o.Append(c,b);if err!=nil {t.Fatal(err)}
 if r.Receipt.Outcome=="VERIFIED" || r.Receipt.Outcome=="CONTROL_BREACH" {t.Fatal("unverified evidence promotion")}
}
func TestMissingCreatesBlankOutbox(t *testing.T) {
 o:=outbox(t)
 n,err:=o.Verify();if err!=nil || n!=0 {t.Fatal(n,err)}
}
