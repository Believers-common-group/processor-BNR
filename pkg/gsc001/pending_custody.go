// Package gsc001 provides a LOCAL staging evidence outbox. Not RiverOS.
package gsc001

import (
  "bytes"
  "crypto/sha256"
  "encoding/hex"
  "encoding/json"
  "errors"
  "fmt"
  "io"
  "os"
  "path/filepath"
  "syscall"
)

const PendingSchema = "genesis.gsc001.pending-custody/v1"
const pendingState = "PENDING_EXTERNAL_CUSTODY"

type PendingRecord struct {
  Schema string `json:"schema"`
  CandidateSHA256 string `json:"candidate_sha256"`
  Receipt Receipt `json:"receipt"`
  State string `json:"state"`
  EvidencePersistence bool `json:"evidence_persisted_externally"`
  RiverOSAdmitted bool `json:"riveros_admitted"`
  GrantsAuthority bool `json:"grants_authority"`
}

// VerifyPending checks all content hashes, duplicates, chain links, and states.
// The caller must provide bytes from a trusted file; a replaced file is not
// independently detectable without an external witness.
func VerifyPending(data []byte) ([]PendingRecord, error) {
  if len(data)==0 { return []PendingRecord{},nil }
  if data[len(data)-1]!='\n' {return nil,errors.New("partial trailing record: hold for recovery")}
  lines:=bytes.Split(data[:len(data)-1],[]byte{'\n'})
  records:=make([]PendingRecord,0,len(lines))
  receipts:=make([]Receipt,0,len(lines))
  seen:=map[string]bool{}
  for _,line:=range lines {
    if len(line)==0 || len(line)>65536 {return nil,errors.New("empty or oversized record")}
    var r PendingRecord
    decoder:=json.NewDecoder(bytes.NewReader(line))
    decoder.DisallowUnknownFields()
    if err:=decoder.Decode(&r);err!=nil{return nil,fmt.Errorf("invalid custody record: %w",err)}
    if err:=decoder.Decode(new(interface{}));err!=io.EOF{return nil,errors.New("trailing record content")}
    if r.Schema!=PendingSchema || r.State!=pendingState || r.EvidencePersistence || r.RiverOSAdmitted || r.GrantsAuthority {
      return nil,errors.New("invalid custody claims")
    }
    if len(r.CandidateSHA256)!=64 {return nil,errors.New("bad candidate hash")}
    if _,err:=hex.DecodeString(r.CandidateSHA256);err!=nil{return nil,err}
    if seen[r.Receipt.EventID] {return nil,errors.New("duplicate custody event")}
    seen[r.Receipt.EventID]=true
    receipts=append(receipts,r.Receipt)
    records=append(records,r)
  }
  if err:=VerifyChain(receipts);err!=nil{return nil,err}
  return records,nil
}

func lockLocal(path string) (*os.File,error) {
  info,err:=os.Lstat(path)
  if err==nil {
    if !info.Mode().IsRegular() {return nil,errors.New("custody path is not a regular file")}
    if info.Mode()&os.ModeSymlink!=0 {return nil,errors.New("symlink not allowed")}
  } else if !os.IsNotExist(err) {return nil,err}
  f,err:=os.OpenFile(path,os.O_RDWR|os.O_CREATE|os.O_APPEND,0600)
  if err!=nil{return nil,err}
  // Linux staging deployment only: reject simultaneous writers.
  if err=syscall.Flock(int(f.Fd()),syscall.LOCK_EX|syscall.LOCK_NB);err!=nil {
    f.Close();return nil,errors.New("exclusive custody-writer lock unavailable")
  }
  return f,nil
}

func unlockLocal(f *os.File) {
  syscall.Flock(int(f.Fd()),syscall.LOCK_UN)
  f.Close()
}

type PendingOutbox struct { Path string }

func (o PendingOutbox) Verify() (int,error) {
  f,err:=lockLocal(o.Path);if err!=nil{return 0,err}
  defer unlockLocal(f)
  data,err:=io.ReadAll(io.LimitReader(f,10*1024*1024+1))
  if err!=nil{return 0,err}
  if len(data)>10*1024*1024{return 0,errors.New("outbox exceeds size limit")}
  records,err:=VerifyPending(data)
  return len(records),err
}

// Append performs byte-level input validation and writes one fsynced local
// candidate. It cannot receive independent custody acknowledgements or change
// the record from PENDING, and it never executes a repair.
func (o PendingOutbox) Append(candidate EvidenceCandidate, evidenceBytes []byte) (PendingRecord,error) {
  f,err:=lockLocal(o.Path);if err!=nil{return PendingRecord{},err}
  defer unlockLocal(f)
  data,err:=io.ReadAll(io.LimitReader(f,10*1024*1024+1))
  if err!=nil{return PendingRecord{},err}
  if len(data)>10*1024*1024{return PendingRecord{},errors.New("outbox size limit")}
  previous,err:=VerifyPending(data)
  if err!=nil{return PendingRecord{},err}
  prior:=Genesis
  for _,entry:=range previous {
    if entry.Receipt.EventID==candidate.EventID{return PendingRecord{},errors.New("duplicate or conflicting custody event")}
    prior=entry.Receipt.Hash
  }
  result,err:=CheckCandidate(candidate,evidenceBytes,prior)
  if err!=nil{return PendingRecord{},err}
  if result.Persisted || result.RiverOSAdmitted || result.GrantsAuthority {return PendingRecord{},errors.New("unexpected evidence authority")}
  b,err:=json.Marshal(candidate);if err!=nil{return PendingRecord{},err}
  sum:=sha256.Sum256(b)
  rec:=PendingRecord{Schema:PendingSchema,CandidateSHA256:hex.EncodeToString(sum[:]),
    Receipt:result.Receipt,State:pendingState,
    EvidencePersistence:false,RiverOSAdmitted:false,GrantsAuthority:false}
  line,err:=json.Marshal(rec);if err!=nil{return PendingRecord{},err}
  before,err:=f.Seek(0,io.SeekEnd);if err!=nil{return PendingRecord{},err}
  line=append(line,'\n')
  n,err:=f.Write(line)
  if err!=nil || n!=len(line) {
    _=f.Truncate(before);_ =f.Sync()
    return PendingRecord{},errors.New("failed to append complete custody record")
  }
  if err:=f.Sync();err!=nil{return PendingRecord{},err}
  return rec,nil
}

// FileStatus explicitly distinguishes local pending evidence from independent custody.
func (o PendingOutbox) FileStatus() (map[string]interface{},error) {
  n,err:=o.Verify()
  if err!=nil{return nil,err}
  return map[string]interface{}{
    "records":n,"state":pendingState,"riveros_writer":"NOT_PROVISIONED",
    "riveros_acknowledgements_verified":0,
    "independent_timestamp":"NOT_ESTABLISHED","external_anchor":"NOT_ESTABLISHED",
    "execution_authority":false,
    "path_basename":filepath.Base(o.Path),
  },nil
}
