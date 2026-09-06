package riverevidence

import (
	"errors"
	"testing"
)

func referenceEvidence() []EvidenceRef {
	return []EvidenceRef{
		{Type: "OUTPUT_COUNT", EvidenceID: "EV-001", Digest: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", VisibilityClass: "PRIVATE"},
		{Type: "QC_RESULT", EvidenceID: "EV-002", Digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", VisibilityClass: "PRIVATE"},
		{Type: "MATERIAL_LINEAGE", EvidenceID: "EV-003", Digest: "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc", VisibilityClass: "PRIVATE", ObjectRef: "MAT-LINEAGE-8821"},
		{Type: "OPERATOR_CONFIRMATION", EvidenceID: "EV-004", Digest: "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd", VisibilityClass: "PRIVATE"},
	}
}

func referenceProvenance() Provenance {
	return Provenance{
		SchemaDigest:          "1111111111111111111111111111111111111111111111111111111111111111",
		ContractVersion:       "0.1",
		ImplementationRef:     "Believers-common-group/processor-BNR@synthetic-r0.1",
		SourceHashOrMerkleRef: "2222222222222222222222222222222222222222222222222222222222222222",
		ValidatorVersion:      "river-r0.1",
		BridgeRef:             "GB-EDGE-SCOTTS-001",
		DeviceID:              "MACHINE-SEW03-0412",
	}
}

func TestBuildBundleIsDeterministicAcrossEvidenceOrder(t *testing.T) {
	a, err := BuildBundle(BuildInput{
		BundleID: "EVB-8821", PodID: "POD-SCOTTS-20260906-000001", DecisionID: "WD-20260906-82101", Subject: "GARMENT-BATCH-8821",
		RequiredEvidence: []string{"OUTPUT_COUNT", "QC_RESULT", "MATERIAL_LINEAGE", "OPERATOR_CONFIRMATION"},
		Evidence: referenceEvidence(), Provenance: referenceProvenance(), MachineBound: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	reversed := referenceEvidence()
	for i, j := 0, len(reversed)-1; i < j; i, j = i+1, j-1 {
		reversed[i], reversed[j] = reversed[j], reversed[i]
	}
	b, err := BuildBundle(BuildInput{
		BundleID: "EVB-8821", PodID: "POD-SCOTTS-20260906-000001", DecisionID: "WD-20260906-82101", Subject: "GARMENT-BATCH-8821",
		RequiredEvidence: []string{"OPERATOR_CONFIRMATION", "MATERIAL_LINEAGE", "QC_RESULT", "OUTPUT_COUNT"},
		Evidence: reversed, Provenance: referenceProvenance(), MachineBound: true,
	})
	if err != nil {
		t.Fatal(err)
	}

	if a.BundleDigest != b.BundleDigest {
		t.Fatalf("digest changed with ordering: %s != %s", a.BundleDigest, b.BundleDigest)
	}
	if len(a.BundleDigest) != 64 {
		t.Fatalf("expected SHA-256 hex digest, got %q", a.BundleDigest)
	}
}

func TestBuildBundleRejectsMissingRequiredEvidence(t *testing.T) {
	evidence := referenceEvidence()
	evidence = evidence[:3]
	_, err := BuildBundle(BuildInput{
		BundleID: "EVB-8821", PodID: "POD-SCOTTS-20260906-000001", DecisionID: "WD-20260906-82101", Subject: "GARMENT-BATCH-8821",
		RequiredEvidence: []string{"OUTPUT_COUNT", "QC_RESULT", "MATERIAL_LINEAGE", "OPERATOR_CONFIRMATION"},
		Evidence: evidence, Provenance: referenceProvenance(), MachineBound: true,
	})
	if !errors.Is(err, ErrEvidenceIncomplete) {
		t.Fatalf("expected ErrEvidenceIncomplete, got %v", err)
	}
}

func TestMachineBoundBundleRequiresBridgeAndDeviceProvenance(t *testing.T) {
	provenance := referenceProvenance()
	provenance.BridgeRef = ""
	_, err := BuildBundle(BuildInput{
		BundleID: "EVB-8821", PodID: "POD-SCOTTS-20260906-000001", DecisionID: "WD-20260906-82101", Subject: "GARMENT-BATCH-8821",
		RequiredEvidence: []string{"OUTPUT_COUNT", "QC_RESULT", "MATERIAL_LINEAGE", "OPERATOR_CONFIRMATION"},
		Evidence: referenceEvidence(), Provenance: provenance, MachineBound: true,
	})
	if !errors.Is(err, ErrBridgeProvenanceMissing) {
		t.Fatalf("expected ErrBridgeProvenanceMissing, got %v", err)
	}
}

func TestVerifyBundleDetectsEvidenceTampering(t *testing.T) {
	bundle, err := BuildBundle(BuildInput{
		BundleID: "EVB-8821", PodID: "POD-SCOTTS-20260906-000001", DecisionID: "WD-20260906-82101", Subject: "GARMENT-BATCH-8821",
		RequiredEvidence: []string{"OUTPUT_COUNT", "QC_RESULT", "MATERIAL_LINEAGE", "OPERATOR_CONFIRMATION"},
		Evidence: referenceEvidence(), Provenance: referenceProvenance(), MachineBound: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	bundle.Evidence[0].Digest = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
	if err := VerifyBundle(bundle); !errors.Is(err, ErrDigestMismatch) {
		t.Fatalf("expected ErrDigestMismatch, got %v", err)
	}
}

func TestMaterialLineageUsesReferenceRatherThanRawPrivatePayload(t *testing.T) {
	bundle, err := BuildBundle(BuildInput{
		BundleID: "EVB-8821", PodID: "POD-SCOTTS-20260906-000001", DecisionID: "WD-20260906-82101", Subject: "GARMENT-BATCH-8821",
		RequiredEvidence: []string{"OUTPUT_COUNT", "QC_RESULT", "MATERIAL_LINEAGE", "OPERATOR_CONFIRMATION"},
		Evidence: referenceEvidence(), Provenance: referenceProvenance(), MachineBound: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, item := range bundle.Evidence {
		if item.Type == "MATERIAL_LINEAGE" && item.ObjectRef != "MAT-LINEAGE-8821" {
			t.Fatalf("expected material-lineage object reference, got %q", item.ObjectRef)
		}
	}
}
