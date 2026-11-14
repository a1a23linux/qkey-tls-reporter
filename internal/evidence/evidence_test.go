package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRecordAndFinish(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "run-1")
	r, err := NewRecorder(dir, "lab1-selftest", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Record(Outcome{Lab: "tls", Scenario: "a-b", Subject: "s", Expected: "x", Observed: "x", Pass: true}); err != nil {
		t.Fatal(err)
	}
	if err := r.Record(Outcome{Lab: "tls", Scenario: "a-b", Subject: "s"}); err == nil {
		t.Fatal("duplicate accepted")
	}
	if err := r.Record(Outcome{Lab: "tls", Scenario: "../x", Subject: "s"}); err == nil {
		t.Fatal("path traversal id accepted")
	}
	m, err := r.Finish(map[string]string{"k": "v"})
	if err != nil {
		t.Fatal(err)
	}
	if m.Total != 1 || m.Passed != 1 {
		t.Fatalf("totals: %+v", m)
	}
	var obs Observation
	data, err := os.ReadFile(filepath.Join(dir, "observations", "tls.a-b.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &obs); err != nil {
		t.Fatal(err)
	}
	art, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(obs.Evidence[0].URI)))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(art)
	if hex.EncodeToString(sum[:]) != obs.Evidence[0].SHA256 {
		t.Fatal("artifact hash mismatch")
	}
	sums, err := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"manifest.json", "REPORT.md", "artifacts/tls.a-b.json", "observations/tls.a-b.json"} {
		if !strings.Contains(string(sums), "  "+want+"\n") {
			t.Fatalf("SHA256SUMS missing %s", want)
		}
	}
	if _, err := NewRecorder(dir, "a", "b"); err == nil {
		t.Fatal("existing directory reused")
	}
}
