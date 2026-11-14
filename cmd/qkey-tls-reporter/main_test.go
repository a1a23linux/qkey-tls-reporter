package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/a1a23linux/qkey-tls-reporter/internal/demo"
)

func TestCLIEndpointExitCodesAndOutputPreservation(t *testing.T) {
	f, err := demo.NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	root := t.TempDir()
	ca := filepath.Join(root, "test-ca.pem")
	if err = os.WriteFile(ca, f.CertificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, stderr bytes.Buffer
	dir := filepath.Join(root, "healthy")
	args := []string{"-target", f.Target, "-servername", "demo.test", "-ca-file", ca, "-out", dir}
	if code := run(args, &out, &stderr); code != 0 {
		t.Fatalf("healthy exit %d: %s", code, stderr.String())
	}
	manifest, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if code := run(args, &out, &stderr); code != 2 {
		t.Fatalf("existing output exit %d", code)
	}
	unchanged, _ := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if !bytes.Equal(manifest, unchanged) {
		t.Fatal("existing output changed")
	}
	f.SetClassical(true)
	args = []string{"-target", f.Target, "-servername", "demo.test", "-ca-file", ca, "-out", filepath.Join(root, "changed"), "-baseline", filepath.Join(dir, "artifacts/tls.endpoint.json")}
	if code := run(args, &out, &stderr); code != 1 {
		t.Fatalf("policy failure exit %d: %s", code, stderr.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("CHANGE: group:")) {
		t.Fatal("missing baseline change output")
	}
}

func TestCLIDemoAndBadInput(t *testing.T) {
	var out, stderr bytes.Buffer
	dir := filepath.Join(t.TempDir(), "demo")
	if code := run([]string{"-demo", "-out", dir}, &out, &stderr); code != 0 {
		t.Fatalf("demo exit %d: %s", code, stderr.String())
	}
	for _, name := range []string{"01-hybrid", "02-classical-regression", "03-classical-allowed", "04-wrong-hostname"} {
		if _, err := os.Stat(filepath.Join(dir, name, "SHA256SUMS")); err != nil {
			t.Fatal(err)
		}
	}
	for _, args := range [][]string{{}, {"-demo", "-target", "example.test:443"}, {"-target", "https://example.test"}, {"unexpected"}} {
		invalidOutput := filepath.Join(t.TempDir(), "must-not-exist")
		args = append(args, "-out", invalidOutput)
		if code := run(args, &out, &stderr); code != 2 {
			t.Fatalf("invalid args %v exit %d", args, code)
		}
		if _, err := os.Stat(invalidOutput); !os.IsNotExist(err) {
			t.Fatalf("invalid arguments created output: %v", err)
		}
	}
}
