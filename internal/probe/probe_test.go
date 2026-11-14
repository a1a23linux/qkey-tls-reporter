package probe_test

import (
	"context"
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/a1a23linux/qkey-tls-reporter/internal/demo"
	"github.com/a1a23linux/qkey-tls-reporter/internal/evidence"
	"github.com/a1a23linux/qkey-tls-reporter/internal/probe"
)

func TestRealTLSOutcomes(t *testing.T) {
	f, err := demo.NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, tc := range []struct {
		name, policy, hostname, status, category string
		classical, untrusted                     bool
	}{
		{"hybrid", probe.RequireHybrid, "demo.test", "pass", "policy_match", false, false},
		{"classical-rejected-by-policy", probe.RequireHybrid, "demo.test", "fail", "policy_mismatch", true, false},
		{"classical-explicitly-allowed", probe.AllowClassical, "demo.test", "pass", "policy_match", true, false},
		{"wrong-hostname", probe.RequireHybrid, "wrong.test", "fail", "certificate_error", false, false},
		{"untrusted-cert", probe.RequireHybrid, "demo.test", "fail", "certificate_error", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f.SetClassical(tc.classical)
			roots := f.Roots
			if tc.untrusted {
				roots = x509.NewCertPool()
			}
			r, err := probe.Run(context.Background(), probe.Options{Target: f.Target, ServerName: tc.hostname, Policy: tc.policy, Timeout: time.Second, RootCAs: roots})
			if err != nil {
				t.Fatal(err)
			}
			if r.Status != tc.status || r.Category != tc.category {
				t.Fatalf("unexpected result %+v", r)
			}
			if r.Status == "pass" && r.CertificateVerification != "passed" {
				t.Fatal("success without verified certificate")
			}
			if tc.name == "hybrid" && r.Group != "X25519MLKEM768" {
				t.Fatalf("wrong hybrid group: %s", r.Group)
			}
			if tc.classical && r.Group != "X25519" {
				t.Fatalf("wrong classical group: %s", r.Group)
			}
		})
	}
}

func TestNetworkFailureAndTimeoutAreInconclusive(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := l.Addr().String()
	l.Close()
	r, err := probe.Run(context.Background(), probe.Options{Target: target, Timeout: time.Second})
	if err != nil || r.Status != "inconclusive" || r.Category != "network_error" {
		t.Fatalf("refused connection mislabeled: %+v %v", r, err)
	}
	l, err = net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		c, e := l.Accept()
		if e == nil {
			accepted <- c
		}
	}()
	r, err = probe.Run(context.Background(), probe.Options{Target: l.Addr().String(), Timeout: 30 * time.Millisecond})
	if err != nil || r.Status != "inconclusive" || r.Category != "network_error" {
		t.Fatalf("timeout mislabeled: %+v %v", r, err)
	}
	select {
	case c := <-accepted:
		c.Close()
	case <-time.After(time.Second):
		t.Fatal("fixture did not accept")
	}
}

func TestBaselineContextAndDifferences(t *testing.T) {
	before := probe.Result{Target: "example.test:443", ServerName: "example.test", Policy: probe.RequireHybrid, TrustID: "system", Status: "pass", TLSVersion: "TLS 1.3", Group: "X25519MLKEM768", CertificateVerification: "passed"}
	dir := filepath.Join(t.TempDir(), "baseline")
	recorder, err := evidence.NewRecorder(dir, "test", "test")
	if err != nil {
		t.Fatal(err)
	}
	if err = recorder.Record(probe.Outcome(before)); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "artifacts/tls.endpoint.json")
	o := probe.Options{Target: before.Target, ServerName: before.ServerName, Policy: before.Policy, TrustID: "system"}
	if _, err = probe.LoadBaseline(path, o); err != nil {
		t.Fatal(err)
	}
	o.ServerName = "other.test"
	if _, err = probe.LoadBaseline(path, o); err == nil {
		t.Fatal("cross-host baseline accepted")
	}
	o.ServerName = before.ServerName
	o.TrustID = "different"
	if _, err = probe.LoadBaseline(path, o); err == nil {
		t.Fatal("different trust input accepted")
	}
	after := before
	after.Group = "X25519"
	after.Status = "fail"
	c := probe.Compare(before, after)
	if !c.Changed || len(c.Changes) != 2 {
		t.Fatalf("comparison %+v", c)
	}
	if probe.Compare(before, before).Changed {
		t.Fatal("identical baseline differs")
	}
	if err = os.WriteFile(path, []byte(`{"details":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err = probe.LoadBaseline(path, probe.Options{}); err == nil {
		t.Fatal("incomplete baseline accepted")
	}
}

func TestInvalidOptions(t *testing.T) {
	for _, o := range []probe.Options{{Target: "https://example.test", Timeout: time.Second}, {Target: "https://example.test:443", Timeout: time.Second}, {Target: "example.test", Timeout: time.Second}, {Target: "example.test:https", Timeout: time.Second}, {Target: "example.test:0", Timeout: time.Second}, {Target: "example.test:65536", Timeout: time.Second}, {Target: "example.test:443", Policy: "anything", Timeout: time.Second}, {Target: "example.test:443", Timeout: 0}, {Target: "example.test:443", Timeout: 2 * time.Minute}} {
		if _, err := probe.Normalize(o); err == nil {
			t.Fatalf("accepted invalid options %+v", o)
		}
	}
}
