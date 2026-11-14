//go:build interop

package probe_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/a1a23linux/qkey-tls-reporter/internal/demo"
	"github.com/a1a23linux/qkey-tls-reporter/internal/probe"
)

func opensslBinary(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("openssl")
	if err != nil {
		t.Fatal("OpenSSL is required for make interop; normal Go tests do not require it")
	}
	output, err := exec.Command(path, "version").Output()
	if err != nil {
		t.Fatal(err)
	}
	t.Log(strings.TrimSpace(string(output)))
	return path
}

func opensslServer(t *testing.T, binary string) (string, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{SerialNumber: serial, DNSNames: []string{"demo.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	keyBytes, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "certificate.pem"), filepath.Join(dir, "ephemeral-key.pem")
	for name, data := range map[string][]byte{certPath: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), keyPath: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyBytes})} {
		if err = os.WriteFile(name, data, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	reservation, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	target := reservation.Addr().String()
	reservation.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	cmd := exec.CommandContext(ctx, binary, "s_server", "-accept", target, "-cert", certPath, "-key", keyPath, "-tls1_3", "-groups", "X25519", "-quiet")
	var log bytes.Buffer
	cmd.Stdout = &log
	cmd.Stderr = &log
	if err = cmd.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			t.Log("OpenSSL server output:", log.String())
		}
	})
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, e := net.DialTimeout("tcp", target, 50*time.Millisecond)
		if e == nil {
			conn.Close()
			return target, roots
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("OpenSSL fixture did not start listening on loopback")
	return "", nil
}

func TestGoClientToOpenSSLServer(t *testing.T) {
	target, roots := opensslServer(t, opensslBinary(t))
	for _, tc := range []struct {
		name, policy, hostname, status, category string
		untrusted                                bool
	}{
		{"classical-allowed", probe.AllowClassical, "demo.test", "pass", "policy_match", false},
		{"classical-fails-hybrid-policy", probe.RequireHybrid, "demo.test", "fail", "policy_mismatch", false},
		{"wrong-hostname", probe.AllowClassical, "wrong.test", "fail", "certificate_error", false},
		{"untrusted-certificate", probe.AllowClassical, "demo.test", "fail", "certificate_error", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			trust := roots
			if tc.untrusted {
				trust = x509.NewCertPool()
			}
			r, err := probe.Run(context.Background(), probe.Options{Target: target, ServerName: tc.hostname, Policy: tc.policy, RootCAs: trust, Timeout: 2 * time.Second})
			if err != nil {
				t.Fatal(err)
			}
			if r.Status != tc.status || r.Category != tc.category {
				t.Fatalf("unexpected result %+v", r)
			}
			if r.CertificateVerification == "passed" && (r.Group != "X25519" || r.Class != "classical" || r.TLSVersion != "TLS 1.3") {
				t.Fatalf("classical server mislabeled: %+v", r)
			}
			t.Logf("%s: status=%s category=%s group=%s", tc.name, r.Status, r.Category, r.Group)
		})
	}
}

func TestOpenSSLClientToGoServer(t *testing.T) {
	binary := opensslBinary(t)
	fixture, err := demo.NewFixture()
	if err != nil {
		t.Fatal(err)
	}
	defer fixture.Close()
	dir := t.TempDir()
	ca := filepath.Join(dir, "trusted-certificate.pem")
	if err = os.WriteFile(ca, fixture.CertificatePEM, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, hostname         string
		classical, wantSuccess bool
	}{
		{"classical-negotiation", "demo.test", true, true},
		{"wrong-hostname-rejected", "wrong.test", true, false},
		{"classical-client-rejected-by-hybrid-only-server", "demo.test", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture.SetClassical(tc.classical)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, binary, "s_client", "-connect", fixture.Target, "-servername", "demo.test", "-verify_hostname", tc.hostname, "-verify_return_error", "-CAfile", ca, "-tls1_3", "-groups", "X25519", "-brief")
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatal("OpenSSL client timed out")
			}
			text := string(output)
			if tc.wantSuccess {
				if err != nil || !strings.Contains(text, "TLSv1.3") || !strings.Contains(text, "X25519") || !strings.Contains(text, "Verification: OK") {
					t.Fatalf("unverified/incorrect successful result: %v\n%s", err, text)
				}
			} else {
				if err == nil {
					t.Fatalf("negative handshake unexpectedly succeeded: %s", text)
				}
				if tc.hostname == "wrong.test" && !strings.Contains(text, "hostname mismatch") {
					t.Fatalf("failed for wrong reason: %s", text)
				}
				if !tc.classical && !strings.Contains(strings.ToLower(text), "handshake failure") {
					t.Fatalf("failed for wrong reason: %s", text)
				}
			}
			t.Log(fmt.Sprintf("%s: success=%t", tc.name, err == nil))
		})
	}
}
