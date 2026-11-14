// Package demo provides a loopback-only TLS fixture with ephemeral in-memory keys.
package demo

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/a1a23linux/qkey-tls-reporter/internal/evidence"
	"github.com/a1a23linux/qkey-tls-reporter/internal/probe"
)

type Fixture struct {
	Target         string
	Roots          *x509.CertPool
	CertificatePEM []byte
	classical      atomic.Bool
	listener       net.Listener
}

func NewFixture() (*Fixture, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	cert := &x509.Certificate{SerialNumber: serial, DNSNames: []string{"demo.test"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, cert, cert, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(parsed)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	f := &Fixture{Target: listener.Addr().String(), Roots: roots, CertificatePEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
	config := &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13}
	config.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		c := config.Clone()
		c.GetConfigForClient = nil
		c.CurvePreferences = []tls.CurveID{tls.X25519MLKEM768}
		if f.classical.Load() {
			c.CurvePreferences = []tls.CurveID{tls.X25519}
		}
		return c, nil
	}
	f.listener = tls.NewListener(listener, config)
	go func() {
		for {
			conn, err := f.listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
				_ = conn.(*tls.Conn).Handshake()
			}()
		}
	}()
	return f, nil
}

func (f *Fixture) SetClassical(value bool) { f.classical.Store(value) }
func (f *Fixture) Close() error            { return f.listener.Close() }

// Run writes four real loopback handshake bundles. Expected negative cases are
// successes for the demonstration, but remain failures in the individual bundles.
func Run(out, version string) error {
	if err := os.Mkdir(out, 0o700); err != nil {
		return err
	}
	f, err := NewFixture()
	if err != nil {
		return err
	}
	defer f.Close()
	var baseline probe.Result
	cases := []struct {
		name, policy, serverName, status, category string
		classical                                  bool
	}{
		{"01-hybrid", probe.RequireHybrid, "demo.test", "pass", "policy_match", false},
		{"02-classical-regression", probe.RequireHybrid, "demo.test", "fail", "policy_mismatch", true},
		{"03-classical-allowed", probe.AllowClassical, "demo.test", "pass", "policy_match", true},
		{"04-wrong-hostname", probe.RequireHybrid, "wrong.test", "fail", "certificate_error", false},
	}
	for i, c := range cases {
		f.SetClassical(c.classical)
		r, err := probe.Run(context.Background(), probe.Options{Target: f.Target, ServerName: c.serverName, Policy: c.policy, Timeout: 5 * time.Second, RootCAs: f.Roots, TrustID: "ephemeral-demo-certificate"})
		if err != nil {
			return err
		}
		if r.Status != c.status || r.Category != c.category {
			return fmt.Errorf("demo %s: unexpected result %+v", c.name, r)
		}
		if i == 0 {
			baseline = r
		}
		if i == 1 {
			comparison := probe.Compare(baseline, r)
			r.Baseline = &comparison
		}
		recorder, err := evidence.NewRecorder(filepath.Join(out, c.name), "synthetic-loopback-demo", version)
		if err != nil {
			return err
		}
		if err = recorder.Record(probe.Outcome(r)); err != nil {
			return err
		}
		if _, err = recorder.Finish(map[string]string{"go_version": runtime.Version(), "fixture": "loopback only; keys generated in memory; expected negative cases remain failures"}); err != nil {
			return err
		}
	}
	return nil
}
