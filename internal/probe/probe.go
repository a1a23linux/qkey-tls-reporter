// Package probe observes one verified TLS connection and evaluates a declared policy.
package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/a1a23linux/qkey-tls-reporter/internal/evidence"
)

const RequireHybrid = "require-hybrid"
const AllowClassical = "allow-classical"

// Options configures a single TLS 1.3 connection. RootCAs nil uses system trust.
type Options struct {
	Target     string
	ServerName string
	Policy     string
	Timeout    time.Duration
	RootCAs    *x509.CertPool
	// TrustID is a non-secret digest of additional CA input, or "system".
	TrustID string
}

// Result separates a failed policy from an uncompleted connection.
type Result struct {
	Target                  string      `json:"target"`
	ServerName              string      `json:"server_name"`
	Policy                  string      `json:"policy"`
	TrustID                 string      `json:"trust_id"`
	Status                  string      `json:"status"`
	Category                string      `json:"category"`
	Error                   string      `json:"error,omitempty"`
	TLSVersion              string      `json:"tls_version,omitempty"`
	Group                   string      `json:"group,omitempty"`
	GroupID                 uint16      `json:"group_id,omitempty"`
	Class                   string      `json:"key_exchange_class,omitempty"`
	CipherSuite             string      `json:"cipher_suite,omitempty"`
	CertificateVerification string      `json:"certificate_verification"`
	CertificateSHA256       string      `json:"leaf_certificate_sha256,omitempty"`
	CertificateSignature    string      `json:"leaf_certificate_signature_algorithm,omitempty"`
	DurationMS              int64       `json:"duration_ms"`
	Baseline                *Comparison `json:"baseline,omitempty"`
}

type Comparison struct {
	Changes []string `json:"changes"`
	// A difference is reported, not automatically interpreted as a security regression.
	Changed bool `json:"changed"`
}

func Normalize(o Options) (Options, error) {
	host, port, err := net.SplitHostPort(o.Target)
	if err != nil || host == "" || port == "" || strings.ContainsAny(host, "/\\\r\n\t ") {
		return o, errors.New("target must be a host:port (use [IPv6]:port for IPv6); URLs are not accepted")
	}
	if o.ServerName == "" {
		o.ServerName = host
	}
	if strings.ContainsAny(o.ServerName, "\r\n\t /\\") {
		return o, errors.New("invalid server name")
	}
	if o.Policy == "" {
		o.Policy = RequireHybrid
	}
	if o.Policy != RequireHybrid && o.Policy != AllowClassical {
		return o, errors.New("policy must be require-hybrid or allow-classical")
	}
	if o.Timeout <= 0 || o.Timeout > time.Minute {
		return o, errors.New("timeout must be greater than zero and at most one minute")
	}
	if o.TrustID == "" {
		o.TrustID = "system"
	}
	return o, nil
}

func Run(ctx context.Context, input Options) (Result, error) {
	o, err := Normalize(input)
	if err != nil {
		return Result{}, err
	}
	r := Result{Target: o.Target, ServerName: o.ServerName, Policy: o.Policy, TrustID: o.TrustID, Status: "inconclusive", CertificateVerification: "not_completed"}
	ctx, cancel := context.WithTimeout(ctx, o.Timeout)
	defer cancel()
	start := time.Now()
	d := tls.Dialer{Config: &tls.Config{
		ServerName: o.ServerName, RootCAs: o.RootCAs, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		// Offer a declared, stable set. Policy evaluates the result; it does not
		// silently turn a failed handshake into a claim of successful rejection.
		CurvePreferences: []tls.CurveID{tls.X25519MLKEM768, tls.X25519, tls.CurveP256, tls.CurveP384},
	}}
	conn, err := d.DialContext(ctx, "tcp", o.Target)
	r.DurationMS = time.Since(start).Milliseconds()
	if err != nil {
		r.Error = err.Error()
		var certErr *tls.CertificateVerificationError
		var netErr net.Error
		switch {
		case errors.As(err, &certErr):
			r.Status = "fail"
			r.Category = "certificate_error"
			r.CertificateVerification = "failed"
		case errors.As(err, &netErr), errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
			r.Category = "network_error"
		default:
			r.Category = "handshake_error"
		}
		return r, nil
	}
	defer conn.Close()
	state := conn.(*tls.Conn).ConnectionState()
	r.TLSVersion = tls.VersionName(state.Version)
	r.Group = state.CurveID.String()
	r.GroupID = uint16(state.CurveID)
	r.CipherSuite = tls.CipherSuiteName(state.CipherSuite)
	r.CertificateVerification = "passed"
	r.Class = "classical"
	if state.CurveID == tls.X25519MLKEM768 {
		r.Class = "pq-hybrid"
	}
	if len(state.PeerCertificates) > 0 {
		cert := state.PeerCertificates[0]
		sum := sha256.Sum256(cert.Raw)
		r.CertificateSHA256 = hex.EncodeToString(sum[:])
		r.CertificateSignature = cert.SignatureAlgorithm.String()
	}
	r.Status = "pass"
	r.Category = "policy_match"
	if o.Policy == RequireHybrid && r.Class != "pq-hybrid" {
		r.Status = "fail"
		r.Category = "policy_mismatch"
	}
	return r, nil
}

// LoadBaseline reads our artifact format and rejects comparisons across different
// targets, names, trust input or policies. It does not authenticate the baseline.
func LoadBaseline(path string, o Options) (Result, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Result{}, err
	}
	var artifact struct {
		Details Result `json:"details"`
	}
	if err = json.Unmarshal(data, &artifact); err != nil {
		return Result{}, err
	}
	r := artifact.Details
	if r.Target != o.Target || r.ServerName != o.ServerName || r.Policy != o.Policy || r.TrustID != o.TrustID {
		return Result{}, errors.New("baseline target, server name, trust input and policy must match this check")
	}
	if r.CertificateVerification != "passed" || r.TLSVersion == "" || r.Group == "" {
		return Result{}, errors.New("baseline must contain a completed, certificate-verified handshake")
	}
	return r, nil
}

func Compare(before, after Result) Comparison {
	c := Comparison{Changes: []string{}}
	for _, field := range []struct{ name, a, b string }{
		{"status", before.Status, after.Status}, {"tls_version", before.TLSVersion, after.TLSVersion},
		{"group", before.Group, after.Group}, {"cipher_suite", before.CipherSuite, after.CipherSuite},
		{"certificate_verification", before.CertificateVerification, after.CertificateVerification},
		{"leaf_certificate_sha256", before.CertificateSHA256, after.CertificateSHA256},
	} {
		if field.a != field.b {
			c.Changes = append(c.Changes, fmt.Sprintf("%s: %s -> %s", field.name, field.a, field.b))
		}
	}
	c.Changed = len(c.Changes) > 0
	return c
}

func Outcome(r Result) evidence.Outcome {
	observed := fmt.Sprintf("status=%s category=%s certificate=%s", r.Status, r.Category, r.CertificateVerification)
	if r.TLSVersion != "" {
		observed += fmt.Sprintf(" version=%s group=%s class=%s", r.TLSVersion, r.Group, r.Class)
	}
	if r.Error != "" {
		observed += " error=" + r.Error
	}
	findings := []string{}
	if r.Baseline != nil {
		findings = append(findings, r.Baseline.Changes...)
	}
	return evidence.Outcome{Lab: "tls", Scenario: "endpoint", Subject: r.Target, Expected: "TLS 1.3; certificate verifies; policy=" + r.Policy, Observed: observed, Pass: r.Status == "pass", Details: r, Findings: findings, Limitations: []string{
		"Only X25519MLKEM768, X25519, P-256 and P-384 are offered. One observed negotiation does not enumerate server support.",
		"A hybrid exchange does not imply a PQ certificate, whole-product quantum safety, or protection of stored data.",
		"The require-hybrid policy checks the negotiated result; application data is never sent. A failed handshake alone is inconclusive about group support.",
		"Baseline input is caller-supplied; hashes provide integrity, not independent authenticity or approval.",
	}}
}
