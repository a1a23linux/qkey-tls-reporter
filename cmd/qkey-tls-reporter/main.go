// Command qkey-tls-reporter records a single verified TLS 1.3 connection.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/a1a23linux/qkey-tls-reporter/internal/demo"
	"github.com/a1a23linux/qkey-tls-reporter/internal/evidence"
	"github.com/a1a23linux/qkey-tls-reporter/internal/probe"
)

var version = "0.1.0-alpha.1"

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("qkey-tls-reporter", flag.ContinueOnError)
	flags.SetOutput(stderr)
	target := flags.String("target", "", "authorized staging host:port; no URL or HTTP request")
	name := flags.String("servername", "", "certificate hostname / SNI; defaults to target host")
	policy := flags.String("policy", probe.RequireHybrid, "require-hybrid or allow-classical")
	out := flags.String("out", "", "new evidence directory; existing directories are never overwritten")
	ca := flags.String("ca-file", "", "additional trusted CA certificates in PEM format")
	baselineFile := flags.String("baseline", "", "previous artifacts/tls.endpoint.json for matching target, name, trust input and policy")
	timeout := flags.Duration("timeout", 10*time.Second, "connection and handshake timeout, maximum 1m")
	demoFlag := flags.Bool("demo", false, "run four ephemeral loopback demo cases; no outside endpoints")
	showVersion := flags.Bool("version", false, "print tool and Go versions")
	if err := flags.Parse(args); err != nil {
		if err == flag.ErrHelp {
			return 0
		}
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintln(stderr, "unexpected positional arguments")
		return 2
	}
	if *showVersion {
		fmt.Fprintln(stdout, evidence.ToolName, version, runtime.Version())
		return 0
	}
	if *out == "" {
		*out = filepath.Join("results", time.Now().UTC().Format("20060102T150405.000000000Z"))
	}
	if *demoFlag {
		if *target != "" || *ca != "" || *baselineFile != "" || *name != "" {
			fmt.Fprintln(stderr, "demo cannot be combined with target, servername, ca-file or baseline")
			return 2
		}
		if err := os.MkdirAll(filepath.Dir(*out), 0o700); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		if err := demo.Run(*out, version); err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		fmt.Fprintln(stdout, "Demo matched all four expected outcomes. Negative cases remain failures in their evidence bundles.")
		fmt.Fprintln(stdout, "Evidence:", *out)
		return 0
	}
	o := probe.Options{Target: *target, ServerName: *name, Policy: *policy, Timeout: *timeout}
	if *ca != "" {
		data, err := os.ReadFile(*ca)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		roots, err := x509.SystemCertPool()
		if err != nil {
			roots = x509.NewCertPool()
		}
		if !roots.AppendCertsFromPEM(data) {
			fmt.Fprintln(stderr, "ca-file contains no parseable certificates")
			return 2
		}
		o.RootCAs = roots
		sum := sha256.Sum256(data)
		o.TrustID = "system+sha256:" + hex.EncodeToString(sum[:])
	}
	var err error
	o, err = probe.Normalize(o)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	var before *probe.Result
	if *baselineFile != "" {
		r, err := probe.LoadBaseline(*baselineFile, o)
		if err != nil {
			fmt.Fprintln(stderr, err)
			return 2
		}
		before = &r
	}
	recorder, err := evidence.NewRecorder(*out, "tls-endpoint-check", version)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	r, err := probe.Run(context.Background(), o)
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if before != nil {
		comparison := probe.Compare(*before, r)
		r.Baseline = &comparison
	}
	if err = recorder.Record(probe.Outcome(r)); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	if _, err = recorder.Finish(map[string]string{"go_version": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH}); err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}
	fmt.Fprintf(stdout, "%s (%s): TLS=%s group=%s certificate=%s\nEvidence: %s\n", r.Status, r.Category, r.TLSVersion, r.Group, r.CertificateVerification, recorder.Dir())
	if r.Baseline != nil {
		for _, change := range r.Baseline.Changes {
			fmt.Fprintln(stdout, "CHANGE:", change)
		}
	}
	if r.Status == "pass" {
		return 0
	}
	if r.Status == "fail" {
		return 1
	}
	return 2
}
