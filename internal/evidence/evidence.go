// Package evidence records lab outcomes as hashed artifacts plus observation
// records that conform to the Q-Key observation JSON schema.
package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// ToolName identifies the collector in every observation.
const ToolName = "qkey-tls-reporter"

// Disclaimer is attached to every manifest and report.
var Disclaimer = []string{
	"One TLS connection from this client to the reached TLS termination point; not a full supported-group or interoperability scan.",
	"Not a certification, validation, or compliance attestation (including FIPS 140-3, CNSA 2.0, or Common Criteria).",
	"Results describe the named library versions only and require human cryptography review before external use.",
}

// Collector identifies the tool that produced an observation.
type Collector struct {
	Type    string  `json:"type"`
	Name    string  `json:"name"`
	Version *string `json:"version"`
}

// Ref points at a hashed evidence artifact.
type Ref struct {
	URI     string  `json:"uri"`
	SHA256  string  `json:"sha256"`
	Locator *string `json:"locator"`
}

// Observation mirrors schemas/observation.schema.json.
type Observation struct {
	ID           string    `json:"id"`
	AssessmentID string    `json:"assessment_id"`
	Kind         string    `json:"kind"`
	Subject      string    `json:"subject"`
	ObservedAt   string    `json:"observed_at"`
	Collector    Collector `json:"collector"`
	Evidence     []Ref     `json:"evidence"`
	ReviewStatus string    `json:"review_status"`
	Reviewer     *string   `json:"reviewer"`
	Limitations  []string  `json:"limitations"`
}

// Outcome is the result of one lab scenario.
type Outcome struct {
	Lab         string   `json:"lab"`
	Scenario    string   `json:"scenario"`
	Subject     string   `json:"subject"`
	Expected    string   `json:"expected"`
	Observed    string   `json:"observed"`
	Pass        bool     `json:"pass"`
	Standards   []string `json:"standards,omitempty"`
	Findings    []string `json:"findings,omitempty"`
	Limitations []string `json:"limitations,omitempty"`
	Details     any      `json:"details,omitempty"`
}

// Entry summarizes one recorded outcome in the manifest.
type Entry struct {
	Lab            string `json:"lab"`
	Scenario       string `json:"scenario"`
	Pass           bool   `json:"pass"`
	Expected       string `json:"expected"`
	Observed       string `json:"observed"`
	Artifact       string `json:"artifact"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	Observation    string `json:"observation"`
}

// Manifest describes a complete lab run.
type Manifest struct {
	RunID        string            `json:"run_id"`
	AssessmentID string            `json:"assessment_id"`
	StartedAt    string            `json:"started_at"`
	FinishedAt   string            `json:"finished_at"`
	Tool         Collector         `json:"tool"`
	Environment  map[string]string `json:"environment"`
	Total        int               `json:"total"`
	Passed       int               `json:"passed"`
	Failed       int               `json:"failed"`
	Results      []Entry           `json:"results"`
	Disclaimer   []string          `json:"disclaimer"`
}

var idPattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*$`)

// Recorder writes artifacts and observations beneath a run directory.
type Recorder struct {
	dir          string
	assessmentID string
	version      string
	started      time.Time
	entries      []Entry
	seen         map[string]bool
}

// NewRecorder creates the run directory layout. dir must not already exist.
func NewRecorder(dir, assessmentID, version string) (*Recorder, error) {
	if assessmentID == "" || version == "" {
		return nil, errors.New("assessment ID and tool version are required")
	}
	if err := os.MkdirAll(filepath.Dir(dir), 0o700); err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil {
		return nil, fmt.Errorf("create new output directory: %w", err)
	}
	for _, sub := range []string{"artifacts", "observations"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0o700); err != nil {
			return nil, err
		}
	}
	return &Recorder{dir: dir, assessmentID: assessmentID, version: version, started: time.Now().UTC(), seen: map[string]bool{}}, nil
}

// Dir returns the run directory.
func (r *Recorder) Dir() string { return r.dir }

func writeJSON(path string, v any) ([]byte, error) {
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return nil, err
	}
	data = append(data, '\n')
	return data, os.WriteFile(path, data, 0o600)
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// Record writes the outcome artifact and its observation record.
func (r *Recorder) Record(o Outcome) error {
	id := o.Lab + "." + o.Scenario
	if !idPattern.MatchString(id) {
		return fmt.Errorf("invalid scenario id %q", id)
	}
	if r.seen[id] {
		return fmt.Errorf("duplicate scenario id %q", id)
	}
	r.seen[id] = true
	artifact := "artifacts/" + id + ".json"
	data, err := writeJSON(filepath.Join(r.dir, filepath.FromSlash(artifact)), o)
	if err != nil {
		return err
	}
	sum := digest(data)
	version := r.version
	locator := "scenario=" + o.Scenario
	limitations := append([]string{
		"Recorded by the named client; results are scoped to the supplied endpoint, policy and collection time.",
	}, o.Limitations...)
	obs := Observation{
		ID:           "obs-" + id,
		AssessmentID: r.assessmentID,
		Kind:         "machine-observation",
		Subject:      o.Subject,
		ObservedAt:   time.Now().UTC().Format(time.RFC3339),
		Collector:    Collector{Type: "tool", Name: ToolName, Version: &version},
		Evidence:     []Ref{{URI: artifact, SHA256: sum, Locator: &locator}},
		ReviewStatus: "unreviewed",
		Limitations:  limitations,
	}
	observation := "observations/" + id + ".json"
	if _, err := writeJSON(filepath.Join(r.dir, filepath.FromSlash(observation)), obs); err != nil {
		return err
	}
	r.entries = append(r.entries, Entry{
		Lab: o.Lab, Scenario: o.Scenario, Pass: o.Pass, Expected: o.Expected, Observed: o.Observed,
		Artifact: artifact, ArtifactSHA256: sum, Observation: observation,
	})
	return nil
}

// Finish writes manifest.json, REPORT.md and SHA256SUMS.
func (r *Recorder) Finish(env map[string]string) (Manifest, error) {
	version := r.version
	m := Manifest{
		RunID:        filepath.Base(r.dir),
		AssessmentID: r.assessmentID,
		StartedAt:    r.started.Format(time.RFC3339),
		FinishedAt:   time.Now().UTC().Format(time.RFC3339),
		Tool:         Collector{Type: "tool", Name: ToolName, Version: &version},
		Environment:  env,
		Results:      r.entries,
		Disclaimer:   Disclaimer,
	}
	for _, e := range r.entries {
		m.Total++
		if e.Pass {
			m.Passed++
		} else {
			m.Failed++
		}
	}
	if _, err := writeJSON(filepath.Join(r.dir, "manifest.json"), m); err != nil {
		return m, err
	}
	if err := os.WriteFile(filepath.Join(r.dir, "REPORT.md"), []byte(report(m)), 0o600); err != nil {
		return m, err
	}
	return m, r.writeSums()
}

func (r *Recorder) writeSums() error {
	var files []string
	err := filepath.WalkDir(r.dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || d.Name() == "SHA256SUMS" {
			return nil
		}
		rel, err := filepath.Rel(r.dir, path)
		if err != nil {
			return err
		}
		files = append(files, filepath.ToSlash(rel))
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(files)
	var b strings.Builder
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(r.dir, filepath.FromSlash(f)))
		if err != nil {
			return err
		}
		fmt.Fprintf(&b, "%s  %s\n", digest(data), f)
	}
	return os.WriteFile(filepath.Join(r.dir, "SHA256SUMS"), []byte(b.String()), 0o600)
}

func cell(s string) string {
	return strings.ReplaceAll(strings.ReplaceAll(s, "|", "\\|"), "\n", " ")
}

func report(m Manifest) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Q-Key TLS Report %s\n\n", m.RunID)
	fmt.Fprintf(&b, "- Assessment: `%s`\n- Started: %s\n- Finished: %s\n", m.AssessmentID, m.StartedAt, m.FinishedAt)
	fmt.Fprintf(&b, "- Tool: %s %s\n- Result: %d/%d scenarios matched expectations\n\n", m.Tool.Name, *m.Tool.Version, m.Passed, m.Total)
	b.WriteString("## Environment\n\n")
	keys := make([]string, 0, len(m.Environment))
	for k := range m.Environment {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		fmt.Fprintf(&b, "- %s: `%s`\n", k, m.Environment[k])
	}
	b.WriteString("\n## Results\n\n| Lab | Scenario | Match | Expected | Observed |\n|---|---|---|---|---|\n")
	for _, e := range m.Results {
		status := "yes"
		if !e.Pass {
			status = "NO"
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %s | %s |\n", e.Lab, e.Scenario, status, cell(e.Expected), cell(e.Observed))
	}
	b.WriteString("\n## Limitations\n\n")
	for _, d := range m.Disclaimer {
		fmt.Fprintf(&b, "- %s\n", d)
	}
	b.WriteString("\nPer-scenario findings, standards references and limitations are in `artifacts/`. ")
	b.WriteString("Verify integrity with `sha256sum -c SHA256SUMS`.\n")
	return b.String()
}
