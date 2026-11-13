package oracle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// A bundle is the directory that makes one deployment's Oracle its own:
//
//	manifest.json          what the bundle contains, with a hash of every file
//	behaviour-model.json   the behaviour model
//	prompts/system.txt     the analyst's instructions
//	prompts/case.txt       the frame the analyst's case file is placed in
//
// The manifest also holds the thresholds and names the analyst's local language model
// (a file in the runtime directory) and the prompt version. Changing any of them is an
// edit to the bundle, never to the gateway's code: a studio that retrains the behaviour
// model on its own data, rewrites the prompts or swaps in a privately tuned language
// model ships nothing but a new bundle, and nobody outside the gateway host sees it.
//
// The gateway only reads a bundle. Nothing in it is served by the dashboard (which serves
// embedded files only), sent to a client, or written to the log.

const (
	EngineName     = "carthago-oracle"
	BundleVersion  = 1
	ManifestFile   = "manifest.json"
	modelFile      = "behaviour-model.json"
	systemFile     = "prompts/system.txt"
	caseFile       = "prompts/case.txt"
	maxBundleFile  = 8 << 20
	promptMaxBytes = 32 << 10
)

// ErrNoBundle means the directory holds no bundle: the Oracle is off.
var ErrNoBundle = errors.New("no Oracle bundle")

type Manifest struct {
	Engine        string       `json:"engine"`
	BundleVersion int          `json:"bundle_version"`
	BundleID      string       `json:"bundle_id"`
	Behaviour     BehaviourRef `json:"behaviour_model"`
	Thresholds    Thresholds   `json:"thresholds"`
	Analyst       AnalystRef   `json:"analyst"`
}

type BehaviourRef struct {
	ID             string `json:"id"`
	File           string `json:"file"`
	SHA256         string `json:"sha256"`
	FeatureVersion int    `json:"feature_version"`
}

// Thresholds turn a score into a band. A session at or above Review is sent to the
// analyst and listed for review; Watch is shown but starts nothing.
type Thresholds struct {
	Watch  float64 `json:"watch"`
	Review float64 `json:"review"`
}

func (t Thresholds) Band(score float64) string {
	switch {
	case score >= t.Review:
		return "review"
	case score >= t.Watch:
		return "watch"
	}
	return "clear"
}

type AnalystRef struct {
	PromptVersion string  `json:"prompt_version"`
	SchemaVersion int     `json:"schema_version"`
	System        FileRef `json:"system_prompt"`
	Case          FileRef `json:"case_prompt"`
	// LocalModel is the language model the gateway runs itself. The file is looked up in
	// the runtime directory, not in the bundle.
	LocalModel LocalModelRef `json:"local_model"`
}

type FileRef struct {
	File   string `json:"file"`
	SHA256 string `json:"sha256"`
}

type LocalModelRef struct {
	ID            string `json:"id"`
	File          string `json:"file"`
	SHA256        string `json:"sha256"`
	ContextTokens int    `json:"context_tokens"`
}

// Bundle is a loaded, verified bundle.
type Bundle struct {
	Dir          string
	Manifest     Manifest
	Model        *Model
	SystemPrompt string
	CasePrompt   string
}

// Contents is what WriteBundle puts into a bundle.
type Contents struct {
	Model         []byte
	Thresholds    Thresholds
	PromptVersion string
	SchemaVersion int
	SystemPrompt  string
	CasePrompt    string
	LocalModel    LocalModelRef
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// id names a manifest by everything in it except the id itself.
func (m Manifest) id() string {
	m.BundleID = ""
	b, _ := json.Marshal(m)
	return "cb-" + sum(b)[:12]
}

// WriteBundle creates or replaces the bundle in dir. Files are private to the user the
// gateway runs as.
func WriteBundle(dir string, c Contents) (*Manifest, error) {
	if _, _, err := ParseModel(c.Model); err != nil {
		return nil, err
	}
	if c.Thresholds.Watch <= 0 || c.Thresholds.Review < c.Thresholds.Watch || c.Thresholds.Review >= 1 {
		return nil, fmt.Errorf("thresholds must satisfy 0 < watch <= review < 1, got %v", c.Thresholds)
	}
	m := Manifest{
		Engine: EngineName, BundleVersion: BundleVersion,
		Behaviour:  BehaviourRef{ID: ModelID(c.Model), File: modelFile, SHA256: sum(c.Model), FeatureVersion: FeatureVersion},
		Thresholds: c.Thresholds,
		Analyst: AnalystRef{PromptVersion: c.PromptVersion, SchemaVersion: c.SchemaVersion,
			System: FileRef{systemFile, sum([]byte(c.SystemPrompt))}, Case: FileRef{caseFile, sum([]byte(c.CasePrompt))}, LocalModel: c.LocalModel},
	}
	m.BundleID = m.id()
	if err := os.MkdirAll(filepath.Join(dir, "prompts"), 0o700); err != nil {
		return nil, err
	}
	files := map[string][]byte{modelFile: c.Model, systemFile: []byte(c.SystemPrompt), caseFile: []byte(c.CasePrompt)}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(name)), data, 0o600); err != nil {
			return nil, err
		}
	}
	return &m, writeManifest(dir, &m)
}

func writeManifest(dir string, m *Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, ManifestFile), append(b, '\n'), 0o600)
}

// Rewrite changes a bundle's manifest through edit and stores it under its new id. It is
// how a threshold, the prompt version or the local model is changed without retraining.
func Rewrite(dir string, edit func(*Manifest) error) (*Manifest, error) {
	b, err := LoadBundle(dir)
	if err != nil {
		return nil, err
	}
	m := b.Manifest
	if err := edit(&m); err != nil {
		return nil, err
	}
	for _, ref := range []*FileRef{&m.Analyst.System, &m.Analyst.Case} {
		data, err := readBundleFile(dir, ref.File, promptMaxBytes)
		if err != nil {
			return nil, err
		}
		ref.SHA256 = sum(data)
	}
	m.BundleID = m.id()
	if err := writeManifest(dir, &m); err != nil {
		return nil, err
	}
	if _, err := LoadBundle(dir); err != nil {
		return nil, err
	}
	return &m, nil
}

func readBundleFile(dir, name string, limit int64) ([]byte, error) {
	// A manifest names files inside its own directory only.
	if name == "" || !fs.ValidPath(name) {
		return nil, fmt.Errorf("bundle file name %q is not a path inside the bundle", name)
	}
	p := filepath.Join(dir, filepath.FromSlash(name))
	st, err := os.Stat(p)
	if err != nil {
		return nil, err
	}
	if st.Size() > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", name, limit)
	}
	return os.ReadFile(p)
}

// LoadBundle reads the bundle in dir and checks every file against the manifest, so a
// model or prompt that was edited without the manifest being rewritten is refused rather
// than run under the wrong id.
func LoadBundle(dir string) (*Bundle, error) {
	raw, err := os.ReadFile(filepath.Join(dir, ManifestFile))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNoBundle
	}
	if err != nil {
		return nil, err
	}
	var m Manifest
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%s: %w", ManifestFile, err)
	}
	if m.Engine != EngineName || m.BundleVersion != BundleVersion {
		return nil, fmt.Errorf("%s: not a bundle this engine reads (engine %q, version %d)", ManifestFile, m.Engine, m.BundleVersion)
	}
	if m.BundleID != m.id() {
		return nil, fmt.Errorf("%s: the bundle id does not match the manifest's contents; use carthago-oracle to change a bundle", ManifestFile)
	}
	if t := m.Thresholds; t.Watch <= 0 || t.Review < t.Watch || t.Review >= 1 {
		return nil, fmt.Errorf("%s: thresholds must satisfy 0 < watch <= review < 1", ManifestFile)
	}
	read := func(ref FileRef, limit int64) ([]byte, error) {
		data, err := readBundleFile(dir, ref.File, limit)
		if err != nil {
			return nil, err
		}
		if sum(data) != ref.SHA256 {
			return nil, fmt.Errorf("%s does not match the hash in the manifest", ref.File)
		}
		return data, nil
	}
	model, err := read(FileRef{m.Behaviour.File, m.Behaviour.SHA256}, maxBundleFile)
	if err != nil {
		return nil, err
	}
	b := &Bundle{Dir: dir, Manifest: m}
	var id string
	if b.Model, id, err = ParseModel(model); err != nil {
		return nil, err
	}
	if id != m.Behaviour.ID || m.Behaviour.FeatureVersion != FeatureVersion {
		return nil, fmt.Errorf("%s: behaviour model id or feature version does not match the model file", ManifestFile)
	}
	sys, err := read(m.Analyst.System, promptMaxBytes)
	if err != nil {
		return nil, err
	}
	cs, err := read(m.Analyst.Case, promptMaxBytes)
	if err != nil {
		return nil, err
	}
	b.SystemPrompt, b.CasePrompt = string(sys), string(cs)
	return b, nil
}
