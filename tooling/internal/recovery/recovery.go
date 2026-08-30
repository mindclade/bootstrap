// Package recovery validates the isolated recovery source contract without
// reading deployed infrastructure, evidence, or state.
package recovery

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

var envPattern = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,127}$`)

type document struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name  string `yaml:"name"`
		Owner string `yaml:"owner"`
	} `yaml:"metadata"`
	Spec struct {
		Primary struct {
			Backend        string `yaml:"backend"`
			ProjectRef     string `yaml:"projectRef"`
			GenerationFrom string `yaml:"generationFrom"`
			DigestFrom     string `yaml:"digestFrom"`
		} `yaml:"primary"`
		Recovery struct {
			Backend        string `yaml:"backend"`
			ProjectRef     string `yaml:"projectRef"`
			GenerationFrom string `yaml:"generationFrom"`
			DigestFrom     string `yaml:"digestFrom"`
		} `yaml:"recovery"`
		RequiredArtifacts []string `yaml:"requiredArtifacts"`
		Verification      struct {
			MaxEvidenceAgeHours         int      `yaml:"maxEvidenceAgeHours"`
			RequiresIndependentOperator bool     `yaml:"requiresIndependentOperator"`
			ForbiddenDependencies       []string `yaml:"forbiddenDependencies"`
		} `yaml:"verification"`
	} `yaml:"spec"`
}

// Verify validates the restore manifest and the presence of all offline
// procedures. It does not verify evidence freshness or perform a restoration.
func Verify(root string) error {
	path := filepath.Join(root, "recovery", "restore-manifest.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var parsed document
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&parsed); err != nil {
		return fmt.Errorf("parse restore manifest: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("parse restore manifest: multiple YAML documents are not allowed")
		}
		return fmt.Errorf("parse restore manifest: %w", err)
	}
	if parsed.APIVersion != "bootstrap.mindclade.dev/v1" || parsed.Kind != "RestoreManifest" {
		return fmt.Errorf("restore manifest has unsupported apiVersion/kind")
	}
	if parsed.Metadata.Name != "ring0-isolated-restore" || parsed.Metadata.Owner != "mindclade-security" {
		return fmt.Errorf("restore manifest metadata must match the reviewed identity and owner")
	}
	if parsed.Spec.Primary.Backend == "" || parsed.Spec.Recovery.Backend == "" || parsed.Spec.Primary.Backend == parsed.Spec.Recovery.Backend {
		return fmt.Errorf("primary and recovery backends must be present and distinct")
	}
	for name, reference := range map[string]struct {
		actual   string
		expected string
	}{
		"primary backend":     {parsed.Spec.Primary.Backend, "ROOT_TRUST_STATE_BACKEND"},
		"primary project":     {parsed.Spec.Primary.ProjectRef, "ROOT_TRUST_STATE_PROJECT"},
		"primary generation":  {parsed.Spec.Primary.GenerationFrom, "ROOT_TRUST_STATE_GENERATION"},
		"primary digest":      {parsed.Spec.Primary.DigestFrom, "ROOT_TRUST_STATE_SHA256"},
		"recovery backend":    {parsed.Spec.Recovery.Backend, "RECOVERY_STATE_BACKEND"},
		"recovery project":    {parsed.Spec.Recovery.ProjectRef, "RECOVERY_STATE_PROJECT"},
		"recovery generation": {parsed.Spec.Recovery.GenerationFrom, "RECOVERY_STATE_GENERATION"},
		"recovery digest":     {parsed.Spec.Recovery.DigestFrom, "RECOVERY_STATE_SHA256"},
	} {
		if !envPattern.MatchString(reference.actual) {
			return fmt.Errorf("%s must name a runtime environment input", name)
		}
		if reference.actual != reference.expected {
			return fmt.Errorf("%s must equal the reviewed reference %s", name, reference.expected)
		}
	}
	if parsed.Spec.Primary.ProjectRef == parsed.Spec.Recovery.ProjectRef {
		return fmt.Errorf("primary and recovery projects must be distinct")
	}
	expectedArtifacts := map[string]bool{
		"RECOVERY_EVIDENCE_BUNDLE":    true,
		"RECOVERY_EVIDENCE_SIGNATURE": true,
		"RECOVERY_EXPORT_MANIFEST":    true,
		"RECOVERY_SIGNING_PUBLIC_KEY": true,
	}
	artifacts := map[string]bool{}
	for _, artifact := range parsed.Spec.RequiredArtifacts {
		if !envPattern.MatchString(artifact) {
			return fmt.Errorf("required artifact must name a runtime environment input")
		}
		if artifacts[artifact] {
			return fmt.Errorf("required artifacts must be unique")
		}
		if !expectedArtifacts[artifact] {
			return fmt.Errorf("required artifact %s is not in the reviewed restore contract", artifact)
		}
		artifacts[artifact] = true
	}
	if len(artifacts) != len(expectedArtifacts) || !parsed.Spec.Verification.RequiresIndependentOperator {
		return fmt.Errorf("restore requires artifacts and an independent operator")
	}
	if parsed.Spec.Verification.MaxEvidenceAgeHours != 168 {
		return fmt.Errorf("maxEvidenceAgeHours must equal the reviewed seven-day limit")
	}
	expectedDependencies := map[string]bool{
		"application workloads": true,
		"argo cd":               true,
		"gke":                   true,
	}
	dependencies := map[string]bool{}
	for _, dependency := range parsed.Spec.Verification.ForbiddenDependencies {
		normalized := strings.ToLower(strings.TrimSpace(dependency))
		if !expectedDependencies[normalized] {
			return fmt.Errorf("forbidden dependency %q is not in the reviewed restore contract", dependency)
		}
		if dependencies[normalized] {
			return fmt.Errorf("forbiddenDependencies must be unique")
		}
		dependencies[normalized] = true
	}
	if len(dependencies) != len(expectedDependencies) {
		return fmt.Errorf("forbiddenDependencies must contain the exact reviewed dependency set")
	}
	for _, required := range []string{
		"independent-contact-procedure.md",
		"offline-evidence-procedure.md",
		"quarterly-drill-procedure.md",
	} {
		if _, err := os.Stat(filepath.Join(root, "recovery", required)); err != nil {
			return fmt.Errorf("required recovery procedure %s: %w", required, err)
		}
	}
	return nil
}
