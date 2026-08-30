// Package manifest validates the closed Ring-0 repository and its declarative inputs.
package manifest

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

const APIVersion = "bootstrap.mindclade.dev/v1"

var manifestSchemas = map[string]string{
	"manifests/trust-anchors.yaml":       "schemas/v1/trust_anchor.schema.json",
	"manifests/state-backends.yaml":      "schemas/v1/state_backend.schema.json",
	"manifests/identity-federation.yaml": "schemas/v1/federation.schema.json",
	"manifests/signing-roots.yaml":       "schemas/v1/signing_root.schema.json",
	"manifests/audit-roots.yaml":         "schemas/v1/audit_root.schema.json",
	"manifests/break-glass-roles.yaml":   "schemas/v1/break_glass.schema.json",
	"manifests/recovery-policy.yaml":     "schemas/v1/recovery_policy.schema.json",
}

var expectedFiles = []string{
	".editorconfig", ".github/CODEOWNERS", ".github/dependabot.yml", ".github/pull_request_template.md",
	".github/workflows/protected-apply.yml", ".github/workflows/pull-request.yml", ".github/workflows/recovery-verification.yml",
	".gitignore", "BUILD.bazel", "LICENSE", "MODULE.bazel", "README.md", "SECURITY.md", "component.yaml", "justfile",
	"manifests/audit-roots.yaml", "manifests/break-glass-roles.yaml", "manifests/identity-federation.yaml",
	"manifests/recovery-policy.yaml", "manifests/signing-roots.yaml", "manifests/state-backends.yaml", "manifests/trust-anchors.yaml",
	"opentofu/live/recovery-plane/backend.tf", "opentofu/live/recovery-plane/main.tf", "opentofu/live/recovery-plane/outputs.tf",
	"opentofu/live/recovery-plane/providers.tf", "opentofu/live/recovery-plane/versions.tf",
	"opentofu/live/root-trust/backend.tf", "opentofu/live/root-trust/main.tf", "opentofu/live/root-trust/outputs.tf",
	"opentofu/live/root-trust/providers.tf", "opentofu/live/root-trust/versions.tf",
	"opentofu/modules/audit-root/main.tf", "opentofu/modules/audit-root/outputs.tf", "opentofu/modules/audit-root/variables.tf",
	"opentofu/modules/break-glass/main.tf", "opentofu/modules/break-glass/outputs.tf", "opentofu/modules/break-glass/variables.tf",
	"opentofu/modules/buildkite-federation/main.tf", "opentofu/modules/buildkite-federation/outputs.tf", "opentofu/modules/buildkite-federation/variables.tf",
	"opentofu/modules/github-federation/main.tf", "opentofu/modules/github-federation/outputs.tf", "opentofu/modules/github-federation/variables.tf",
	"opentofu/modules/gitops-federation/main.tf", "opentofu/modules/gitops-federation/outputs.tf", "opentofu/modules/gitops-federation/variables.tf",
	"opentofu/modules/recovery-exports/main.tf", "opentofu/modules/recovery-exports/outputs.tf", "opentofu/modules/recovery-exports/variables.tf",
	"opentofu/modules/signing-root/main.tf", "opentofu/modules/signing-root/outputs.tf", "opentofu/modules/signing-root/variables.tf",
	"opentofu/modules/state-backend/main.tf", "opentofu/modules/state-backend/outputs.tf", "opentofu/modules/state-backend/variables.tf",
	"opentofu/modules/workforce-identity/main.tf", "opentofu/modules/workforce-identity/outputs.tf", "opentofu/modules/workforce-identity/variables.tf",
	"policy/break_glass.rego", "policy/federation_claims.rego", "policy/key_administration.rego", "policy/root_separation.rego",
	"policy/state_protection.rego", "policy/tests/break_glass_test.rego", "policy/tests/federation_claims_test.rego",
	"policy/tests/key_administration_test.rego", "policy/tests/root_separation_test.rego", "policy/tests/state_protection_test.rego",
	"recovery/independent-contact-procedure.md", "recovery/offline-evidence-procedure.md", "recovery/quarterly-drill-procedure.md", "recovery/restore-manifest.yaml",
	"runbooks/break-glass-activation.md", "runbooks/root-identity-compromise.md", "runbooks/signing-root-recovery.md", "runbooks/state-backend-unavailable.md",
	"schemas/v1/audit_root.schema.json", "schemas/v1/break_glass.schema.json", "schemas/v1/federation.schema.json",
	"schemas/v1/recovery_policy.schema.json", "schemas/v1/signing_root.schema.json", "schemas/v1/state_backend.schema.json", "schemas/v1/trust_anchor.schema.json",
	"tests/contract/test_manifest_schemas.py", "tests/failure/test_partial_bootstrap_apply.py", "tests/plan/test_minimum_privilege.py", "tests/recovery/test_isolated_restore.py",
	"tooling/BUILD.bazel", "tooling/cmd/bootstrapctl/main.go", "tooling/go.mod", "tooling/go.sum",
	"tooling/internal/evidence/evidence.go", "tooling/internal/manifest/manifest.go", "tooling/internal/plan/plan.go", "tooling/internal/recovery/recovery.go",
}

var (
	envNamePattern                 = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,127}$`)
	secretKeyPattern               = regexp.MustCompile(`(?i)(password|private[_-]?key|credential|secret|token)$`)
	projectIDPattern               = regexp.MustCompile(`^[a-z][a-z0-9-]{4,28}[a-z0-9]$`)
	bucketNamePattern              = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$`)
	keyIDPattern                   = regexp.MustCompile(`^[A-Za-z0-9_-]{1,63}$`)
	gcpIDPattern                   = regexp.MustCompile(`^[a-z][a-z0-9-]{1,31}$`)
	githubRepoPattern              = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	uuidPattern                    = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	providerNamePattern            = regexp.MustCompile(`^projects/([0-9]+)/locations/global/workloadIdentityPools/([a-z0-9-]+)/providers/([a-z0-9-]+)$`)
	keyVersionPattern              = regexp.MustCompile(`^projects/([a-z][a-z0-9-]{4,28}[a-z0-9])/locations/([a-z0-9-]+)/keyRings/([A-Za-z0-9_-]+)/cryptoKeys/([A-Za-z0-9_-]+)/cryptoKeyVersions/([1-9][0-9]*)$`)
	emailAddressPattern            = regexp.MustCompile(`^[A-Za-z0-9.!#$%&'*+/=?^_{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$`)
	serviceAccountPrincipalPattern = regexp.MustCompile(
		`^serviceAccount:[a-z][a-z0-9-]{1,28}[a-z0-9]@[a-z][a-z0-9-]{4,28}[a-z0-9]\.iam\.gserviceaccount\.com$`,
	)
	federatedPrincipalPattern = regexp.MustCompile(
		`^(principal://iam\.googleapis\.com/(projects/[0-9]+/locations/global/workloadIdentityPools/[a-z0-9-]+|locations/global/workforcePools/[a-z0-9-]+)/subject/[^/*[:space:]]+|principalSet://iam\.googleapis\.com/(projects/[0-9]+/locations/global/workloadIdentityPools/[a-z0-9-]+|locations/global/workforcePools/[a-z0-9-]+)/(group|attribute\.[A-Za-z0-9_]+)/[^/*[:space:]]+)$`,
	)
)

const workforceSecretReference = "WORKFORCE_OIDC_CLIENT_SECRET"

var outOfBandReferences = map[string]bool{
	"RECOVERY_CONTACT_1": true,
	"RECOVERY_CONTACT_2": true,
}

// ExpectedFiles returns the closed blueprint source manifest, including BLUEPRINT.md.
func ExpectedFiles() []string {
	paths := append([]string{}, expectedFiles...)
	paths = append(paths, "BLUEPRINT.md")
	sort.Strings(paths)
	return paths
}

// Result is a machine-readable validation outcome.
type Result struct {
	Files     int      `json:"files"`
	Manifests int      `json:"manifests"`
	Errors    []string `json:"errors,omitempty"`
}

// RenderResult reports only the identity and digest of a rendered, non-secret
// OpenTofu variable document. It deliberately never echoes resolved values.
type RenderResult struct {
	Composition  string `json:"composition"`
	OutputSHA256 string `json:"outputSha256"`
}

type compiler struct {
	root      string
	documents map[string]map[string]any
	values    map[string]string
	problems  []string
}

type roleValues struct {
	Plan     string `json:"plan"`
	Apply    string `json:"apply"`
	Recovery string `json:"recovery"`
}

type recoveryContext struct {
	Federation struct {
		GitHub struct {
			Providers roleValues `json:"providers"`
			Audiences roleValues `json:"audiences"`
		} `json:"github"`
		Buildkite struct {
			Provider string `json:"provider"`
			Audience string `json:"audience"`
		} `json:"buildkite"`
		GitOps struct {
			Provider string `json:"provider"`
			Audience string `json:"audience"`
		} `json:"gitops"`
	} `json:"federation"`
	StateBackends struct {
		RootTrust     recoveryBackendContext `json:"root_trust"`
		RecoveryPlane recoveryBackendContext `json:"recovery_plane"`
	} `json:"state_backends"`
	SigningRoots map[string]struct {
		PrimaryVersion string `json:"primary_version"`
	} `json:"signing_roots"`
}

type recoveryBackendContext struct {
	ProjectID        string `json:"project_id"`
	Bucket           string `json:"bucket"`
	Prefix           string `json:"prefix"`
	ReplicaProjectID string `json:"replica_project_id"`
	ReplicaBucket    string `json:"replica_bucket"`
}

// ValidateRepository validates the exact tree and every manifest/schema pair.
func ValidateRepository(root string) (Result, error) {
	root, err := filepath.Abs(root)
	if err != nil {
		return Result{}, err
	}
	result := Result{Files: len(expectedFiles), Manifests: len(manifestSchemas)}
	var problems []string
	if err := validateTree(root); err != nil {
		problems = append(problems, err.Error())
	}
	if err := validateTrackedPaths(root); err != nil {
		problems = append(problems, err.Error())
	}
	if err := validateWorkflowSecurity(root); err != nil {
		problems = append(problems, err.Error())
	}
	paths := make([]string, 0, len(manifestSchemas))
	for path := range manifestSchemas {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, manifestPath := range paths {
		if err := validateDocument(root, manifestPath, manifestSchemas[manifestPath]); err != nil {
			problems = append(problems, err.Error())
		}
	}
	if err := validateComponent(root); err != nil {
		problems = append(problems, err.Error())
	}
	if err := validateReferences(root); err != nil {
		problems = append(problems, err.Error())
	}
	documents, documentsErr := loadCompilerDocuments(root)
	if documentsErr != nil {
		problems = append(problems, documentsErr.Error())
	} else {
		compiled := &compiler{root: root, documents: documents, values: map[string]string{}}
		compiled.validateContracts()
		if err := compiled.err(); err != nil {
			problems = append(problems, err.Error())
		}
	}
	result.Errors = problems
	if len(problems) != 0 {
		return result, errors.New(strings.Join(problems, "\n"))
	}
	return result, nil
}

// RenderVariables compiles the reviewed manifest set and an exact map of
// non-secret external values into one OpenTofu root variable document.
// Context is forbidden for root-trust and required for recovery-plane.
func RenderVariables(root, composition, valuesPath, contextPath, outputPath string) (RenderResult, error) {
	if composition != "root-trust" && composition != "recovery-plane" {
		return RenderResult{}, fmt.Errorf("composition must be root-trust or recovery-plane")
	}
	if valuesPath == "" || outputPath == "" {
		return RenderResult{}, fmt.Errorf("values and output paths are required")
	}
	if composition == "root-trust" && contextPath != "" {
		return RenderResult{}, fmt.Errorf("context is forbidden for root-trust")
	}
	if composition == "recovery-plane" && contextPath == "" {
		return RenderResult{}, fmt.Errorf("context is required for recovery-plane")
	}

	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return RenderResult{}, err
	}
	if _, err := ValidateRepository(absoluteRoot); err != nil {
		return RenderResult{}, fmt.Errorf("repository is not valid: %w", err)
	}
	documents, err := loadCompilerDocuments(absoluteRoot)
	if err != nil {
		return RenderResult{}, err
	}
	values, err := loadExactStringMap(valuesPath)
	if err != nil {
		return RenderResult{}, fmt.Errorf("load values: %w", err)
	}
	references := map[string]int{}
	for path, document := range documents {
		collectEnvironmentReferences(document, path, references)
	}
	if references[workforceSecretReference] != 1 {
		return RenderResult{}, fmt.Errorf("manifest set must contain exactly one %s reference", workforceSecretReference)
	}
	if _, present := values[workforceSecretReference]; present {
		return RenderResult{}, fmt.Errorf("values must not contain %s", workforceSecretReference)
	}
	for name := range outOfBandReferences {
		if _, present := values[name]; present {
			return RenderResult{}, fmt.Errorf("values must not contain out-of-band reference %s", name)
		}
	}
	var missing, unknown, invalid []string
	for name := range references {
		if name == workforceSecretReference || outOfBandReferences[name] {
			continue
		}
		value, present := values[name]
		if !present {
			missing = append(missing, name)
			continue
		}
		if value == "" || strings.TrimSpace(value) == "" || value != strings.TrimSpace(value) || strings.ContainsAny(value, "\x00\r\n") {
			invalid = append(invalid, name)
		}
	}
	for name := range values {
		if references[name] == 0 {
			unknown = append(unknown, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(unknown)
	sort.Strings(invalid)
	if len(missing) != 0 || len(unknown) != 0 || len(invalid) != 0 {
		return RenderResult{}, fmt.Errorf("values contract failed: missing=%v unknown=%v invalid=%v", missing, unknown, invalid)
	}

	compiled := &compiler{root: absoluteRoot, documents: documents, values: values}
	compiled.validateContracts()
	var output map[string]any
	if composition == "root-trust" {
		output = map[string]any{"bootstrap": compiled.rootTrustVariables()}
	} else {
		context, contextErr := loadRecoveryContext(contextPath)
		if contextErr != nil {
			return RenderResult{}, contextErr
		}
		output = map[string]any{"recovery": compiled.recoveryVariables(context)}
	}
	if err := compiled.err(); err != nil {
		return RenderResult{}, err
	}

	encoded, err := json.MarshalIndent(output, "", "  ")
	if err != nil {
		return RenderResult{}, fmt.Errorf("encode rendered variables: %w", err)
	}
	encoded = append(encoded, '\n')
	if err := protectOutputTarget(absoluteRoot, valuesPath, contextPath, outputPath); err != nil {
		return RenderResult{}, err
	}
	if err := writePrivateAtomic(outputPath, encoded); err != nil {
		return RenderResult{}, err
	}
	digest := sha256.Sum256(encoded)
	return RenderResult{Composition: composition, OutputSHA256: fmt.Sprintf("sha256:%x", digest[:])}, nil
}

type componentDocument struct {
	APIVersion string `yaml:"apiVersion"`
	Kind       string `yaml:"kind"`
	Metadata   struct {
		Name        string            `yaml:"name"`
		Description string            `yaml:"description"`
		Annotations map[string]string `yaml:"annotations"`
	} `yaml:"metadata"`
	Spec struct {
		Type                string   `yaml:"type"`
		Lifecycle           string   `yaml:"lifecycle"`
		Maturity            string   `yaml:"maturity"`
		Owner               string   `yaml:"owner"`
		SecurityReviewers   []string `yaml:"security_reviewers"`
		RepositoryClass     string   `yaml:"repository_class"`
		DataClassification  string   `yaml:"data_classification"`
		ProductionAuthority bool     `yaml:"production_authority"`
		Dependencies        []string `yaml:"dependencies"`
		Provides            []string `yaml:"provides"`
		Release             struct {
			Strategy  string   `yaml:"strategy"`
			Artifact  string   `yaml:"artifact"`
			Immutable bool     `yaml:"immutable"`
			Evidence  []string `yaml:"evidence"`
		} `yaml:"release"`
		Activation struct {
			SourceReady struct {
				Description string `yaml:"description"`
			} `yaml:"source_ready"`
			Connected struct {
				Description string `yaml:"description"`
			} `yaml:"connected"`
		} `yaml:"activation"`
		License string `yaml:"license"`
	} `yaml:"spec"`
}

func validateComponent(root string) error {
	path := filepath.Join(root, "component.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	var component componentDocument
	if err := decoder.Decode(&component); err != nil {
		return fmt.Errorf("validate component.yaml: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("validate component.yaml: multiple YAML documents are not allowed")
	}
	if component.APIVersion != "mindclade.io/v1alpha1" || component.Kind != "Component" || component.Metadata.Name != "bootstrap" {
		return fmt.Errorf("validate component.yaml: invalid component identity")
	}
	if component.Metadata.Description == "" || component.Metadata.Annotations["github.com/project-slug"] != "mindclade/bootstrap" ||
		component.Metadata.Annotations["mindclade.dev/authority-boundary"] != "ring-0-only" {
		return fmt.Errorf("validate component.yaml: metadata contract is incomplete")
	}
	if component.Spec.Type != "bootstrap-control-plane" || component.Spec.Lifecycle != "production" || component.Spec.Maturity != "production" ||
		component.Spec.Owner != "platform-operations" || component.Spec.RepositoryClass != "infrastructure-source" ||
		component.Spec.DataClassification != "restricted" || !component.Spec.ProductionAuthority {
		return fmt.Errorf("validate component.yaml: owner/maturity/authority contract is invalid")
	}
	if component.Spec.Dependencies == nil || len(component.Spec.Provides) < 3 || len(component.Spec.SecurityReviewers) < 1 ||
		component.Spec.SecurityReviewers[0] == component.Spec.Owner {
		return fmt.Errorf("validate component.yaml: dependency/ownership contract is invalid")
	}
	for _, dependency := range component.Spec.Dependencies {
		if !strings.HasPrefix(dependency, "component:") || strings.TrimPrefix(dependency, "component:") == "" {
			return fmt.Errorf("validate component.yaml: invalid dependency %q", dependency)
		}
	}
	if component.Spec.Release.Strategy == "" || component.Spec.Release.Artifact != "source-commit" || !component.Spec.Release.Immutable ||
		len(component.Spec.Release.Evidence) < 3 || component.Spec.Activation.SourceReady.Description == "" ||
		component.Spec.Activation.Connected.Description == "" || component.Spec.License == "" {
		return fmt.Errorf("validate component.yaml: release/activation metadata is incomplete")
	}
	return nil
}

// SourceDigest binds the authoritative blueprint tree by path and content.
func SourceDigest(root string) (string, error) {
	paths := ExpectedFiles()
	digest := sha256.New()
	for _, relative := range paths {
		data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			return "", err
		}
		_, _ = digest.Write([]byte(relative))
		_, _ = digest.Write([]byte{0})
		_, _ = digest.Write(data)
		_, _ = digest.Write([]byte{0})
	}
	return fmt.Sprintf("%x", digest.Sum(nil)), nil
}

func validateReferences(root string) error {
	projects, err := identifiersAt(root, "manifests/trust-anchors.yaml", "spec", "projects")
	if err != nil {
		return err
	}
	backends, err := identifiersAt(root, "manifests/state-backends.yaml", "spec", "backends")
	if err != nil {
		return err
	}
	signingRoots, err := identifiersAt(root, "manifests/signing-roots.yaml", "spec", "keys")
	if err != nil {
		return err
	}
	auditBuckets, err := identifiersAt(root, "manifests/audit-roots.yaml", "spec", "logBuckets")
	if err != nil {
		return err
	}

	targets := map[string]map[string]bool{
		"projectRef":           projects,
		"targetProjectRef":     projects,
		"rootTrustBackendRef":  backends,
		"recoveryBackendRef":   backends,
		"signingRootRef":       signingRoots,
		"destinationBucketRef": auditBuckets,
	}
	var problems []string
	for manifestPath := range manifestSchemas {
		document, err := LoadYAML(filepath.Join(root, filepath.FromSlash(manifestPath)))
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		checkReferences(document, manifestPath, targets, &problems)
	}
	sort.Strings(problems)
	if len(problems) != 0 {
		return fmt.Errorf("cross-manifest reference validation failed: %s", strings.Join(problems, "; "))
	}
	return nil
}

type workflowContract struct {
	triggers     []string
	jobs         map[string]map[string]string
	environments map[string]string
	actions      []string
}

var workflowContracts = map[string]workflowContract{
	".github/workflows/pull-request.yml": {
		triggers: []string{"merge_group", "pull_request", "push", "workflow_dispatch"},
		jobs: map[string]map[string]string{
			"required": nil,
		},
		environments: map[string]string{},
		actions: []string{
			"actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
			"actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
			"actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
			"bazel-contrib/setup-bazel@c5acdfb288317d0b5c0bbd7a396a3dc868bb0f86",
			"opentofu/setup-opentofu@a1320f892987e89d278cc92dc5adc984fb93aca4",
		},
	},
	".github/workflows/protected-apply.yml": {
		triggers: []string{"workflow_dispatch"},
		jobs: map[string]map[string]string{
			"plan":  {"contents": "read", "id-token": "write"},
			"apply": {"actions": "read", "contents": "read", "id-token": "write"},
		},
		environments: map[string]string{
			"plan":  "infrastructure-plan",
			"apply": "infrastructure-apply",
		},
		actions: []string{
			"actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
			"actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
			"actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c",
			"actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
			"actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
			"actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
			"google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093",
			"google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093",
			"opentofu/setup-opentofu@a1320f892987e89d278cc92dc5adc984fb93aca4",
			"opentofu/setup-opentofu@a1320f892987e89d278cc92dc5adc984fb93aca4",
		},
	},
	".github/workflows/recovery-verification.yml": {
		triggers: []string{"schedule", "workflow_dispatch"},
		jobs: map[string]map[string]string{
			"offline":   {"attestations": "write", "contents": "read", "id-token": "write"},
			"connected": {"contents": "read", "id-token": "write"},
		},
		environments: map[string]string{
			"connected": "recovery-verification",
		},
		actions: []string{
			"actions/attest-build-provenance@4d101475d8b20a2381f78447822ac1eab6504dd8",
			"actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
			"actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
			"actions/setup-go@b7ad1dad31e06c5925ef5d2fc7ad053ef454303e",
			"actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
			"actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
			"actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
			"bazel-contrib/setup-bazel@c5acdfb288317d0b5c0bbd7a396a3dc868bb0f86",
			"google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093",
			"google-github-actions/setup-gcloud@aa5489c8933f4cc7a4f7d45035b3b1440c9c10db",
			"opentofu/setup-opentofu@a1320f892987e89d278cc92dc5adc984fb93aca4",
		},
	},
}

const (
	qualifiedTofuVersion  = "1.12.6"
	qualifiedTofuChecksum = "5dc43da4f750f33873dc25e94587128709e819e544b7be9016b255316153c3a8"
)

func validateWorkflowSecurity(root string) error {
	var problems []string
	for relative, contract := range workflowContracts {
		value, err := LoadYAML(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		workflow, ok := value.(map[string]any)
		if !ok {
			problems = append(problems, relative+" must be a YAML object")
			continue
		}

		triggers, ok := workflow["on"].(map[string]any)
		if !ok || !reflect.DeepEqual(sortedKeys(triggers), contract.triggers) {
			problems = append(problems, fmt.Sprintf("%s must use exactly the approved triggers %v", relative, contract.triggers))
		}
		if !exactStringMap(workflow["permissions"], map[string]string{"contents": "read"}) {
			problems = append(problems, relative+" must default to contents: read only")
		}
		environment, _ := workflow["env"].(map[string]any)
		if environment["TOFU_VERSION"] != qualifiedTofuVersion {
			problems = append(problems, relative+" must pin the qualified OpenTofu version "+qualifiedTofuVersion)
		}

		jobs, ok := workflow["jobs"].(map[string]any)
		if !ok || !reflect.DeepEqual(sortedKeys(jobs), sortedKeys(contract.jobs)) {
			problems = append(problems, fmt.Sprintf("%s must contain exactly the approved jobs", relative))
			continue
		}
		var actions []string
		for jobName, expectedPermissions := range contract.jobs {
			job, ok := jobs[jobName].(map[string]any)
			if !ok {
				problems = append(problems, fmt.Sprintf("%s job %s must be an object", relative, jobName))
				continue
			}
			if job["runs-on"] != "ubuntu-24.04" {
				problems = append(problems, fmt.Sprintf("%s job %s must use ubuntu-24.04", relative, jobName))
			}
			actualPermissions, present := job["permissions"]
			if expectedPermissions == nil {
				if present {
					problems = append(problems, fmt.Sprintf("%s job %s must inherit the read-only workflow permissions", relative, jobName))
				}
			} else if !present || !exactStringMap(actualPermissions, expectedPermissions) {
				problems = append(problems, fmt.Sprintf("%s job %s permissions differ from the exact approved set", relative, jobName))
			}
			expectedEnvironment := contract.environments[jobName]
			if actualEnvironment, present := job["environment"]; expectedEnvironment == "" {
				if present {
					problems = append(problems, fmt.Sprintf("%s job %s must not use an unreviewed environment", relative, jobName))
				}
			} else if !present || actualEnvironment != expectedEnvironment {
				problems = append(problems, fmt.Sprintf("%s job %s must use environment %s", relative, jobName, expectedEnvironment))
			}

			steps, ok := job["steps"].([]any)
			if !ok || len(steps) == 0 {
				problems = append(problems, fmt.Sprintf("%s job %s must contain steps", relative, jobName))
				continue
			}
			for _, rawStep := range steps {
				step, ok := rawStep.(map[string]any)
				if !ok {
					problems = append(problems, fmt.Sprintf("%s job %s contains a non-object step", relative, jobName))
					continue
				}
				uses, hasUses := step["uses"].(string)
				if !hasUses {
					continue
				}
				actions = append(actions, uses)
				inputs, _ := step["with"].(map[string]any)
				if strings.HasPrefix(uses, "actions/checkout@") && inputs["persist-credentials"] != false {
					problems = append(problems, fmt.Sprintf("%s job %s checkout must disable persisted credentials", relative, jobName))
				}
				if strings.HasPrefix(uses, "opentofu/setup-opentofu@") &&
					(inputs["tofu_version"] != "${{ env.TOFU_VERSION }}" || inputs["tofu_wrapper"] != false || inputs["cache"] != false ||
						strings.TrimSpace(fmt.Sprint(inputs["checksums"])) != qualifiedTofuChecksum) {
					problems = append(problems, fmt.Sprintf("%s job %s OpenTofu setup must use the exact version, checksum, and disabled wrapper/cache contract", relative, jobName))
				}
				if strings.HasPrefix(uses, "google-github-actions/auth@") && inputs["audience"] == nil {
					problems = append(problems, fmt.Sprintf("%s job %s federation must request the configured audience", relative, jobName))
				}
			}
		}
		sort.Strings(actions)
		expectedActions := append([]string{}, contract.actions...)
		sort.Strings(expectedActions)
		if !reflect.DeepEqual(actions, expectedActions) {
			problems = append(problems, fmt.Sprintf("%s actions must equal the exact immutable allowlist", relative))
		}
	}

	if err := validateTerminalSourceRechecks(root); err != nil {
		problems = append(problems, err.Error())
	}
	if err := validateRecoveryWorkflowContract(root); err != nil {
		problems = append(problems, err.Error())
	}
	if err := validateDependabot(root); err != nil {
		problems = append(problems, err.Error())
	}
	readme, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		problems = append(problems, err.Error())
	} else if !bytes.Contains(readme, []byte(`buildkite-agent oidc request-token --audience "${BUILDKITE_OIDC_AUDIENCE}" --subject-claim pipeline_id`)) {
		problems = append(problems, "README.md must document the exact Buildkite audience and pipeline-ID subject token request")
	}

	sort.Strings(problems)
	if len(problems) != 0 {
		return fmt.Errorf("workflow security validation failed: %s", strings.Join(problems, "; "))
	}
	return nil
}

func validateRecoveryWorkflowContract(root string) error {
	const relative = ".github/workflows/recovery-verification.yml"
	value, err := LoadYAML(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		return err
	}
	workflow, _ := value.(map[string]any)
	var problems []string
	if workflow["name"] != "recovery-verification" {
		problems = append(problems, "workflow name must remain recovery-verification")
	}
	if !exactStringMap(workflow["env"], map[string]string{
		"GO_VERSION": "1.26.6", "JUST_VERSION": "1.55.1", "PYTHON_VERSION": "3.14.7",
		"TOFU_VERSION": qualifiedTofuVersion, "USE_BAZEL_VERSION": "9.1.1",
	}) {
		problems = append(problems, "recovery workflow tool versions must equal the exact qualified set")
	}
	expectedConcurrency := map[string]any{
		"group": "bootstrap-ring0-state-mutation-observation", "cancel-in-progress": false,
	}
	if !reflect.DeepEqual(workflow["concurrency"], expectedConcurrency) {
		problems = append(problems, "recovery workflow must retain the shared non-cancelling Ring-0 concurrency mutex")
	}

	triggers, _ := workflow["on"].(map[string]any)
	schedule, scheduleOK := triggers["schedule"].([]any)
	validSchedule := scheduleOK && len(schedule) == 1
	if validSchedule {
		entry, _ := schedule[0].(map[string]any)
		validSchedule = len(entry) == 1 && entry["cron"] == "17 7 1 1,4,7,10 *"
	}
	dispatch, _ := triggers["workflow_dispatch"].(map[string]any)
	inputs, _ := dispatch["inputs"].(map[string]any)
	connectedInput, _ := inputs["connected"].(map[string]any)
	validInput := len(dispatch) == 1 && len(inputs) == 1 && len(connectedInput) == 4 &&
		connectedInput["description"] == "Also perform federated, read-only recovery-plane checks and KMS-sign the evidence" &&
		connectedInput["required"] == false && connectedInput["default"] == false && connectedInput["type"] == "boolean"
	if !validSchedule || !validInput {
		problems = append(problems, "recovery workflow must use the exact quarterly schedule and manual connected boolean input")
	}

	jobs, _ := workflow["jobs"].(map[string]any)
	offline, _ := jobs["offline"].(map[string]any)
	connected, _ := jobs["connected"].(map[string]any)
	if offline["timeout-minutes"] != 45 || connected["timeout-minutes"] != 45 {
		problems = append(problems, "recovery jobs must retain the exact 45-minute timeout")
	}
	if connected["if"] != "github.event_name == 'workflow_dispatch' && inputs.connected" || connected["needs"] != "offline" {
		problems = append(problems, "connected recovery verification must remain manual-only and depend on offline qualification")
	}
	if !exactStringMap(connected["env"], map[string]string{
		"ORGANIZATION_ID":                  "${{ vars.GCP_ORGANIZATION_ID }}",
		"AUDIT_PROJECT_ID":                 "${{ vars.GCP_AUDIT_PROJECT_ID }}",
		"RECOVERY_PROJECT_ID":              "${{ vars.GCP_RECOVERY_PROJECT_ID }}",
		"ROOT_TRUST_STATE_BUCKET":          "${{ vars.ROOT_TRUST_STATE_BUCKET }}",
		"ROOT_TRUST_STATE_REPLICA_BUCKET":  "${{ vars.ROOT_TRUST_STATE_REPLICA_BUCKET }}",
		"RECOVERY_STATE_BUCKET":            "${{ vars.RECOVERY_STATE_BUCKET }}",
		"RECOVERY_STATE_REPLICA_BUCKET":    "${{ vars.RECOVERY_STATE_REPLICA_BUCKET }}",
		"RECOVERY_EXPORT_BUCKET":           "${{ vars.RECOVERY_EXPORT_BUCKET }}",
		"RECOVERY_EVIDENCE_BUCKET":         "${{ vars.RECOVERY_EVIDENCE_BUCKET }}",
		"RECOVERY_SIGNING_PROJECT_ID":      "${{ vars.RECOVERY_SIGNING_PROJECT_ID }}",
		"RECOVERY_SIGNING_KMS_LOCATION":    "${{ vars.RECOVERY_SIGNING_KMS_LOCATION }}",
		"RECOVERY_SIGNING_KMS_KEYRING":     "${{ vars.RECOVERY_SIGNING_KMS_KEYRING }}",
		"RECOVERY_SIGNING_KMS_KEY":         "${{ vars.RECOVERY_SIGNING_KMS_KEY }}",
		"RECOVERY_SIGNING_KMS_KEY_VERSION": "${{ vars.RECOVERY_SIGNING_KMS_KEY_VERSION }}",
		"WIF_PROVIDER":                     "${{ vars.GCP_RECOVERY_WORKLOAD_IDENTITY_PROVIDER }}",
		"WIF_SERVICE_ACCOUNT":              "${{ vars.GCP_RECOVERY_SERVICE_ACCOUNT }}",
		"WIF_AUDIENCE":                     "${{ vars.GCP_RECOVERY_OIDC_AUDIENCE }}",
	}) {
		problems = append(problems, "connected recovery environment must equal the exact non-secret qualified-output contract")
	}

	step := func(job map[string]any, name string) map[string]any {
		steps, _ := job["steps"].([]any)
		var found map[string]any
		for _, raw := range steps {
			candidate, _ := raw.(map[string]any)
			if candidate["name"] != name {
				continue
			}
			if found != nil {
				return nil
			}
			found = candidate
		}
		return found
	}
	exactInputs := func(candidate map[string]any, expected map[string]any) bool {
		inputs, ok := candidate["with"].(map[string]any)
		return ok && reflect.DeepEqual(inputs, expected)
	}
	auth := step(connected, "Authenticate the isolated recovery identity")
	if auth == nil || !exactInputs(auth, map[string]any{
		"project_id":                   "${{ env.RECOVERY_PROJECT_ID }}",
		"workload_identity_provider":   "${{ env.WIF_PROVIDER }}",
		"service_account":              "${{ env.WIF_SERVICE_ACCOUNT }}",
		"audience":                     "${{ env.WIF_AUDIENCE }}",
		"create_credentials_file":      true,
		"export_environment_variables": true,
	}) {
		problems = append(problems, "recovery federation must use the exact identity, audience, and credential-file inputs")
	}
	gcloud := step(connected, "Set up Google Cloud CLI")
	if gcloud == nil || !exactInputs(gcloud, map[string]any{"version": "504.0.0"}) {
		problems = append(problems, "recovery workflow must pin the exact qualified gcloud version")
	}
	attestation := step(offline, "Sign the offline evidence with GitHub artifact attestation")
	if attestation == nil || !exactInputs(attestation, map[string]any{
		"subject-path": "${{ runner.temp }}/offline-source-simulation.json",
	}) {
		problems = append(problems, "offline attestation must bind only the redacted evidence subject")
	}
	offlineUpload := step(offline, "Retain only the redacted offline evidence")
	if offlineUpload == nil || !exactInputs(offlineUpload, map[string]any{
		"name":              "offline-source-simulation-${{ github.run_id }}-${{ github.run_attempt }}",
		"path":              "${{ runner.temp }}/offline-source-simulation.json",
		"if-no-files-found": "error", "retention-days": 90,
	}) {
		problems = append(problems, "offline artifact upload must retain only the exact redacted evidence file")
	}
	connectedUpload := step(connected, "Retain only redacted signed evidence")
	if connectedUpload == nil || !exactInputs(connectedUpload, map[string]any{
		"name":              "connected-recovery-evidence-${{ github.run_id }}-${{ github.run_attempt }}",
		"path":              "${{ runner.temp }}/connected-evidence/",
		"if-no-files-found": "error", "retention-days": 90,
	}) {
		problems = append(problems, "connected artifact upload must retain only the exact redacted signed bundle")
	}

	sinkStep := step(connected, "Read backend and recovery generations without logging inventory")
	sinkRun, _ := sinkStep["run"].(string)
	requiredSinkSnippets := []string{
		`'bootstrap-admin-activity|primary|log_id("cloudaudit.googleapis.com/activity")'`,
		`'bootstrap-admin-activity-recovery|recovery|log_id("cloudaudit.googleapis.com/activity")'`,
		`'bootstrap-security-events|primary|severity>=WARNING OR protoPayload.serviceName="iam.googleapis.com"'`,
		`'bootstrap-security-events-recovery|recovery|severity>=WARNING OR protoPayload.serviceName="iam.googleapis.com"'`,
		`--organization="${ORGANIZATION_ID}"`,
		`--arg writerIdentity "serviceAccount:service-org-${ORGANIZATION_ID}@gcp-sa-logging.iam.gserviceaccount.com"`,
		`and ((.exclusions // []) == [])`,
		`and (.writerIdentity == $writerIdentity)`,
		`audit-sink-files.txt`,
		`exactConfigurationVerified: true`,
		`sharedOrganizationWriterIdentity: true`,
	}
	for _, snippet := range requiredSinkSnippets {
		if !strings.Contains(sinkRun, snippet) {
			problems = append(problems, "connected recovery must verify the four exact enabled, exclusion-free organization audit sinks")
			break
		}
	}

	sort.Strings(problems)
	if len(problems) != 0 {
		return fmt.Errorf("%s exact recovery contract failed: %s", relative, strings.Join(problems, "; "))
	}
	return nil
}

func validateTerminalSourceRechecks(root string) error {
	checks := []struct {
		path      string
		job       string
		step      string
		sha       string
		tracked   string
		untracked string
		mutation  string
	}{
		{
			path: ".github/workflows/protected-apply.yml", job: "apply", step: "Apply only the verified saved plan",
			sha: `test "$(git rev-parse HEAD)" = "${EXPECTED_SOURCE_SHA}"`, mutation: `tofu -chdir="opentofu/live/${BOOTSTRAP_ROOT}" apply`,
		},
		{
			path: ".github/workflows/recovery-verification.yml", job: "connected", step: "Render and KMS-sign redacted connected evidence",
			sha: `test "$(git rev-parse HEAD)" = "${GITHUB_SHA}"`, tracked: "git diff --exit-code -- .",
			untracked: `test -z "$(git status --porcelain=v1 --untracked-files=all)"`, mutation: "gcloud kms asymmetric-sign",
		},
	}
	for _, check := range checks {
		value, err := LoadYAML(filepath.Join(root, filepath.FromSlash(check.path)))
		if err != nil {
			return err
		}
		workflow, _ := value.(map[string]any)
		jobs, _ := workflow["jobs"].(map[string]any)
		job, _ := jobs[check.job].(map[string]any)
		steps, _ := job["steps"].([]any)
		var run string
		var hasToken bool
		for _, rawStep := range steps {
			step, _ := rawStep.(map[string]any)
			if step["name"] == check.step {
				run, _ = step["run"].(string)
				env, _ := step["env"].(map[string]any)
				hasToken = env["GH_TOKEN"] != nil
				break
			}
		}
		shaIndex := strings.LastIndex(run, check.sha)
		trackedIndex := strings.LastIndex(run, check.tracked)
		untrackedIndex := strings.LastIndex(run, check.untracked)
		mainIndex := strings.LastIndex(run, `gh api "repos/${GITHUB_REPOSITORY}/git/ref/heads/main" --jq .object.sha`)
		mutationIndex := strings.LastIndex(run, check.mutation)
		cleanChecksValid := check.tracked == "" || (trackedIndex >= 0 && untrackedIndex >= 0 && trackedIndex < untrackedIndex && untrackedIndex < shaIndex)
		if run == "" || !hasToken || shaIndex < 0 || mainIndex < 0 || mutationIndex < 0 || !cleanChecksValid || shaIndex > mainIndex || mainIndex > mutationIndex {
			return fmt.Errorf("%s job %s must recheck the checkout and live main SHA immediately before %s", check.path, check.job, check.mutation)
		}
	}
	return nil
}

func validateDependabot(root string) error {
	value, err := LoadYAML(filepath.Join(root, ".github", "dependabot.yml"))
	if err != nil {
		return err
	}
	document, _ := value.(map[string]any)
	if document["version"] != float64(2) && document["version"] != 2 {
		return fmt.Errorf(".github/dependabot.yml must use version 2")
	}
	updates, ok := document["updates"].([]any)
	if !ok {
		return fmt.Errorf(".github/dependabot.yml updates must be a list")
	}
	var actual []string
	for _, raw := range updates {
		update, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf(".github/dependabot.yml contains a non-object update")
		}
		ecosystem, _ := update["package-ecosystem"].(string)
		directory, _ := update["directory"].(string)
		actual = append(actual, ecosystem+"|"+directory)
	}
	sort.Strings(actual)
	expected := []string{
		"bazel|/",
		"github-actions|/",
		"gomod|/tooling",
		"opentofu|/opentofu/live/recovery-plane",
		"opentofu|/opentofu/live/root-trust",
	}
	if !reflect.DeepEqual(actual, expected) {
		return fmt.Errorf(".github/dependabot.yml ecosystems and roots must equal the exact approved set")
	}
	return nil
}

func exactStringMap(value any, expected map[string]string) bool {
	object, ok := value.(map[string]any)
	if !ok || len(object) != len(expected) {
		return false
	}
	for key, expectedValue := range expected {
		if object[key] != expectedValue {
			return false
		}
	}
	return true
}

func identifiersAt(root, manifestPath string, keys ...string) (map[string]bool, error) {
	value, err := LoadYAML(filepath.Join(root, filepath.FromSlash(manifestPath)))
	if err != nil {
		return nil, err
	}
	current := value
	path := manifestPath
	for _, key := range keys {
		object, ok := current.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s must be an object", path)
		}
		current, ok = object[key]
		if !ok {
			return nil, fmt.Errorf("%s.%s is required", path, key)
		}
		path += "." + key
	}
	object, ok := current.(map[string]any)
	if !ok || len(object) == 0 {
		return nil, fmt.Errorf("%s must be a non-empty object", path)
	}
	identifiers := make(map[string]bool, len(object))
	for identifier := range object {
		identifiers[identifier] = true
	}
	return identifiers, nil
}

func checkReferences(value any, path string, targets map[string]map[string]bool, problems *[]string) {
	switch typed := value.(type) {
	case map[string]any:
		for key, child := range typed {
			childPath := path + "." + key
			if allowed, referenceKey := targets[key]; referenceKey {
				reference, ok := child.(string)
				if !ok || reference == "" {
					*problems = append(*problems, childPath+" must be a non-empty string reference")
				} else if !allowed[reference] {
					*problems = append(*problems, fmt.Sprintf("%s references unknown identifier %q", childPath, reference))
				}
			}
			checkReferences(child, childPath, targets, problems)
		}
	case []any:
		for index, child := range typed {
			checkReferences(child, fmt.Sprintf("%s[%d]", path, index), targets, problems)
		}
	}
}

// LoadYAML loads YAML into JSON-compatible values.
func LoadYAML(path string) (any, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var value any
	decoder := yaml.NewDecoder(bytes.NewReader(b))
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return nil, fmt.Errorf("parse %s: multiple YAML documents are not allowed", path)
		}
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return value, nil
}

func validateDocument(root, manifestPath, schemaPath string) error {
	document, err := LoadYAML(filepath.Join(root, filepath.FromSlash(manifestPath)))
	if err != nil {
		return err
	}
	data, err := json.Marshal(document)
	if err != nil {
		return fmt.Errorf("normalize %s: %w", manifestPath, err)
	}
	var jsonDocument any
	if err := json.Unmarshal(data, &jsonDocument); err != nil {
		return fmt.Errorf("normalize %s: %w", manifestPath, err)
	}
	compiler := jsonschema.NewCompiler()
	schema, err := compiler.Compile("file://" + filepath.ToSlash(filepath.Join(root, schemaPath)))
	if err != nil {
		return fmt.Errorf("compile %s: %w", schemaPath, err)
	}
	if err := schema.Validate(jsonDocument); err != nil {
		return fmt.Errorf("validate %s: %w", manifestPath, err)
	}
	var semanticProblems []string
	checkValue(jsonDocument, manifestPath, &semanticProblems)
	if manifestPath == "manifests/signing-roots.yaml" {
		semanticProblems = append(semanticProblems, validateSigningRotation(jsonDocument, manifestPath)...)
	}
	if len(semanticProblems) > 0 {
		return errors.New(strings.Join(semanticProblems, "; "))
	}
	return nil
}

func validateSigningRotation(document any, path string) []string {
	root, ok := document.(map[string]any)
	if !ok {
		return []string{path + " must be an object"}
	}
	spec, ok := root["spec"].(map[string]any)
	if !ok {
		return []string{path + ".spec must be an object"}
	}
	keys, ok := spec["keys"].(map[string]any)
	if !ok {
		return []string{path + ".spec.keys must be an object"}
	}

	type window struct {
		ref      string
		start    time.Time
		deadline time.Time
	}
	var problems []string
	for keyName, rawKey := range keys {
		key, ok := rawKey.(map[string]any)
		if !ok {
			problems = append(problems, fmt.Sprintf("%s.spec.keys.%s must be an object", path, keyName))
			continue
		}
		rotationDays, ok := key["rotationDays"].(float64)
		if !ok || rotationDays != 90 {
			problems = append(problems, fmt.Sprintf("%s.spec.keys.%s.rotationDays must equal 90", path, keyName))
			continue
		}
		versions, ok := key["versions"].(map[string]any)
		if !ok || len(versions) == 0 {
			problems = append(problems, fmt.Sprintf("%s.spec.keys.%s.versions must contain at least one declaration", path, keyName))
			continue
		}
		activeRef, _ := key["activeVersionRef"].(string)
		if _, exists := versions[activeRef]; !exists {
			problems = append(problems, fmt.Sprintf("%s.spec.keys.%s.activeVersionRef must identify a declared version", path, keyName))
		}

		windows := make([]window, 0, len(versions))
		for versionRef, rawVersion := range versions {
			version, ok := rawVersion.(map[string]any)
			if !ok {
				problems = append(problems, fmt.Sprintf("%s.spec.keys.%s.versions.%s must be an object", path, keyName, versionRef))
				continue
			}
			startText, _ := version["activationWindowStart"].(string)
			deadlineText, _ := version["rotationDeadline"].(string)
			start, startErr := time.Parse(time.RFC3339, startText)
			deadline, deadlineErr := time.Parse(time.RFC3339, deadlineText)
			if startErr != nil || deadlineErr != nil || start.Format(time.RFC3339) != startText || deadline.Format(time.RFC3339) != deadlineText {
				problems = append(problems, fmt.Sprintf("%s.spec.keys.%s.versions.%s must use canonical UTC RFC3339 timestamps", path, keyName, versionRef))
				continue
			}
			if versionRef != "v"+start.Format("20060102") {
				problems = append(problems, fmt.Sprintf("%s.spec.keys.%s.versions.%s must match its activation date", path, keyName, versionRef))
			}
			if start.Hour() != 0 || start.Minute() != 0 || start.Second() != 0 || start.Nanosecond() != 0 {
				problems = append(problems, fmt.Sprintf("%s.spec.keys.%s.versions.%s must start at midnight UTC so its reference immutably binds the window", path, keyName, versionRef))
			}
			if deadline.Sub(start) != time.Duration(rotationDays)*24*time.Hour {
				problems = append(problems, fmt.Sprintf("%s.spec.keys.%s.versions.%s must declare exactly a 90-day activation window", path, keyName, versionRef))
			}
			windows = append(windows, window{ref: versionRef, start: start, deadline: deadline})
		}

		sort.Slice(windows, func(i, j int) bool { return windows[i].start.Before(windows[j].start) })
		for index := 1; index < len(windows); index++ {
			previous := windows[index-1]
			current := windows[index]
			if !current.start.After(previous.start) {
				problems = append(problems, fmt.Sprintf("%s.spec.keys.%s version activation times must be strictly increasing", path, keyName))
			}
			overlap := previous.deadline.Sub(current.start)
			if overlap <= 0 {
				problems = append(problems, fmt.Sprintf("%s.spec.keys.%s versions %s and %s must overlap so activation cannot create a signing outage", path, keyName, previous.ref, current.ref))
			} else if overlap > 24*time.Hour {
				problems = append(problems, fmt.Sprintf("%s.spec.keys.%s versions %s and %s exceed the maximum 24-hour rotation overlap", path, keyName, previous.ref, current.ref))
			}
		}
	}
	return problems
}

func checkValue(value any, path string, problems *[]string) {
	switch typed := value.(type) {
	case map[string]any:
		if valueFrom, ok := typed["valueFrom"].(map[string]any); ok {
			env, _ := valueFrom["env"].(string)
			if !envNamePattern.MatchString(env) {
				*problems = append(*problems, fmt.Sprintf("%s has invalid valueFrom.env", path))
			}
		}
		for key, child := range typed {
			if secretKeyPattern.MatchString(key) {
				if text, ok := child.(string); ok && text != "" {
					*problems = append(*problems, fmt.Sprintf("%s.%s contains a plaintext sensitive value", path, key))
				}
			}
			checkValue(child, path+"."+key, problems)
		}
	case []any:
		seen := map[string]bool{}
		for index, child := range typed {
			if object, ok := child.(map[string]any); ok {
				for _, key := range []string{"id", "name"} {
					if id, ok := object[key].(string); ok && id != "" {
						identity := key + ":" + id
						if seen[identity] {
							*problems = append(*problems, fmt.Sprintf("%s contains duplicate %s %q", path, key, id))
						}
						seen[identity] = true
					}
				}
			}
			checkValue(child, fmt.Sprintf("%s[%d]", path, index), problems)
		}
	}
}

func validateTree(root string) error {
	expected := make(map[string]bool, len(expectedFiles)+1)
	for _, path := range expectedFiles {
		expected[path] = true
	}
	expected["BLUEPRINT.md"] = true
	actual := map[string]bool{}
	var symlinks []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		if entry.IsDir() {
			base := entry.Name()
			if rel == ".git" || strings.HasPrefix(rel, ".git/") || base == ".terraform" || strings.HasPrefix(base, "bazel-") {
				return filepath.SkipDir
			}
			return nil
		}
		if ephemeral(rel) {
			return nil
		}
		if entry.Type()&fs.ModeSymlink != 0 {
			symlinks = append(symlinks, rel)
		}
		actual[rel] = true
		return nil
	})
	if err != nil {
		return err
	}
	var missing, unexpected []string
	for path := range expected {
		if !actual[path] {
			missing = append(missing, path)
		}
	}
	for path := range actual {
		if !expected[path] {
			unexpected = append(unexpected, path)
		}
	}
	sort.Strings(missing)
	sort.Strings(unexpected)
	sort.Strings(symlinks)
	if len(missing) != 0 || len(unexpected) != 0 || len(symlinks) != 0 {
		return fmt.Errorf("blueprint tree mismatch: missing=%v unexpected=%v symlinks=%v", missing, unexpected, symlinks)
	}
	return nil
}

func validateTrackedPaths(root string) error {
	if _, err := os.Stat(filepath.Join(root, ".git")); err != nil {
		return nil
	}
	command := exec.Command("git", "-C", root, "ls-files", "-z")
	output, err := command.Output()
	if err != nil {
		return fmt.Errorf("enumerate tracked source: %w", err)
	}
	allowed := make(map[string]bool, len(expectedFiles)+1)
	for _, path := range expectedFiles {
		allowed[path] = true
	}
	allowed["BLUEPRINT.md"] = true
	var unexpected []string
	for _, path := range strings.Split(string(output), "\x00") {
		if path != "" && !allowed[filepath.ToSlash(path)] {
			unexpected = append(unexpected, filepath.ToSlash(path))
		}
	}
	sort.Strings(unexpected)
	if len(unexpected) != 0 {
		return fmt.Errorf("tracked files outside blueprint: %v", unexpected)
	}
	return nil
}

func ephemeral(path string) bool {
	base := filepath.Base(path)
	return base == ".DS_Store" || base == "MODULE.bazel.lock" || strings.HasPrefix(base, "bazel-") || path == "tooling/bootstrapctl" || base == ".terraform.lock.hcl" || strings.HasSuffix(base, ".tfplan") ||
		strings.HasSuffix(base, ".tfplan.json") || strings.HasSuffix(base, ".evidence.json") ||
		strings.HasSuffix(base, ".pyc") || strings.Contains(path, "/__pycache__/")
}

func loadCompilerDocuments(root string) (map[string]map[string]any, error) {
	documents := make(map[string]map[string]any, len(manifestSchemas))
	paths := make([]string, 0, len(manifestSchemas))
	for path := range manifestSchemas {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	for _, path := range paths {
		value, err := LoadYAML(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			return nil, err
		}
		document, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s must be an object", path)
		}
		documents[path] = document
	}
	return documents, nil
}

func collectEnvironmentReferences(value any, path string, references map[string]int) {
	switch typed := value.(type) {
	case map[string]any:
		if valueFrom, ok := typed["valueFrom"].(map[string]any); ok {
			if env, ok := valueFrom["env"].(string); ok {
				references[env]++
			}
		}
		for key, child := range typed {
			collectEnvironmentReferences(child, path+"."+key, references)
		}
	case []any:
		for index, child := range typed {
			collectEnvironmentReferences(child, fmt.Sprintf("%s[%d]", path, index), references)
		}
	}
}

func loadExactStringMap(path string) (map[string]string, error) {
	data, err := readBoundedJSON(path)
	if err != nil {
		return nil, err
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return nil, err
	}
	var values map[string]string
	if err := decodeExactJSON(data, &values); err != nil {
		return nil, err
	}
	if values == nil {
		return nil, fmt.Errorf("JSON document must be an object")
	}
	return values, nil
}

func loadRecoveryContext(path string) (recoveryContext, error) {
	data, err := readBoundedJSON(path)
	if err != nil {
		return recoveryContext{}, fmt.Errorf("load recovery context: %w", err)
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return recoveryContext{}, fmt.Errorf("load recovery context: %w", err)
	}
	var context recoveryContext
	if err := decodeExactJSON(data, &context); err != nil {
		return recoveryContext{}, fmt.Errorf("load recovery context: %w", err)
	}
	return context, nil
}

func readBoundedJSON(path string) ([]byte, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s must be a regular file", path)
	}
	const maximumJSONBytes = 1024 * 1024
	if info.Size() > maximumJSONBytes {
		return nil, fmt.Errorf("%s exceeds %d bytes", path, maximumJSONBytes)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, fmt.Errorf("%s is empty", path)
	}
	return data, nil
}

func decodeExactJSON(data []byte, destination any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode exact JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("decode exact JSON: trailing data is not allowed")
	}
	return nil
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder); err != nil {
		return fmt.Errorf("decode exact JSON: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode exact JSON: trailing data is not allowed")
		}
		return fmt.Errorf("decode exact JSON: %w", err)
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key must be a string")
			}
			if seen[key] {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = true
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim('}') {
			return fmt.Errorf("object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil {
			return err
		}
		if closing != json.Delim(']') {
			return fmt.Errorf("array is not closed")
		}
	default:
		return fmt.Errorf("unexpected delimiter %q", delimiter)
	}
	return nil
}

func protectOutputTarget(root, valuesPath, contextPath, outputPath string) error {
	output, err := filepath.Abs(outputPath)
	if err != nil {
		return err
	}
	for label, path := range map[string]string{"values": valuesPath, "context": contextPath} {
		if path == "" {
			continue
		}
		absolute, err := filepath.Abs(path)
		if err != nil {
			return err
		}
		if output == absolute {
			return fmt.Errorf("output must not overwrite %s input", label)
		}
	}
	relative, err := filepath.Rel(root, output)
	if err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return fmt.Errorf("output must be outside the closed blueprint repository")
	}
	return nil
}

func writePrivateAtomic(path string, data []byte) (returnErr error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	directory := filepath.Dir(absolute)
	info, err := os.Stat(directory)
	if err != nil {
		return fmt.Errorf("inspect output directory: %w", err)
	}
	if !info.IsDir() {
		return fmt.Errorf("output parent is not a directory")
	}
	temporary, err := os.CreateTemp(directory, ".bootstrap-vars-*")
	if err != nil {
		return fmt.Errorf("create private output: %w", err)
	}
	temporaryName := temporary.Name()
	defer func() {
		_ = temporary.Close()
		if returnErr != nil {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return fmt.Errorf("protect private output: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		return fmt.Errorf("write private output: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		return fmt.Errorf("sync private output: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close private output: %w", err)
	}
	if err := os.Rename(temporaryName, absolute); err != nil {
		return fmt.Errorf("publish private output: %w", err)
	}
	if err := os.Chmod(absolute, 0o600); err != nil {
		return fmt.Errorf("protect published output: %w", err)
	}
	return nil
}

func (c *compiler) lookup(file string, path ...string) any {
	current, ok := c.documents[file]
	if !ok {
		c.problem("compiler document %s is unavailable", file)
		return nil
	}
	var value any = current
	for _, key := range path {
		object, ok := value.(map[string]any)
		if !ok {
			c.problem("%s.%s must be an object", file, strings.Join(path, "."))
			return nil
		}
		value, ok = object[key]
		if !ok {
			c.problem("%s.%s is required", file, strings.Join(path, "."))
			return nil
		}
	}
	return value
}

func (c *compiler) validateContracts() {
	const (
		trust      = "manifests/trust-anchors.yaml"
		state      = "manifests/state-backends.yaml"
		federation = "manifests/identity-federation.yaml"
		signing    = "manifests/signing-roots.yaml"
		audit      = "manifests/audit-roots.yaml"
		breakGlass = "manifests/break-glass-roles.yaml"
		recovery   = "manifests/recovery-policy.yaml"
	)
	envelopes := map[string]struct {
		kind string
		name string
	}{
		trust:      {"TrustAnchorSet", "root-trust"},
		state:      {"StateBackendSet", "bootstrap-state"},
		federation: {"IdentityFederation", "bootstrap-identity"},
		signing:    {"SigningRootSet", "bootstrap-signing"},
		audit:      {"AuditRootSet", "bootstrap-audit"},
		breakGlass: {"BreakGlassRoleSet", "bootstrap-break-glass"},
		recovery:   {"RecoveryPolicy", "bootstrap-recovery"},
	}
	for _, file := range sortedKeys(envelopes) {
		c.expect(file, APIVersion, "apiVersion")
		c.expect(file, envelopes[file].kind, "kind")
		c.expect(file, envelopes[file].name, "metadata", "name")
	}

	c.expectEnvName(trust, "GCP_ORGANIZATION_ID", "spec", "organization")
	c.expectEnvName(trust, "GCP_BILLING_ACCOUNT_ID", "spec", "billingAccount")
	c.expectKeys(trust, []string{"state-root", "audit-root", "identity-root", "signing-root", "recovery-root"}, "spec", "projects")
	projectContracts := map[string]struct {
		env    string
		plane  string
		region string
	}{
		"state-root":    {"GCP_STATE_ROOT_PROJECT_ID", "root-trust", "us-central1"},
		"audit-root":    {"GCP_AUDIT_ROOT_PROJECT_ID", "root-trust", "us-central1"},
		"identity-root": {"GCP_IDENTITY_ROOT_PROJECT_ID", "root-trust", "us-central1"},
		"signing-root":  {"GCP_SIGNING_ROOT_PROJECT_ID", "root-trust", "us-central1"},
		"recovery-root": {"GCP_RECOVERY_ROOT_PROJECT_ID", "recovery", "us-east4"},
	}
	for _, name := range sortedKeys(projectContracts) {
		contract := projectContracts[name]
		c.expectEnvName(trust, contract.env, "spec", "projects", name, "projectId")
		c.expect(trust, contract.plane, "spec", "projects", name, "plane")
		c.expect(trust, contract.region, "spec", "projects", name, "region")
	}
	c.expectEnvName(trust, "ROOT_TRUST_ADMIN_GROUP", "spec", "administratorPrincipals", "root")
	c.expectEnvName(trust, "RECOVERY_ADMIN_GROUP", "spec", "administratorPrincipals", "recovery")
	c.expectEnvName(trust, "SECURITY_APPROVER_GROUP", "spec", "administratorPrincipals", "security")
	c.expectStrings(trust, []string{"us-central1", "us-east4"}, "spec", "geographicalBoundary", "allowedLocations")
	c.expect(trust, "us-central1", "spec", "geographicalBoundary", "defaultLocation")
	c.expect(trust, "us-east4", "spec", "geographicalBoundary", "recoveryLocation")

	c.expectKeys(state, []string{"root-trust", "recovery-plane"}, "spec", "backends")
	backendContracts := map[string]struct {
		project, location, bucketEnv, keyEnv                             string
		replicaProject, replicaLocation, replicaBucketEnv, replicaKeyEnv string
	}{
		"root-trust": {
			"state-root", "us-central1", "ROOT_TRUST_STATE_BUCKET", "ROOT_TRUST_STATE_KMS_KEY",
			"recovery-root", "us-east4", "ROOT_TRUST_STATE_REPLICA_BUCKET", "ROOT_TRUST_STATE_REPLICA_KMS_KEY",
		},
		"recovery-plane": {
			"recovery-root", "us-east4", "RECOVERY_STATE_BUCKET", "RECOVERY_STATE_KMS_KEY",
			"state-root", "us-central1", "RECOVERY_STATE_REPLICA_BUCKET", "RECOVERY_STATE_REPLICA_KMS_KEY",
		},
	}
	for _, name := range sortedKeys(backendContracts) {
		contract := backendContracts[name]
		base := []string{"spec", "backends", name}
		c.expect(state, contract.project, append(base, "projectRef")...)
		c.expect(state, name, append(base, "prefix")...)
		c.expect(state, contract.location, append(base, "location")...)
		c.expectEnvName(state, contract.bucketEnv, append(base, "bucketName")...)
		c.expectEnvName(state, contract.keyEnv, append(base, "encryption", "keyName")...)
		c.expect(state, "HSM", append(base, "encryption", "protectionLevel")...)
		c.expect(state, contract.replicaProject, append(base, "replica", "projectRef")...)
		c.expect(state, contract.replicaLocation, append(base, "replica", "location")...)
		c.expectEnvName(state, contract.replicaBucketEnv, append(base, "replica", "bucketName")...)
		c.expectEnvName(state, contract.replicaKeyEnv, append(base, "replica", "encryption", "keyName")...)
		c.expect(state, "HSM", append(base, "replica", "encryption", "protectionLevel")...)
		c.expect(state, true, append(base, "controls", "uniformBucketLevelAccess")...)
		c.expect(state, "enforced", append(base, "controls", "publicAccessPrevention")...)
		c.expect(state, true, append(base, "controls", "versioning")...)
		c.expect(state, 30, append(base, "controls", "softDeleteRetentionDays")...)
		c.expect(state, true, append(base, "controls", "deletionProtection")...)
		c.expect(state, true, append(base, "controls", "nativeLocking")...)
	}

	c.expect(federation, "identity-root", "spec", "workforce", "projectRef")
	c.expect(federation, "global", "spec", "workforce", "location")
	c.expect(federation, "oidc", "spec", "workforce", "protocol")
	c.expectEnvName(federation, "WORKFORCE_OIDC_ISSUER_URI", "spec", "workforce", "issuerUri")
	c.expectEnvName(federation, "WORKFORCE_OIDC_CLIENT_ID", "spec", "workforce", "clientId")
	c.expectEnvName(federation, workforceSecretReference, "spec", "workforce", "clientSecret")
	c.expectEnvName(federation, "WORKFORCE_ADMIN_GROUP", "spec", "workforce", "administratorGroup")
	c.expect(federation, "assertion.sub", "spec", "workforce", "attributeMapping", "subject")
	c.expect(federation, "assertion.name", "spec", "workforce", "attributeMapping", "displayName")
	c.expect(federation, "assertion.groups", "spec", "workforce", "attributeMapping", "groups")
	c.expectKeys(federation, []string{"github", "buildkite", "gitops"}, "spec", "workloadIdentityProviders")

	githubBase := []string{"spec", "workloadIdentityProviders", "github"}
	c.validateProviderContract(federation, githubBase, "github", "identity-root", map[string]string{
		"plan":     "state-root",
		"apply":    "state-root",
		"recovery": "recovery-root",
	})
	c.expectEnvName(federation, "GITHUB_OIDC_ISSUER_URI", append(githubBase, "issuerUri")...)
	c.expectEnvName(federation, "GITHUB_OIDC_AUDIENCE", append(githubBase, "allowedAudience")...)
	c.expectEnvName(federation, "GITHUB_REPOSITORY_OWNER_ID", append(githubBase, "requiredClaims", "repository_owner_id")...)
	c.expectEnvName(federation, "GITHUB_REPOSITORY_ID", append(githubBase, "requiredClaims", "repository_id")...)
	c.expect(federation, "refs/heads/main", append(githubBase, "requiredClaims", "ref", "literal")...)
	c.expectEnvName(federation, "GITHUB_APPLY_WORKFLOW_REF", append(githubBase, "requiredClaims", "workflow_ref")...)
	c.expectKeys(federation, []string{"plan", "apply", "recovery"}, append(githubBase, "serviceAccounts")...)
	c.expect(federation, "bootstrap-plan", append(githubBase, "serviceAccounts", "plan", "accountId")...)
	c.expectStrings(federation, []string{
		"custom/bootstrapAuditPlanRead",
		"custom/bootstrapOrganizationPlanRead",
		"custom/bootstrapRecoveryPlanObjectRead",
		"custom/bootstrapRecoveryPlanRead",
		"custom/bootstrapStatePlanLock",
		"roles/browser",
		"roles/cloudkms.viewer",
		"roles/iam.roleViewer",
		"roles/iam.securityReviewer",
		"roles/iam.serviceAccountViewer",
		"roles/iam.workforcePoolViewer",
		"roles/privilegedaccessmanager.viewer",
		"roles/serviceusage.serviceUsageViewer",
		"roles/storage.legacyBucketReader",
		"roles/storage.objectViewer",
		"roles/storagetransfer.viewer",
	}, append(githubBase, "serviceAccounts", "plan", "roles")...)
	c.expect(federation, "bootstrap-apply", append(githubBase, "serviceAccounts", "apply", "accountId")...)
	c.expectStrings(federation, []string{
		"custom/bootstrapOrganizationIamApply",
		"roles/cloudkms.admin",
		"roles/iam.organizationRoleAdmin",
		"roles/iam.roleAdmin",
		"roles/iam.serviceAccountAdmin",
		"roles/iam.serviceAccountUser",
		"roles/iam.workforcePoolAdmin",
		"roles/logging.configWriter",
		"roles/privilegedaccessmanager.admin",
		"roles/resourcemanager.projectIamAdmin",
		"roles/serviceusage.serviceUsageAdmin",
		"roles/storage.admin",
		"roles/storage.objectAdmin",
		"roles/storage.objectCreator",
		"roles/storagetransfer.user",
	}, append(githubBase, "serviceAccounts", "apply", "roles")...)
	c.expect(federation, "bootstrap-recovery", append(githubBase, "serviceAccounts", "recovery", "accountId")...)
	c.expectStrings(federation, []string{
		"custom/bootstrapRecoverySigningMetadata",
		"custom/bootstrapRecoverySinkRead",
		"roles/cloudkms.signerVerifier",
		"roles/storage.legacyBucketReader",
		"roles/storage.objectViewer",
	}, append(githubBase, "serviceAccounts", "recovery", "roles")...)

	buildkiteBase := []string{"spec", "workloadIdentityProviders", "buildkite"}
	c.validateProviderContract(federation, buildkiteBase, "buildkite", "identity-root", map[string]string{"bootstrap": "state-root"})
	c.expectEnvName(federation, "BUILDKITE_OIDC_ISSUER_URI", append(buildkiteBase, "issuerUri")...)
	c.expectEnvName(federation, "BUILDKITE_OIDC_AUDIENCE", append(buildkiteBase, "allowedAudience")...)
	c.expectEnvName(federation, "BUILDKITE_ORGANIZATION_SLUG", append(buildkiteBase, "requiredClaims", "organization_slug")...)
	c.expectEnvName(federation, "BUILDKITE_PIPELINE_SLUG", append(buildkiteBase, "requiredClaims", "pipeline_slug")...)
	c.expectEnvName(federation, "BUILDKITE_PIPELINE_ID", append(buildkiteBase, "requiredClaims", "pipeline_id")...)
	c.expect(federation, "main", append(buildkiteBase, "requiredClaims", "build_branch", "literal")...)
	c.expect(federation, "bootstrap-ring0-signing", append(buildkiteBase, "requiredClaims", "step_key", "literal")...)
	c.expectKeys(federation, []string{"bootstrap"}, append(buildkiteBase, "serviceAccounts")...)
	c.expect(federation, "buildkite-bootstrap", append(buildkiteBase, "serviceAccounts", "bootstrap", "accountId")...)
	c.expectStrings(federation, []string{"roles/cloudkms.signerVerifier"}, append(buildkiteBase, "serviceAccounts", "bootstrap", "roles")...)

	gitopsBase := []string{"spec", "workloadIdentityProviders", "gitops"}
	c.validateProviderContract(federation, gitopsBase, "gitops", "identity-root", map[string]string{"bootstrap": "recovery-root"})
	c.expectEnvName(federation, "GITOPS_OIDC_ISSUER_URI", append(gitopsBase, "issuerUri")...)
	c.expectEnvName(federation, "GITOPS_OIDC_AUDIENCE", append(gitopsBase, "allowedAudience")...)
	c.expectEnvName(federation, "GITOPS_REPOSITORY", append(gitopsBase, "requiredClaims", "repository")...)
	c.expect(federation, "refs/heads/main", append(gitopsBase, "requiredClaims", "ref", "literal")...)
	c.expectEnvName(federation, "GITOPS_IMMUTABLE_SUBJECT", append(gitopsBase, "requiredClaims", "subject")...)
	c.expectKeys(federation, []string{"bootstrap"}, append(gitopsBase, "serviceAccounts")...)
	c.expect(federation, "gitops-bootstrap", append(gitopsBase, "serviceAccounts", "bootstrap", "accountId")...)
	c.expectStrings(federation, []string{}, append(gitopsBase, "serviceAccounts", "bootstrap", "roles")...)

	c.expect(signing, "signing-root", "spec", "projectRef")
	c.expect(signing, "us-central1", "spec", "location")
	c.expect(signing, "bootstrap-signing", "spec", "keyRing")
	c.expectKeys(signing, []string{"bootstrap-handoff", "audit-anchor", "recovery-evidence"}, "spec", "keys")
	administratorRefs := c.lookup(signing, "spec", "administrators")
	if items, ok := administratorRefs.([]any); !ok || len(items) != 2 {
		c.problem("%s.spec.administrators must contain exactly two references", signing)
	}
	expectedAdministrators := []string{"KMS_ADMIN_PRINCIPAL_1", "KMS_ADMIN_PRINCIPAL_2"}
	for index, expected := range expectedAdministrators {
		c.expectListEnvName(signing, expected, index, "spec", "administrators")
	}
	signerContracts := map[string]string{
		"bootstrap-handoff": "BOOTSTRAP_HANDOFF_SIGNER",
		"audit-anchor":      "AUDIT_ANCHOR_SIGNER",
		"recovery-evidence": "RECOVERY_EVIDENCE_SIGNER",
	}
	for _, name := range sortedKeys(signerContracts) {
		base := []string{"spec", "keys", name}
		c.expect(signing, "ASYMMETRIC_SIGN", append(base, "purpose")...)
		c.expect(signing, "EC_SIGN_P256_SHA256", append(base, "algorithm")...)
		c.expect(signing, "HSM", append(base, "protectionLevel")...)
		c.expect(signing, 90, append(base, "rotationDays")...)
		activeVersionRef := c.stringAt(signing, append(base, "activeVersionRef")...)
		if _, declared := c.objectAt(signing, append(base, "versions")...)[activeVersionRef]; !declared {
			c.problem("%s.%s.activeVersionRef must identify a declared version", signing, strings.Join(base, "."))
		}
		c.expect(signing, true, append(base, "deletionProtection")...)
		if items, ok := c.lookup(signing, append(base, "signers")...).([]any); !ok || len(items) != 1 {
			c.problem("%s.%s.signers must contain exactly one reference", signing, strings.Join(base, "."))
		}
		c.expectListEnvName(signing, signerContracts[name], 0, append(base, "signers")...)
	}

	c.expectEnvName(audit, "GCP_ORGANIZATION_ID", "spec", "organization")
	c.expect(audit, "audit-root", "spec", "projectRef")
	c.expect(audit, 2555, "spec", "retentionDays")
	c.expect(audit, true, "spec", "lockAfterQualification", "enabled")
	c.expect(audit, true, "spec", "lockAfterQualification", "qualificationEvidenceRequired")
	auditLocked := c.boolAt(audit, "spec", "lockAfterQualification", "locked")
	if auditLocked {
		expectedKeyRef := "audit-anchor:" + c.stringAt(signing, "spec", "keys", "audit-anchor", "activeVersionRef")
		if c.stringAt(audit, "spec", "lockAfterQualification", "qualificationEvidence", "signingKeyRef") != expectedKeyRef {
			c.problem("%s.spec.lockAfterQualification.qualificationEvidence.signingKeyRef must equal the active audit-anchor version %s", audit, expectedKeyRef)
		}
		zeroDigest := "sha256:" + strings.Repeat("0", 64)
		for _, field := range []string{"artifactSha256", "signatureSha256"} {
			if c.stringAt(audit, "spec", "lockAfterQualification", "qualificationEvidence", field) == zeroDigest {
				c.problem("%s.spec.lockAfterQualification.qualificationEvidence.%s must not be the all-zero digest", audit, field)
			}
		}
		if c.stringAt(audit, "spec", "lockAfterQualification", "qualificationEvidence", "qualifiedSourceSha") == strings.Repeat("0", 40) {
			c.problem("%s.spec.lockAfterQualification.qualificationEvidence.qualifiedSourceSha must not be the all-zero SHA", audit)
		}
		qualifiedAt := c.stringAt(audit, "spec", "lockAfterQualification", "qualificationEvidence", "qualifiedAt")
		parsedQualifiedAt, err := time.Parse(time.RFC3339, qualifiedAt)
		if err != nil || parsedQualifiedAt.Format(time.RFC3339) != qualifiedAt {
			c.problem("%s.spec.lockAfterQualification.qualificationEvidence.qualifiedAt must be canonical UTC RFC3339", audit)
		}
	}
	c.expect(audit, "audit-root", "spec", "logBuckets", "primary", "projectRef")
	c.expect(audit, "us-central1", "spec", "logBuckets", "primary", "location")
	c.expectEnvName(audit, "AUDIT_PRIMARY_KMS_KEY", "spec", "logBuckets", "primary", "encryptionKeyName")
	c.expect(audit, "recovery-root", "spec", "logBuckets", "recovery", "projectRef")
	c.expect(audit, "us-east4", "spec", "logBuckets", "recovery", "location")
	c.expectEnvName(audit, "AUDIT_RECOVERY_KMS_KEY", "spec", "logBuckets", "recovery", "encryptionKeyName")
	auditSinkContracts := map[string]struct {
		name, bucket, filter string
	}{
		"admin-activity":           {"bootstrap-admin-activity", "primary", `log_id("cloudaudit.googleapis.com/activity")`},
		"admin-activity-recovery":  {"bootstrap-admin-activity-recovery", "recovery", `log_id("cloudaudit.googleapis.com/activity")`},
		"security-events":          {"bootstrap-security-events", "primary", `severity>=WARNING OR protoPayload.serviceName="iam.googleapis.com"`},
		"security-events-recovery": {"bootstrap-security-events-recovery", "recovery", `severity>=WARNING OR protoPayload.serviceName="iam.googleapis.com"`},
	}
	c.expectKeys(audit, sortedKeys(auditSinkContracts), "spec", "aggregatedSinks")
	for _, name := range sortedKeys(auditSinkContracts) {
		contract := auditSinkContracts[name]
		c.expect(audit, contract.name, "spec", "aggregatedSinks", name, "sinkName")
		c.expect(audit, contract.bucket, "spec", "aggregatedSinks", name, "destinationBucketRef")
		c.expect(audit, true, "spec", "aggregatedSinks", name, "includeChildren")
		c.expect(audit, contract.filter, "spec", "aggregatedSinks", name, "filter")
	}
	c.expectEnvName(audit, "AUDIT_SECURITY_READER_GROUP", "spec", "readers", "security")
	c.expectEnvName(audit, "AUDIT_COMPLIANCE_READER_GROUP", "spec", "readers", "compliance")

	c.expect(breakGlass, "identity-root", "spec", "projectRef")
	c.expect(breakGlass, "global", "spec", "location")
	c.expectEnvName(breakGlass, "BREAK_GLASS_REQUESTER_1", "spec", "requesters", "primary")
	c.expectEnvName(breakGlass, "BREAK_GLASS_REQUESTER_2", "spec", "requesters", "secondary")
	c.expectEnvName(breakGlass, "BREAK_GLASS_APPROVER_1", "spec", "approvers", "security-primary")
	c.expectEnvName(breakGlass, "BREAK_GLASS_APPROVER_2", "spec", "approvers", "security-secondary")
	c.expectEnvName(breakGlass, "BREAK_GLASS_NOTIFICATION_RECIPIENT", "spec", "notificationRecipients", "security-operations")
	c.expectKeys(breakGlass, []string{"identity-root-administration", "recovery-root-administration", "root-trust-administration", "signing-root-administration"}, "spec", "entitlements")
	for _, name := range []string{"identity-root-administration", "recovery-root-administration", "root-trust-administration", "signing-root-administration"} {
		base := []string{"spec", "entitlements", name}
		c.expect(breakGlass, 7200, append(base, "maxDurationSeconds")...)
		c.expect(breakGlass, 2, append(base, "approval", "requiredApprovals")...)
		c.expect(breakGlass, true, append(base, "approval", "justificationRequired")...)
		c.expect(breakGlass, false, append(base, "approval", "allowSelfApproval")...)
		c.expect(breakGlass, false, append(base, "standingAccess")...)
	}
	c.expect(breakGlass, "state-root", "spec", "entitlements", "root-trust-administration", "targetProjectRef")
	c.expectStrings(breakGlass, []string{"roles/resourcemanager.projectIamAdmin", "roles/iam.securityAdmin"}, "spec", "entitlements", "root-trust-administration", "roles")
	c.expect(breakGlass, "signing-root", "spec", "entitlements", "signing-root-administration", "targetProjectRef")
	c.expectStrings(breakGlass, []string{"roles/cloudkms.admin"}, "spec", "entitlements", "signing-root-administration", "roles")
	c.expect(breakGlass, "identity-root", "spec", "entitlements", "identity-root-administration", "targetProjectRef")
	c.expectStrings(breakGlass, []string{"roles/iam.workloadIdentityPoolAdmin", "roles/iam.serviceAccountAdmin", "roles/resourcemanager.projectIamAdmin", "roles/serviceusage.serviceUsageAdmin"}, "spec", "entitlements", "identity-root-administration", "roles")
	c.expect(breakGlass, "recovery-root", "spec", "entitlements", "recovery-root-administration", "targetProjectRef")
	c.expectStrings(breakGlass, []string{"roles/cloudkms.admin", "roles/iam.roleAdmin", "roles/iam.serviceAccountAdmin", "roles/logging.admin", "roles/resourcemanager.projectIamAdmin", "roles/serviceusage.serviceUsageAdmin", "roles/storage.admin", "roles/storagetransfer.user"}, "spec", "entitlements", "recovery-root-administration", "roles")

	c.expect(recovery, "us-central1", "spec", "primaryRegion")
	c.expect(recovery, "us-east4", "spec", "recoveryRegion")
	c.expect(recovery, "root-trust", "spec", "rootTrustBackendRef")
	c.expect(recovery, "recovery-plane", "spec", "recoveryBackendRef")
	c.expect(recovery, "recovery-evidence", "spec", "signingRootRef")
	c.expect(recovery, "recovery/restore-manifest.yaml", "spec", "restoreManifestPath")
	c.expect(recovery, 24, "spec", "objectives", "recoveryPointHours")
	c.expect(recovery, 8, "spec", "objectives", "recoveryTimeHours")
	c.expect(recovery, 3, "spec", "exports", "minimumRetainedStateGenerations")
	c.expectEnvName(recovery, "RECOVERY_EXPORT_KMS_KEY", "spec", "exports", "encryptionKeyName")
	c.expect(recovery, true, "spec", "exports", "includePublicTrustMetadata")
	c.expect(recovery, false, "spec", "exports", "includePrivateKeyMaterial")
	c.expect(recovery, 2190, "spec", "evidence", "maximumAgeHours")
	c.expect(recovery, "EC_SIGN_P256_SHA256", "spec", "evidence", "signatureAlgorithm")
	c.expect(recovery, true, "spec", "evidence", "requireManifestDigest")
	c.expect(recovery, "quarterly", "spec", "drills", "cadence")
	c.expect(recovery, true, "spec", "drills", "offlineByDefault")
	c.expect(recovery, "read-only", "spec", "drills", "connectedMode")
	c.expect(recovery, 2555, "spec", "drills", "evidenceRetentionDays")
	c.expect(recovery, true, "spec", "isolation", "required")
	c.expect(recovery, true, "spec", "isolation", "denyPrimaryPlaneDependencies")
	c.expect(recovery, true, "spec", "isolation", "networkIsolationRequired")
	c.expectEnvName(recovery, "RECOVERY_ADMIN_GROUP", "spec", "isolation", "recoveryAdministrator")
	c.expectEnvName(recovery, "RECOVERY_CONTACT_1", "spec", "independentContacts", "primary")
	c.expectEnvName(recovery, "RECOVERY_CONTACT_2", "spec", "independentContacts", "secondary")
}

func (c *compiler) validateProviderContract(file string, base []string, platform, projectRef string, serviceAccountProjectRefs map[string]string) {
	c.expect(file, platform, append(base, "platform")...)
	c.expect(file, projectRef, append(base, "projectRef")...)
	c.expect(file, "assertion.sub", append(base, "subjectClaim")...)
	serviceAccounts := c.objectAt(file, append(base, "serviceAccounts")...)
	for _, name := range sortedKeys(serviceAccounts) {
		expectedProjectRef, ok := serviceAccountProjectRefs[name]
		if !ok {
			c.problem("%s.%s.serviceAccounts contains unexpected account %s", file, strings.Join(base, "."), name)
			continue
		}
		c.expect(file, expectedProjectRef, append(base, "serviceAccounts", name, "projectRef")...)
	}
}

func (c *compiler) expectListEnvName(file, expected string, index int, path ...string) {
	items, ok := c.lookup(file, path...).([]any)
	if !ok || index < 0 || index >= len(items) {
		c.problem("%s.%s[%d] is required", file, strings.Join(path, "."), index)
		return
	}
	reference, ok := items[index].(map[string]any)
	if !ok {
		c.problem("%s.%s[%d] must be an external value reference", file, strings.Join(path, "."), index)
		return
	}
	valueFrom, ok := reference["valueFrom"].(map[string]any)
	if !ok || valueFrom["env"] != expected {
		c.problem("%s.%s[%d] must reference %s", file, strings.Join(path, "."), index, expected)
	}
}

func (c *compiler) rootTrustVariables() map[string]any {
	const (
		trust      = "manifests/trust-anchors.yaml"
		state      = "manifests/state-backends.yaml"
		federation = "manifests/identity-federation.yaml"
		signing    = "manifests/signing-roots.yaml"
		audit      = "manifests/audit-roots.yaml"
		breakGlass = "manifests/break-glass-roles.yaml"
	)

	projects := map[string]string{
		"root_state": c.projectID("state-root"),
		"recovery":   c.projectID("recovery-root"),
		"audit":      c.projectID("audit-root"),
		"identity":   c.projectID("identity-root"),
		"signing":    c.projectID("signing-root"),
	}
	projectObjects := map[string]any{}
	projectIDs := make([]string, 0, len(projects))
	for _, name := range sortedKeys(projects) {
		id := projects[name]
		c.requirePattern("project "+name, id, projectIDPattern)
		projectObjects[name] = map[string]any{"id": id, "name": id}
		projectIDs = append(projectIDs, id)
	}
	c.requireDistinct("root project IDs", projectIDs)

	stateBackends := map[string]any{}
	for _, backend := range []struct {
		manifestName string
		outputName   string
	}{
		{"root-trust", "root_trust"},
		{"recovery-plane", "recovery_plane"},
	} {
		base := []string{"spec", "backends", backend.manifestName}
		bucket := c.resolvedAt(state, append(base, "bucketName")...)
		replicaBucket := c.resolvedAt(state, append(base, "replica", "bucketName")...)
		keyName := c.resolvedAt(state, append(base, "encryption", "keyName")...)
		replicaKeyName := c.resolvedAt(state, append(base, "replica", "encryption", "keyName")...)
		c.requireBucketName(backend.manifestName+" state bucket", bucket)
		c.requireBucketName(backend.manifestName+" replica bucket", replicaBucket)
		c.requirePattern(backend.manifestName+" state key ID", keyName, keyIDPattern)
		c.requirePattern(backend.manifestName+" replica key ID", replicaKeyName, keyIDPattern)
		stateBackends[backend.outputName] = map[string]any{
			"bucket_name":         bucket,
			"replica_bucket_name": replicaBucket,
			"key_name":            keyName,
			"replica_key_name":    replicaKeyName,
			"prefix":              c.stringAt(state, append(base, "prefix")...),
		}
	}
	c.requireDistinct("state primary and replica buckets", []string{
		stateBackends["root_trust"].(map[string]any)["bucket_name"].(string),
		stateBackends["root_trust"].(map[string]any)["replica_bucket_name"].(string),
		stateBackends["recovery_plane"].(map[string]any)["bucket_name"].(string),
		stateBackends["recovery_plane"].(map[string]any)["replica_bucket_name"].(string),
	})

	auditBuckets := map[string]any{}
	for _, name := range []string{"primary", "recovery"} {
		base := []string{"spec", "logBuckets", name}
		keyName := c.resolvedAt(audit, append(base, "encryptionKeyName")...)
		c.requirePattern("audit "+name+" key ID", keyName, keyIDPattern)
		auditBuckets[name] = map[string]any{
			"bucket_id": c.stringAt(audit, append(base, "bucketId")...),
			"location":  c.stringAt(audit, append(base, "location")...),
			"key_name":  keyName,
		}
	}
	auditSinks := map[string]any{}
	for _, name := range sortedKeys(c.objectAt(audit, "spec", "aggregatedSinks")) {
		base := []string{"spec", "aggregatedSinks", name}
		auditSinks[name] = map[string]any{
			"bucket_id": c.stringAt(audit, append(base, "destinationBucketRef")...),
			"name":      c.stringAt(audit, append(base, "sinkName")...),
			"filter":    c.stringAt(audit, append(base, "filter")...),
		}
	}
	auditReaders := []string{
		c.resolvedAt(audit, "spec", "readers", "security"),
		c.resolvedAt(audit, "spec", "readers", "compliance"),
	}
	auditAdministrators := []string{c.resolvedAt(trust, "spec", "administratorPrincipals", "root")}
	c.validateExplicitPrincipals("audit reader principals", auditReaders, false)
	c.validateExplicitPrincipals("audit administrator principals", auditAdministrators, false)
	c.requireGroupPrincipals("audit reader principals", auditReaders)
	c.requireGroupPrincipals("audit administrator principals", auditAdministrators)
	c.requireDistinct("audit reader principals", auditReaders)

	workforceAdministrator := c.resolvedAt(federation, "spec", "workforce", "administratorGroup")
	workforceIssuer := c.resolvedAt(federation, "spec", "workforce", "issuerUri")
	if !strings.HasPrefix(workforceIssuer, "https://") {
		c.problem("workforce issuer must use HTTPS")
	}
	workforce := map[string]any{
		"pool_id":             c.stringAt(federation, "spec", "workforce", "poolId"),
		"provider_id":         c.stringAt(federation, "spec", "workforce", "providerId"),
		"issuer_uri":          workforceIssuer,
		"client_id":           c.resolvedAt(federation, "spec", "workforce", "clientId"),
		"administrator_group": workforceAdministrator,
		"attribute_mapping": map[string]any{
			"google.subject":      c.stringAt(federation, "spec", "workforce", "attributeMapping", "subject"),
			"google.display_name": c.stringAt(federation, "spec", "workforce", "attributeMapping", "displayName"),
			"google.groups":       c.stringAt(federation, "spec", "workforce", "attributeMapping", "groups"),
		},
		"attribute_condition": fmt.Sprintf("assertion.groups.exists(group, group == %s)", celString(workforceAdministrator)),
		"additional_scopes":   []string{"groups"},
	}

	githubBase := []string{"spec", "workloadIdentityProviders", "github"}
	githubPoolBase := c.stringAt(federation, append(githubBase, "poolId")...)
	githubProviderBase := c.stringAt(federation, append(githubBase, "providerId")...)
	githubAudienceBase := c.resolvedAt(federation, append(githubBase, "allowedAudience")...)
	githubApplyRef := c.resolvedAt(federation, append(githubBase, "requiredClaims", "workflow_ref")...)
	const applyWorkflowSuffix = "/.github/workflows/protected-apply.yml@refs/heads/main"
	repositoryFullName := strings.TrimSuffix(githubApplyRef, applyWorkflowSuffix)
	if repositoryFullName == githubApplyRef || !githubRepoPattern.MatchString(repositoryFullName) || githubApplyRef != repositoryFullName+applyWorkflowSuffix {
		c.problem("GitHub apply workflow reference must exactly identify protected-apply.yml on refs/heads/main")
	}
	if repositoryFullName != c.componentProjectSlug() {
		c.problem("GitHub apply workflow repository must equal component github.com/project-slug")
	}
	roles := []string{"plan", "apply", "recovery"}
	githubPools := map[string]any{}
	githubProviders := map[string]any{}
	githubServiceAccounts := map[string]any{}
	githubAudiences := map[string]any{}
	githubWorkflowRefs := map[string]any{}
	for _, role := range roles {
		poolID := githubPoolBase + "-" + role
		providerID := githubProviderBase + "-" + role
		c.requirePattern("GitHub "+role+" pool ID", poolID, gcpIDPattern)
		c.requirePattern("GitHub "+role+" provider ID", providerID, gcpIDPattern)
		githubPools[role] = poolID
		githubProviders[role] = providerID
		githubAudiences[role] = suffix(githubAudienceBase, role)
		githubWorkflowRefs[role] = githubApplyRef
	}
	githubServiceAccounts["plan"] = c.stringAt(federation, append(githubBase, "serviceAccounts", "plan", "accountId")...)
	githubServiceAccounts["apply"] = c.stringAt(federation, append(githubBase, "serviceAccounts", "apply", "accountId")...)
	githubServiceAccounts["recovery"] = c.stringAt(federation, append(githubBase, "serviceAccounts", "recovery", "accountId")...)
	githubWorkflowRefs["recovery"] = repositoryFullName + "/.github/workflows/recovery-verification.yml@refs/heads/main"
	c.requireDistinct("GitHub pool IDs", stringMapValues(githubPools))
	c.requireDistinct("GitHub provider IDs", stringMapValues(githubProviders))
	c.requireDistinct("GitHub service-account IDs", stringMapValues(githubServiceAccounts))
	c.requireDistinct("GitHub audiences", stringMapValues(githubAudiences))
	githubIssuer := c.resolvedAt(federation, append(githubBase, "issuerUri")...)
	if githubIssuer != "https://token.actions.githubusercontent.com" {
		c.problem("GitHub issuer must equal the canonical token.actions.githubusercontent.com endpoint")
	}
	repositoryID := c.resolvedAt(federation, append(githubBase, "requiredClaims", "repository_id")...)
	repositoryOwnerID := c.resolvedAt(federation, append(githubBase, "requiredClaims", "repository_owner_id")...)
	if !regexp.MustCompile(`^[0-9]+$`).MatchString(repositoryID) || !regexp.MustCompile(`^[0-9]+$`).MatchString(repositoryOwnerID) {
		c.problem("GitHub immutable repository and owner IDs must be decimal numbers")
	}
	github := map[string]any{
		"issuer_uri":           githubIssuer,
		"repository_full_name": repositoryFullName,
		"repository_id":        repositoryID,
		"repository_owner_id":  repositoryOwnerID,
		"branch_ref":           c.stringAt(federation, append(githubBase, "requiredClaims", "ref", "literal")...),
		"pool_ids":             githubPools,
		"provider_ids":         githubProviders,
		"service_account_ids":  githubServiceAccounts,
		"audiences":            githubAudiences,
		"workflow_refs":        githubWorkflowRefs,
	}

	buildkiteBase := []string{"spec", "workloadIdentityProviders", "buildkite"}
	buildkiteIssuer := c.resolvedAt(federation, append(buildkiteBase, "issuerUri")...)
	if buildkiteIssuer != "https://agent.buildkite.com" {
		c.problem("Buildkite issuer must equal the canonical agent.buildkite.com endpoint")
	}
	buildkite := map[string]any{
		"pool_id":            c.stringAt(federation, append(buildkiteBase, "poolId")...),
		"provider_id":        c.stringAt(federation, append(buildkiteBase, "providerId")...),
		"service_account_id": c.stringAt(federation, append(buildkiteBase, "serviceAccounts", "bootstrap", "accountId")...),
		"issuer_uri":         buildkiteIssuer,
		"audience":           c.resolvedAt(federation, append(buildkiteBase, "allowedAudience")...),
		"organization_slug":  c.resolvedAt(federation, append(buildkiteBase, "requiredClaims", "organization_slug")...),
		"pipeline_slug":      c.resolvedAt(federation, append(buildkiteBase, "requiredClaims", "pipeline_slug")...),
		"pipeline_id":        c.resolvedAt(federation, append(buildkiteBase, "requiredClaims", "pipeline_id")...),
		"build_branch":       c.stringAt(federation, append(buildkiteBase, "requiredClaims", "build_branch", "literal")...),
		"step_key":           c.stringAt(federation, append(buildkiteBase, "requiredClaims", "step_key", "literal")...),
	}

	gitopsBase := []string{"spec", "workloadIdentityProviders", "gitops"}
	gitopsIssuer := c.resolvedAt(federation, append(gitopsBase, "issuerUri")...)
	if !strings.HasPrefix(gitopsIssuer, "https://") {
		c.problem("GitOps issuer must use HTTPS")
	}
	gitops := map[string]any{
		"pool_id":            c.stringAt(federation, append(gitopsBase, "poolId")...),
		"provider_id":        c.stringAt(federation, append(gitopsBase, "providerId")...),
		"service_account_id": c.stringAt(federation, append(gitopsBase, "serviceAccounts", "bootstrap", "accountId")...),
		"issuer_uri":         gitopsIssuer,
		"audience":           c.resolvedAt(federation, append(gitopsBase, "allowedAudience")...),
		"subject":            c.resolvedAt(federation, append(gitopsBase, "requiredClaims", "subject")...),
		"repository":         c.resolvedAt(federation, append(gitopsBase, "requiredClaims", "repository")...),
		"ref":                c.stringAt(federation, append(gitopsBase, "requiredClaims", "ref", "literal")...),
	}
	if !uuidPattern.MatchString(buildkite["pipeline_id"].(string)) {
		c.problem("Buildkite pipeline ID must be an immutable UUID")
	}
	if buildkite["build_branch"] != "main" || buildkite["step_key"] != "bootstrap-ring0-signing" {
		c.problem("Buildkite signer federation must require the main branch and dedicated bootstrap-ring0-signing step")
	}

	signingAdministrators := c.resolvedList(signing, "spec", "administrators")
	c.requireDistinct("signing administrators", signingAdministrators)
	c.validateExplicitPrincipals("signing administrators", signingAdministrators, false)
	c.requireGroupPrincipals("signing administrators", signingAdministrators)
	signingKeys := map[string]any{}
	signingPrincipals := append([]string{}, signingAdministrators...)
	for _, name := range sortedKeys(c.objectAt(signing, "spec", "keys")) {
		signers := c.resolvedList(signing, "spec", "keys", name, "signers")
		c.requireDistinct("signers for "+name, signers)
		c.validateExplicitPrincipals("signers for "+name, signers, false)
		c.requireServiceAccountPrincipals("signers for "+name, signers)
		versionDeclarations := map[string]any{}
		for _, versionRef := range sortedKeys(c.objectAt(signing, "spec", "keys", name, "versions")) {
			versionDeclarations[versionRef] = map[string]any{
				"activation_window_start": c.stringAt(signing, "spec", "keys", name, "versions", versionRef, "activationWindowStart"),
				"rotation_deadline":       c.stringAt(signing, "spec", "keys", name, "versions", versionRef, "rotationDeadline"),
			}
		}
		signingKeys[name] = map[string]any{
			"signer_principals":  signers,
			"rotation_days":      c.intAt(signing, "spec", "keys", name, "rotationDays"),
			"active_version_ref": c.stringAt(signing, "spec", "keys", name, "activeVersionRef"),
			"versions":           versionDeclarations,
		}
		signingPrincipals = append(signingPrincipals, signers...)
	}

	requesters := c.resolvedMapValues(breakGlass, "spec", "requesters")
	approvers := c.resolvedMapValues(breakGlass, "spec", "approvers")
	notificationRecipients := c.resolvedMapValues(breakGlass, "spec", "notificationRecipients")
	c.requireDistinct("break-glass requesters", requesters)
	c.requireDistinct("break-glass approvers", approvers)
	c.validateExplicitPrincipals("break-glass requesters", requesters, true)
	c.validateExplicitPrincipals("break-glass approvers", approvers, true)
	if intersects(requesters, approvers) {
		c.problem("break-glass requesters and approvers must be disjoint")
	}
	for _, recipient := range notificationRecipients {
		if !looksLikeEmail(recipient) {
			c.problem("break-glass notification recipients must be email addresses")
		}
	}
	breakGlassEntitlements := map[string]any{}
	for _, name := range sortedKeys(c.objectAt(breakGlass, "spec", "entitlements")) {
		base := []string{"spec", "entitlements", name}
		roles := c.stringsAt(breakGlass, append(base, "roles")...)
		sort.Strings(roles)
		breakGlassEntitlements[name] = map[string]any{
			"target_project_id": c.projectID(c.stringAt(breakGlass, append(base, "targetProjectRef")...)),
			"roles":             roles,
		}
	}

	organizationID := c.resolvedAt(trust, "spec", "organization")
	billingAccount := c.resolvedAt(trust, "spec", "billingAccount")
	rootAdministrator := c.resolvedAt(trust, "spec", "administratorPrincipals", "root")
	recoveryAdministrator := c.resolvedAt(trust, "spec", "administratorPrincipals", "recovery")
	securityApprover := c.resolvedAt(trust, "spec", "administratorPrincipals", "security")
	if !strings.HasPrefix(recoveryAdministrator, "group:") || !looksLikeEmail(strings.TrimPrefix(recoveryAdministrator, "group:")) {
		c.problem("recovery administrator must be one explicit group email principal")
	}
	c.validateExplicitPrincipals("recovery administrator", []string{recoveryAdministrator}, false)
	for _, principal := range append([]string{rootAdministrator, securityApprover}, signingPrincipals...) {
		if recoveryAdministrator == principal {
			c.problem("recovery administrator must be distinct from root, security, and signing principals")
		}
	}
	if !regexp.MustCompile(`^[0-9]+$`).MatchString(organizationID) {
		c.problem("organization ID must contain decimal digits only")
	}
	if !regexp.MustCompile(`^[0-9A-Z]{6}-[0-9A-Z]{6}-[0-9A-Z]{6}$`).MatchString(billingAccount) {
		c.problem("billing account must use the canonical XXXXXX-XXXXXX-XXXXXX format")
	}
	c.validateOmittedOperationalValues()
	auditLocked := c.boolAt(audit, "spec", "lockAfterQualification", "locked")
	var auditQualificationEvidence any
	if auditLocked {
		auditQualificationEvidence = map[string]any{
			"artifact_sha256":      c.stringAt(audit, "spec", "lockAfterQualification", "qualificationEvidence", "artifactSha256"),
			"signature_sha256":     c.stringAt(audit, "spec", "lockAfterQualification", "qualificationEvidence", "signatureSha256"),
			"signing_key_ref":      c.stringAt(audit, "spec", "lockAfterQualification", "qualificationEvidence", "signingKeyRef"),
			"qualified_source_sha": c.stringAt(audit, "spec", "lockAfterQualification", "qualificationEvidence", "qualifiedSourceSha"),
			"qualified_at":         c.stringAt(audit, "spec", "lockAfterQualification", "qualificationEvidence", "qualifiedAt"),
		}
	}

	return map[string]any{
		"organization_id":                  organizationID,
		"billing_account":                  billingAccount,
		"default_region":                   c.stringAt(trust, "spec", "geographicalBoundary", "defaultLocation"),
		"recovery_region":                  c.stringAt(trust, "spec", "geographicalBoundary", "recoveryLocation"),
		"recovery_administrator_principal": recoveryAdministrator,
		"projects":                         projectObjects,
		"state_backends":                   stateBackends,
		"audit": map[string]any{
			"buckets":                  auditBuckets,
			"sinks":                    auditSinks,
			"retention_days":           c.intAt(audit, "spec", "retentionDays"),
			"lock_after_qualification": auditLocked,
			"qualification_evidence":   auditQualificationEvidence,
			"reader_principals":        auditReaders,
			"administrator_principals": auditAdministrators,
		},
		"workforce": workforce,
		"github":    github,
		"buildkite": buildkite,
		"gitops":    gitops,
		"signing": map[string]any{
			"location":       c.stringAt(signing, "spec", "location"),
			"key_ring_name":  c.stringAt(signing, "spec", "keyRing"),
			"administrators": signingAdministrators,
			"keys":           signingKeys,
		},
		"break_glass": map[string]any{
			"requester_principals":    requesters,
			"approver_principals":     approvers,
			"notification_recipients": notificationRecipients,
			"entitlements":            breakGlassEntitlements,
		},
	}
}

func (c *compiler) recoveryVariables(context recoveryContext) map[string]any {
	const (
		recovery = "manifests/recovery-policy.yaml"
		signing  = "manifests/signing-roots.yaml"
	)
	rootVariables := c.rootTrustVariables()
	projectID := c.projectID("recovery-root")
	stateProjectID := c.projectID("state-root")
	location := c.stringAt(recovery, "spec", "recoveryRegion")
	exportKeyName := c.resolvedAt(recovery, "spec", "exports", "encryptionKeyName")
	c.requirePattern("recovery export key ID", exportKeyName, keyIDPattern)
	if exportKeyName == "recovery-evidence" {
		c.problem("recovery export key must be distinct from the fixed recovery-evidence key")
	}
	exportBucketName := projectID + "-recovery-exports"
	evidenceBucketName := projectID + "-recovery-evidence"
	c.requireBucketName("recovery export bucket", exportBucketName)
	c.requireBucketName("recovery evidence bucket", evidenceBucketName)

	github := rootVariables["github"].(map[string]any)
	githubPools := github["pool_ids"].(map[string]any)
	githubProviders := github["provider_ids"].(map[string]any)
	contextProviders := map[string]string{
		"github-plan":     context.Federation.GitHub.Providers.Plan,
		"github-apply":    context.Federation.GitHub.Providers.Apply,
		"github-recovery": context.Federation.GitHub.Providers.Recovery,
		"buildkite":       context.Federation.Buildkite.Provider,
		"gitops":          context.Federation.GitOps.Provider,
	}
	providerProjectNumbers := []string{}
	for _, entry := range []struct {
		name, value, pool, provider string
	}{
		{"github-plan", contextProviders["github-plan"], githubPools["plan"].(string), githubProviders["plan"].(string)},
		{"github-apply", contextProviders["github-apply"], githubPools["apply"].(string), githubProviders["apply"].(string)},
		{"github-recovery", contextProviders["github-recovery"], githubPools["recovery"].(string), githubProviders["recovery"].(string)},
		{"buildkite", contextProviders["buildkite"], rootVariables["buildkite"].(map[string]any)["pool_id"].(string), rootVariables["buildkite"].(map[string]any)["provider_id"].(string)},
		{"gitops", contextProviders["gitops"], rootVariables["gitops"].(map[string]any)["pool_id"].(string), rootVariables["gitops"].(map[string]any)["provider_id"].(string)},
	} {
		matches := providerNamePattern.FindStringSubmatch(entry.value)
		if len(matches) != 4 {
			c.problem("recovery context %s provider must be a canonical project-number-based provider name", entry.name)
			continue
		}
		if matches[2] != entry.pool || matches[3] != entry.provider {
			c.problem("recovery context %s provider does not match the compiled pool/provider IDs", entry.name)
		}
		providerProjectNumbers = append(providerProjectNumbers, matches[1])
	}
	c.requireSingleValue("recovery context identity provider project numbers", providerProjectNumbers)

	expectedSigningKeys := sortedKeys(c.objectAt(signing, "spec", "keys"))
	actualSigningKeys := sortedKeys(context.SigningRoots)
	if !reflect.DeepEqual(actualSigningKeys, expectedSigningKeys) {
		c.problem("recovery context signing_roots keys must equal %v", expectedSigningKeys)
	}
	signingVersions := map[string]string{}
	signingWindows := map[string]any{}
	for _, name := range expectedSigningKeys {
		version := context.SigningRoots[name].PrimaryVersion
		matches := keyVersionPattern.FindStringSubmatch(version)
		if len(matches) != 6 {
			c.problem("recovery context signing root %s must be a canonical public CryptoKeyVersion name", name)
		} else if matches[1] != c.projectID("signing-root") || matches[2] != c.stringAt(signing, "spec", "location") ||
			matches[3] != c.stringAt(signing, "spec", "keyRing") || matches[4] != name {
			c.problem("recovery context signing root %s does not match the compiled signing root", name)
		}
		signingVersions[name] = version
		activeVersionRef := c.stringAt(signing, "spec", "keys", name, "activeVersionRef")
		signingWindows[name] = map[string]any{
			"active_version_ref":      activeVersionRef,
			"activation_window_start": c.stringAt(signing, "spec", "keys", name, "versions", activeVersionRef, "activationWindowStart"),
			"rotation_deadline":       c.stringAt(signing, "spec", "keys", name, "versions", activeVersionRef, "rotationDeadline"),
		}
	}

	manifestDigests := map[string]string{}
	manifestPaths := make([]string, 0, len(manifestSchemas))
	for path := range manifestSchemas {
		manifestPaths = append(manifestPaths, path)
	}
	sort.Strings(manifestPaths)
	for _, path := range manifestPaths {
		digest, err := digestFile(filepath.Join(c.root, filepath.FromSlash(path)))
		if err != nil {
			c.problem("digest %s: %v", path, err)
			continue
		}
		manifestDigests[path] = digest
	}
	restorePath := c.stringAt(recovery, "spec", "restoreManifestPath")
	restoreDigest, err := digestFile(filepath.Join(c.root, filepath.FromSlash(restorePath)))
	if err != nil {
		c.problem("digest restore manifest: %v", err)
	}

	githubAudiences := github["audiences"].(map[string]any)
	expectedFederationAudiences := map[string]string{
		"github-plan":     githubAudiences["plan"].(string),
		"github-apply":    githubAudiences["apply"].(string),
		"github-recovery": githubAudiences["recovery"].(string),
		"buildkite":       rootVariables["buildkite"].(map[string]any)["audience"].(string),
		"gitops":          rootVariables["gitops"].(map[string]any)["audience"].(string),
	}
	federationAudiences := map[string]string{
		"github-plan":     context.Federation.GitHub.Audiences.Plan,
		"github-apply":    context.Federation.GitHub.Audiences.Apply,
		"github-recovery": context.Federation.GitHub.Audiences.Recovery,
		"buildkite":       context.Federation.Buildkite.Audience,
		"gitops":          context.Federation.GitOps.Audience,
	}
	for _, name := range sortedKeys(expectedFederationAudiences) {
		if federationAudiences[name] != expectedFederationAudiences[name] {
			c.problem("recovery context %s audience does not match deployed root-trust inputs", name)
		}
		if !strings.HasPrefix(federationAudiences[name], "https://") && !strings.HasPrefix(federationAudiences[name], "//iam.googleapis.com/") {
			c.problem("recovery context %s audience must be HTTPS or canonical IAM", name)
		}
	}

	compiledStateBackends := rootVariables["state_backends"].(map[string]any)
	contextStateBackends := map[string]recoveryBackendContext{
		"root-trust":     context.StateBackends.RootTrust,
		"recovery-plane": context.StateBackends.RecoveryPlane,
	}
	stateBackendMetadata := map[string]any{}
	for manifestName, outputName := range map[string]string{
		"root-trust":     "root_trust",
		"recovery-plane": "recovery_plane",
	} {
		compiled := compiledStateBackends[outputName].(map[string]any)
		deployed := contextStateBackends[manifestName]
		expectedProjectID := stateProjectID
		expectedReplicaProjectID := projectID
		if manifestName == "recovery-plane" {
			expectedProjectID, expectedReplicaProjectID = projectID, stateProjectID
		}
		if deployed.Bucket != compiled["bucket_name"].(string) ||
			deployed.Prefix != compiled["prefix"].(string) ||
			deployed.ReplicaBucket != compiled["replica_bucket_name"].(string) ||
			deployed.ProjectID != expectedProjectID ||
			deployed.ReplicaProjectID != expectedReplicaProjectID {
			c.problem("recovery context %s backend does not match deployed root-trust inputs", manifestName)
		}
		c.requireBucketName("recovery context "+manifestName+" state bucket", deployed.Bucket)
		c.requireBucketName("recovery context "+manifestName+" replica bucket", deployed.ReplicaBucket)
		if deployed.Prefix != manifestName {
			c.problem("recovery context %s prefix must equal %s", manifestName, manifestName)
		}
		stateBackendMetadata[manifestName] = map[string]any{
			"bucket":         deployed.Bucket,
			"prefix":         deployed.Prefix,
			"replica_bucket": deployed.ReplicaBucket,
		}
	}
	c.requireDistinct("recovery export, evidence, primary-state, and replica-state buckets", []string{
		exportBucketName,
		evidenceBucketName,
		contextStateBackends["root-trust"].Bucket,
		contextStateBackends["root-trust"].ReplicaBucket,
		contextStateBackends["recovery-plane"].Bucket,
		contextStateBackends["recovery-plane"].ReplicaBucket,
	})
	sourceStateBackends := map[string]any{}
	for name, backend := range contextStateBackends {
		sourceStateBackends[name] = map[string]any{
			"project_id": backend.ProjectID,
			"bucket":     backend.Bucket,
			"prefix":     backend.Prefix,
		}
	}

	return map[string]any{
		"project_id":                         projectID,
		"location":                           location,
		"key_ring_name":                      "bootstrap-recovery",
		"export_key_name":                    exportKeyName,
		"export_bucket_name":                 exportBucketName,
		"evidence_bucket_name":               evidenceBucketName,
		"exporter_principal":                 serviceAccountMember("bootstrap-apply", stateProjectID),
		"recovery_principal":                 serviceAccountMember("bootstrap-recovery", projectID),
		"plan_principal":                     serviceAccountMember("bootstrap-plan", stateProjectID),
		"source_state_backends":              sourceStateBackends,
		"minimum_retained_state_generations": c.intAt(recovery, "spec", "exports", "minimumRetainedStateGenerations"),
		"restore_manifest_digest":            restoreDigest,
		"public_trust_metadata": map[string]any{
			"schema_version":       1,
			"manifest_digests":     manifestDigests,
			"signing_key_versions": signingVersions,
			"signing_windows":      signingWindows,
			"federation_providers": contextProviders,
			"federation_audiences": federationAudiences,
			"state_backends":       stateBackendMetadata,
		},
	}
}

func (c *compiler) projectID(reference string) string {
	return c.resolvedAt("manifests/trust-anchors.yaml", "spec", "projects", reference, "projectId")
}

func (c *compiler) componentProjectSlug() string {
	value, err := LoadYAML(filepath.Join(c.root, "component.yaml"))
	if err != nil {
		c.problem("load component project slug: %v", err)
		return ""
	}
	component, ok := value.(map[string]any)
	if !ok {
		c.problem("component.yaml must be an object")
		return ""
	}
	metadata, ok := component["metadata"].(map[string]any)
	if !ok {
		c.problem("component.yaml.metadata must be an object")
		return ""
	}
	annotations, ok := metadata["annotations"].(map[string]any)
	if !ok {
		c.problem("component.yaml.metadata.annotations must be an object")
		return ""
	}
	slug, ok := annotations["github.com/project-slug"].(string)
	if !ok || !githubRepoPattern.MatchString(slug) {
		c.problem("component github.com/project-slug must be an owner/repository string")
		return ""
	}
	return slug
}

func (c *compiler) validateOmittedOperationalValues() {
	const (
		trust    = "manifests/trust-anchors.yaml"
		recovery = "manifests/recovery-policy.yaml"
	)
	recoveryAdministrator := c.resolvedAt(trust, "spec", "administratorPrincipals", "recovery")
	policyRecoveryAdministrator := c.resolvedAt(recovery, "spec", "isolation", "recoveryAdministrator")
	if recoveryAdministrator != policyRecoveryAdministrator {
		c.problem("recovery administrator must resolve identically across trust and recovery manifests")
	}
	c.validateExplicitPrincipals("recovery administrator", []string{recoveryAdministrator}, false)
	securityApprover := c.resolvedAt(trust, "spec", "administratorPrincipals", "security")
	c.validateExplicitPrincipals("security approver", []string{securityApprover}, false)
	c.requireGroupPrincipals("recovery administrator", []string{recoveryAdministrator})
	c.requireGroupPrincipals("security approver", []string{securityApprover})
	contacts := c.objectAt(recovery, "spec", "independentContacts")
	if len(contacts) < 2 {
		c.problem("independent recovery contacts must contain at least two out-of-band references")
	}
	for _, name := range sortedKeys(contacts) {
		reference := c.envNameAt(recovery, "spec", "independentContacts", name)
		if !outOfBandReferences[reference] {
			c.problem("independent recovery contact %s must use an approved out-of-band reference", name)
		}
	}
}

func (c *compiler) requirePattern(label, value string, pattern *regexp.Regexp) {
	if !pattern.MatchString(value) {
		c.problem("%s has an invalid format", label)
	}
}

func (c *compiler) requireBucketName(label, value string) {
	if !bucketNamePattern.MatchString(value) || strings.HasPrefix(value, "goog") || strings.Contains(value, "google") {
		c.problem("%s has an invalid or Google-reserved format", label)
	}
}

func (c *compiler) requireDistinct(label string, values []string) {
	seen := map[string]bool{}
	for _, value := range values {
		if value == "" || seen[value] {
			c.problem("%s must contain distinct non-empty values", label)
			return
		}
		seen[value] = true
	}
}

func (c *compiler) requireSingleValue(label string, values []string) {
	if len(values) == 0 {
		c.problem("%s must be present", label)
		return
	}
	first := values[0]
	for _, value := range values[1:] {
		if value != first {
			c.problem("%s must all be identical", label)
			return
		}
	}
}

func (c *compiler) validateExplicitPrincipals(label string, principals []string, usersOnly bool) {
	for _, principal := range principals {
		if usersOnly {
			if !strings.HasPrefix(principal, "user:") || !looksLikeEmail(strings.TrimPrefix(principal, "user:")) {
				c.problem("%s must contain explicit user: email principals", label)
			}
			continue
		}
		if !canonicalIAMPrincipal(principal) {
			c.problem("%s must contain canonical explicit IAM principals", label)
		}
	}
}

func (c *compiler) requireGroupPrincipals(label string, principals []string) {
	for _, principal := range principals {
		if !strings.HasPrefix(principal, "group:") || !looksLikeEmail(strings.TrimPrefix(principal, "group:")) {
			c.problem("%s must contain canonical group email principals", label)
		}
	}
}

func (c *compiler) requireServiceAccountPrincipals(label string, principals []string) {
	for _, principal := range principals {
		if !serviceAccountPrincipalPattern.MatchString(principal) {
			c.problem("%s must contain canonical service-account principals", label)
		}
	}
}

func canonicalIAMPrincipal(principal string) bool {
	if strings.ContainsAny(principal, "*\x00\r\n\t ") || principal == "allUsers" || principal == "allAuthenticatedUsers" {
		return false
	}
	for _, prefix := range []string{"user:", "group:"} {
		if strings.HasPrefix(principal, prefix) {
			return looksLikeEmail(strings.TrimPrefix(principal, prefix))
		}
	}
	return serviceAccountPrincipalPattern.MatchString(principal) || federatedPrincipalPattern.MatchString(principal)
}

func celString(value string) string {
	escaped := strings.ReplaceAll(value, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `'`, `\'`)
	return "'" + escaped + "'"
}

func suffix(base, role string) string {
	return strings.TrimRight(base, "/") + "/" + role
}

func serviceAccountMember(accountID, projectID string) string {
	return fmt.Sprintf("serviceAccount:%s@%s.iam.gserviceaccount.com", accountID, projectID)
}

func stringMapValues(values map[string]any) []string {
	result := make([]string, 0, len(values))
	for _, key := range sortedKeys(values) {
		if value, ok := values[key].(string); ok {
			result = append(result, value)
		}
	}
	return result
}

func intersects(left, right []string) bool {
	seen := map[string]bool{}
	for _, value := range left {
		seen[value] = true
	}
	for _, value := range right {
		if seen[value] {
			return true
		}
	}
	return false
}

func looksLikeEmail(value string) bool {
	return emailAddressPattern.MatchString(value)
}

func digestFile(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(data)
	return fmt.Sprintf("sha256:%x", digest[:]), nil
}

func (c *compiler) objectAt(file string, path ...string) map[string]any {
	value := c.lookup(file, path...)
	object, ok := value.(map[string]any)
	if !ok {
		c.problem("%s.%s must be an object", file, strings.Join(path, "."))
		return map[string]any{}
	}
	return object
}

func (c *compiler) stringAt(file string, path ...string) string {
	value := c.lookup(file, path...)
	text, ok := value.(string)
	if !ok || text == "" {
		c.problem("%s.%s must be a non-empty string", file, strings.Join(path, "."))
		return ""
	}
	return text
}

func (c *compiler) boolAt(file string, path ...string) bool {
	value := c.lookup(file, path...)
	boolean, ok := value.(bool)
	if !ok {
		c.problem("%s.%s must be a boolean", file, strings.Join(path, "."))
		return false
	}
	return boolean
}

func (c *compiler) intAt(file string, path ...string) int {
	value := c.lookup(file, path...)
	switch number := value.(type) {
	case int:
		return number
	case int64:
		return int(number)
	case float64:
		if number == float64(int(number)) {
			return int(number)
		}
	}
	c.problem("%s.%s must be an integer", file, strings.Join(path, "."))
	return 0
}

func (c *compiler) stringsAt(file string, path ...string) []string {
	value := c.lookup(file, path...)
	items, ok := value.([]any)
	if !ok {
		c.problem("%s.%s must be an array", file, strings.Join(path, "."))
		return nil
	}
	result := make([]string, 0, len(items))
	for index, item := range items {
		text, ok := item.(string)
		if !ok || text == "" {
			c.problem("%s.%s[%d] must be a non-empty string", file, strings.Join(path, "."), index)
			continue
		}
		result = append(result, text)
	}
	return result
}

func (c *compiler) resolvedAt(file string, path ...string) string {
	reference := c.objectAt(file, path...)
	valueFrom, ok := reference["valueFrom"].(map[string]any)
	if !ok {
		c.problem("%s.%s must be an external value reference", file, strings.Join(path, "."))
		return ""
	}
	name, ok := valueFrom["env"].(string)
	if !ok || name == "" {
		c.problem("%s.%s.valueFrom.env must be a non-empty string", file, strings.Join(path, "."))
		return ""
	}
	if name == workforceSecretReference {
		c.problem("%s may not be resolved into rendered variables", workforceSecretReference)
		return ""
	}
	value, ok := c.values[name]
	if !ok {
		c.problem("external value %s is unavailable", name)
		return ""
	}
	return value
}

func (c *compiler) envNameAt(file string, path ...string) string {
	reference := c.objectAt(file, path...)
	valueFrom, ok := reference["valueFrom"].(map[string]any)
	if !ok {
		c.problem("%s.%s must be an external value reference", file, strings.Join(path, "."))
		return ""
	}
	name, ok := valueFrom["env"].(string)
	if !ok {
		c.problem("%s.%s.valueFrom.env must be a string", file, strings.Join(path, "."))
		return ""
	}
	return name
}

func (c *compiler) resolvedMapValues(file string, path ...string) []string {
	object := c.objectAt(file, path...)
	keys := sortedKeys(object)
	values := make([]string, 0, len(keys))
	for _, key := range keys {
		values = append(values, c.resolvedAt(file, append(path, key)...))
	}
	return values
}

func (c *compiler) resolvedList(file string, path ...string) []string {
	value := c.lookup(file, path...)
	items, ok := value.([]any)
	if !ok {
		c.problem("%s.%s must be an array", file, strings.Join(path, "."))
		return nil
	}
	values := make([]string, 0, len(items))
	for index, item := range items {
		reference, ok := item.(map[string]any)
		if !ok {
			c.problem("%s.%s[%d] must be an external value reference", file, strings.Join(path, "."), index)
			continue
		}
		valueFrom, ok := reference["valueFrom"].(map[string]any)
		if !ok {
			c.problem("%s.%s[%d].valueFrom is required", file, strings.Join(path, "."), index)
			continue
		}
		name, ok := valueFrom["env"].(string)
		if !ok || name == workforceSecretReference {
			c.problem("%s.%s[%d] has an invalid external value reference", file, strings.Join(path, "."), index)
			continue
		}
		values = append(values, c.values[name])
	}
	return values
}

func (c *compiler) expect(file string, expected any, path ...string) {
	actual := c.lookup(file, path...)
	if !reflect.DeepEqual(actual, expected) {
		c.problem("%s.%s must equal %v", file, strings.Join(path, "."), expected)
	}
}

func (c *compiler) expectKeys(file string, expected []string, path ...string) {
	actual := sortedKeys(c.objectAt(file, path...))
	wanted := append([]string{}, expected...)
	sort.Strings(wanted)
	if !reflect.DeepEqual(actual, wanted) {
		c.problem("%s.%s keys must equal %v", file, strings.Join(path, "."), wanted)
	}
}

func (c *compiler) expectStrings(file string, expected []string, path ...string) {
	actual := c.stringsAt(file, path...)
	if !reflect.DeepEqual(actual, expected) {
		c.problem("%s.%s must equal %v", file, strings.Join(path, "."), expected)
	}
}

func (c *compiler) expectEnvName(file, expected string, path ...string) {
	actual := c.envNameAt(file, path...)
	if actual != expected {
		c.problem("%s.%s must reference %s", file, strings.Join(path, "."), expected)
	}
}

func (c *compiler) problem(format string, arguments ...any) {
	c.problems = append(c.problems, fmt.Sprintf(format, arguments...))
}

func (c *compiler) err() error {
	if len(c.problems) == 0 {
		return nil
	}
	unique := map[string]bool{}
	for _, problem := range c.problems {
		unique[problem] = true
	}
	problems := make([]string, 0, len(unique))
	for problem := range unique {
		problems = append(problems, problem)
	}
	sort.Strings(problems)
	return fmt.Errorf("manifest compiler contract failed: %s", strings.Join(problems, "; "))
}

func sortedKeys[V any](object map[string]V) []string {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
