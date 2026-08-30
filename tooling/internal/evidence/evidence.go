// Package evidence creates redacted provenance for protected Ring-0 plans.
package evidence

import (
	"archive/zip"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"os/exec"
	archivepath "path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/mindclade/bootstrap/tooling/internal/manifest"
	plancheck "github.com/mindclade/bootstrap/tooling/internal/plan"
)

const SchemaVersion = "mindclade.bootstrap/plan-evidence/v1"

const ApprovalReceiptSchemaVersion = "mindclade.bootstrap/approval-receipt/v1"

const maxArchivedConfigurationBytes = 2 << 20

const maxApprovalReceiptBytes = 64 << 10

var (
	approvalPrincipalPattern = regexp.MustCompile(`^user:[A-Za-z0-9.!#$%&'*+/=?^_` + "`" + `{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	hexSHA256Pattern         = regexp.MustCompile(`^[0-9a-f]{64}$`)
	fullSourceSHAPattern     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	numericRunIDPattern      = regexp.MustCompile(`^[1-9][0-9]*$`)
)

type planModuleContract struct {
	source       string
	directory    string
	sourceFolder string
}

type archivedModule struct {
	Key    string  `json:"Key"`
	Source *string `json:"Source,omitempty"`
	Dir    string  `json:"Dir"`
}

var planModuleContracts = map[string]map[string]planModuleContract{
	"root-trust": {
		"":                     {directory: ".", sourceFolder: "live/root-trust"},
		"audit_root":           {source: "../../modules/audit-root", directory: "../../modules/audit-root", sourceFolder: "modules/audit-root"},
		"break_glass":          {source: "../../modules/break-glass", directory: "../../modules/break-glass", sourceFolder: "modules/break-glass"},
		"buildkite_federation": {source: "../../modules/buildkite-federation", directory: "../../modules/buildkite-federation", sourceFolder: "modules/buildkite-federation"},
		"github_federation":    {source: "../../modules/github-federation", directory: "../../modules/github-federation", sourceFolder: "modules/github-federation"},
		"gitops_federation":    {source: "../../modules/gitops-federation", directory: "../../modules/gitops-federation", sourceFolder: "modules/gitops-federation"},
		"recovery_state":       {source: "../../modules/state-backend", directory: "../../modules/state-backend", sourceFolder: "modules/state-backend"},
		"root_state":           {source: "../../modules/state-backend", directory: "../../modules/state-backend", sourceFolder: "modules/state-backend"},
		"signing_root":         {source: "../../modules/signing-root", directory: "../../modules/signing-root", sourceFolder: "modules/signing-root"},
		"workforce_identity":   {source: "../../modules/workforce-identity", directory: "../../modules/workforce-identity", sourceFolder: "modules/workforce-identity"},
	},
	"recovery-plane": {
		"":                 {directory: ".", sourceFolder: "live/recovery-plane"},
		"recovery_exports": {source: "../../modules/recovery-exports", directory: "../../modules/recovery-exports", sourceFolder: "modules/recovery-exports"},
	},
}

// VerifyPlanConfiguration proves that a pinned OpenTofu saved-plan archive
// embeds exactly the reviewed root and module HCL bytes. This closes a gap in
// tofu show -json: configuration references do not retain expression operators
// or literals, so JSON alone cannot prove a computed IAM condition is safe.
func VerifyPlanConfiguration(savedPlanPath, opentofuRoot, providerLockPath, rootName string, initialLocalBackend bool) error {
	contracts, ok := planModuleContracts[rootName]
	if !ok {
		return fmt.Errorf("unsupported Ring-0 composition %q", rootName)
	}
	if initialLocalBackend && rootName != "root-trust" {
		return fmt.Errorf("initial local-backend mode is permitted only for root-trust")
	}
	rootInfo, err := os.Lstat(opentofuRoot)
	if err != nil {
		return fmt.Errorf("inspect OpenTofu source root: %w", err)
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 || !rootInfo.IsDir() {
		return fmt.Errorf("OpenTofu source root must be a real directory, not a symlink")
	}

	expectedConfiguration := map[string][]byte{}
	moduleKeys := make([]string, 0, len(contracts))
	for key := range contracts {
		moduleKeys = append(moduleKeys, key)
	}
	sort.Strings(moduleKeys)
	for _, key := range moduleKeys {
		contract := contracts[key]
		sourceFiles := []string{"main.tf", "outputs.tf", "variables.tf"}
		archiveFiles := sourceFiles
		if key == "" {
			sourceFiles = []string{"backend.tf", "main.tf", "outputs.tf", "providers.tf", "versions.tf"}
			archiveFiles = sourceFiles
			if initialLocalBackend {
				archiveFiles = []string{"main.tf", "outputs.tf", "providers.tf", "versions.tf"}
			}
		}
		directory := filepath.Join(opentofuRoot, filepath.FromSlash(contract.sourceFolder))
		if err := requireExactConfigurationFiles(directory, sourceFiles); err != nil {
			return err
		}
		for _, name := range archiveFiles {
			sourcePath := filepath.Join(directory, name)
			content, err := readRegularFile(sourcePath, maxArchivedConfigurationBytes)
			if err != nil {
				return err
			}
			expectedConfiguration["tfconfig/m-"+key+"/"+name] = content
		}
	}

	if providerLockPath == "" {
		providerLockPath = filepath.Join(opentofuRoot, "live", rootName, ".terraform.lock.hcl")
	}
	expectedLock, err := readRegularFile(providerLockPath, maxArchivedConfigurationBytes)
	if err != nil {
		return fmt.Errorf("read generated provider lock for saved-plan comparison: %w", err)
	}

	archive, err := zip.OpenReader(savedPlanPath)
	if err != nil {
		return fmt.Errorf("open saved plan as the pinned OpenTofu archive format: %w", err)
	}
	defer archive.Close()
	expectedEntryCount := len(expectedConfiguration) + 5
	if len(archive.File) != expectedEntryCount {
		return fmt.Errorf("saved plan archive must contain exactly %d entries, found %d", expectedEntryCount, len(archive.File))
	}
	entries := map[string]*zip.File{}
	fixedEntries := map[string]bool{
		".terraform.lock.hcl":   true,
		"tfconfig/modules.json": true,
		"tfplan":                true,
		"tfstate":               true,
		"tfstate-prev":          true,
	}
	for _, entry := range archive.File {
		name := entry.Name
		if name == "" || archivepath.Clean(name) != name || strings.HasPrefix(name, "/") || strings.Contains(name, "\\") ||
			strings.IndexFunc(name, func(character rune) bool {
				return !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') &&
					!(character >= '0' && character <= '9') && !strings.ContainsRune("._-/", character)
			}) >= 0 {
			return fmt.Errorf("saved plan archive contains an unsafe entry name")
		}
		if _, duplicate := entries[name]; duplicate {
			return fmt.Errorf("saved plan archive contains duplicate entry %s", name)
		}
		if entry.FileInfo().IsDir() || entry.Mode()&os.ModeType != 0 {
			return fmt.Errorf("saved plan archive entry %s must be a regular file", name)
		}
		if entry.Flags&1 != 0 || (entry.Method != zip.Store && entry.Method != zip.Deflate) {
			return fmt.Errorf("saved plan archive entry %s uses unsupported ZIP encoding", name)
		}
		if _, configured := expectedConfiguration[name]; !configured && !fixedEntries[name] {
			return fmt.Errorf("saved plan archive contains unexpected entry %s", name)
		}
		entries[name] = entry
	}
	for name, expected := range expectedConfiguration {
		entry, present := entries[name]
		if !present {
			return fmt.Errorf("saved plan archive is missing reviewed configuration entry %s", name)
		}
		actual, err := readArchivedFile(entry, maxArchivedConfigurationBytes)
		if err != nil {
			return err
		}
		if !bytes.Equal(actual, expected) {
			return fmt.Errorf("saved plan configuration entry %s does not match the reviewed source bytes", name)
		}
	}
	for name := range fixedEntries {
		if entries[name] == nil {
			return fmt.Errorf("saved plan archive is missing required entry %s", name)
		}
	}
	actualLock, err := readArchivedFile(entries[".terraform.lock.hcl"], maxArchivedConfigurationBytes)
	if err != nil {
		return err
	}
	if !bytes.Equal(actualLock, expectedLock) {
		return fmt.Errorf("saved plan provider lock does not match the initialized reviewed root")
	}
	modulesJSON, err := readArchivedFile(entries["tfconfig/modules.json"], maxArchivedConfigurationBytes)
	if err != nil {
		return err
	}
	if err := verifyArchivedModules(modulesJSON, contracts); err != nil {
		return err
	}
	for _, name := range []string{"tfplan", "tfstate", "tfstate-prev"} {
		if err := verifyArchivedPayload(entries[name], 128<<20); err != nil {
			return err
		}
	}
	return nil
}

func requireExactConfigurationFiles(directory string, expected []string) error {
	info, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect reviewed configuration directory %s: %w", filepath.ToSlash(directory), err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
		return fmt.Errorf("reviewed configuration path %s must be a real directory", filepath.ToSlash(directory))
	}
	want := map[string]bool{}
	for _, name := range expected {
		want[name] = true
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return fmt.Errorf("read reviewed configuration directory %s: %w", filepath.ToSlash(directory), err)
	}
	seen := map[string]bool{}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".tf") && !strings.HasSuffix(name, ".tf.json") {
			continue
		}
		if !want[name] {
			return fmt.Errorf("reviewed configuration directory %s contains unexpected configuration file %s", filepath.ToSlash(directory), name)
		}
		fileInfo, err := entry.Info()
		if err != nil || fileInfo.Mode()&os.ModeSymlink != 0 || !fileInfo.Mode().IsRegular() {
			return fmt.Errorf("reviewed configuration file %s must be a regular file", filepath.ToSlash(filepath.Join(directory, name)))
		}
		seen[name] = true
	}
	for name := range want {
		if !seen[name] {
			return fmt.Errorf("reviewed configuration directory %s is missing %s", filepath.ToSlash(directory), name)
		}
	}
	return nil
}

func readRegularFile(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("inspect file %s: %w", filepath.ToSlash(path), err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() > maximum {
		return nil, fmt.Errorf("file %s must be a bounded regular file", filepath.ToSlash(path))
	}
	return os.ReadFile(path)
}

func readArchivedFile(file *zip.File, maximum uint64) ([]byte, error) {
	if file == nil || file.UncompressedSize64 > maximum {
		return nil, fmt.Errorf("saved plan archive contains an oversized required entry")
	}
	reader, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("open saved plan archive entry %s: %w", file.Name, err)
	}
	defer reader.Close()
	content, err := io.ReadAll(io.LimitReader(reader, int64(maximum)+1))
	if err != nil {
		return nil, fmt.Errorf("read saved plan archive entry %s: %w", file.Name, err)
	}
	if uint64(len(content)) > maximum {
		return nil, fmt.Errorf("saved plan archive entry %s exceeds the size limit", file.Name)
	}
	return content, nil
}

func verifyArchivedPayload(file *zip.File, maximum uint64) error {
	if file == nil || file.UncompressedSize64 == 0 || file.UncompressedSize64 > maximum {
		return fmt.Errorf("saved plan archive payload is missing, empty, or oversized")
	}
	reader, err := file.Open()
	if err != nil {
		return fmt.Errorf("open saved plan archive payload: %w", err)
	}
	defer reader.Close()
	written, err := io.Copy(io.Discard, io.LimitReader(reader, int64(maximum)+1))
	if err != nil {
		return fmt.Errorf("verify saved plan archive payload: %w", err)
	}
	if written > int64(maximum) {
		return fmt.Errorf("saved plan archive payload exceeds the size limit")
	}
	return nil
}

func verifyArchivedModules(content []byte, contracts map[string]planModuleContract) error {
	var modules []archivedModule
	decoder := json.NewDecoder(bytes.NewReader(content))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&modules); err != nil {
		return fmt.Errorf("parse saved plan module inventory: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return fmt.Errorf("parse saved plan module inventory: %w", err)
	}
	if len(modules) != len(contracts) {
		return fmt.Errorf("saved plan module inventory must contain exactly %d modules", len(contracts))
	}
	seen := map[string]bool{}
	for _, module := range modules {
		contract, expected := contracts[module.Key]
		if !expected || seen[module.Key] {
			return fmt.Errorf("saved plan module inventory contains an unexpected or duplicate key")
		}
		seen[module.Key] = true
		if module.Dir != contract.directory {
			return fmt.Errorf("saved plan module %q directory does not match the reviewed local source", module.Key)
		}
		if module.Key == "" {
			if module.Source != nil {
				return fmt.Errorf("saved plan root module must not declare a source")
			}
		} else if module.Source == nil || *module.Source != contract.source {
			return fmt.Errorf("saved plan module %q source does not match the reviewed local module", module.Key)
		}
	}
	return nil
}

// Document is deliberately identifier-light and safe for short-lived CI artifacts.
type Document struct {
	SchemaVersion    string            `json:"schemaVersion"`
	Repository       string            `json:"repository"`
	SourceSHA        string            `json:"sourceSha"`
	SourceTreeSHA256 string            `json:"sourceTreeSha256"`
	Root             string            `json:"root"`
	PlanSHA256       string            `json:"planSha256"`
	ManifestSHA256   map[string]string `json:"manifestSha256"`
	Summary          plancheck.Summary `json:"summary"`
	CreatedAt        time.Time         `json:"createdAt"`
	ExpiresAt        time.Time         `json:"expiresAt"`
}

// ApprovalIdentity binds one named human approver to one immutable ECDSA
// public key. The digest is over the PKIX DER bytes, not transport PEM bytes.
type ApprovalIdentity struct {
	Principal       string `json:"principal"`
	PublicKeySHA256 string `json:"publicKeySha256"`
}

// ApprovalReceipt is deliberately small and canonical. Both independent
// approvers sign the exact compact JSON bytes of the complete receipt.
type ApprovalReceipt struct {
	SchemaVersion string             `json:"schemaVersion"`
	Operation     string             `json:"operation"`
	SourceSHA     string             `json:"sourceSha"`
	Root          string             `json:"root"`
	SubjectKind   string             `json:"subjectKind"`
	SubjectSHA256 string             `json:"subjectSha256"`
	PlanRunID     string             `json:"planRunId"`
	IssuedAt      time.Time          `json:"issuedAt"`
	ExpiresAt     time.Time          `json:"expiresAt"`
	Approvers     []ApprovalIdentity `json:"approvers"`
}

// VerifyApprovalReceipt verifies an expiry-bound two-person authorization
// before any privileged workload-identity exchange. Expected values are
// supplied by the protected workflow, never trusted from the receipt itself.
func VerifyApprovalReceipt(receiptPath string, publicKeyPaths, signaturePaths []string, expected ApprovalReceipt, now time.Time) (ApprovalReceipt, error) {
	receiptBytes, err := readRegularFile(receiptPath, maxApprovalReceiptBytes)
	if err != nil {
		return ApprovalReceipt{}, fmt.Errorf("read approval receipt: %w", err)
	}
	var receipt ApprovalReceipt
	decoder := json.NewDecoder(bytes.NewReader(receiptBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&receipt); err != nil {
		return receipt, fmt.Errorf("parse approval receipt: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return receipt, err
	}
	canonical, err := json.Marshal(receipt)
	if err != nil {
		return receipt, fmt.Errorf("canonicalize approval receipt: %w", err)
	}
	if !bytes.Equal(receiptBytes, canonical) {
		return receipt, fmt.Errorf("approval receipt must be exact canonical compact JSON")
	}
	if receipt.SchemaVersion != ApprovalReceiptSchemaVersion {
		return receipt, fmt.Errorf("unsupported approval receipt schema %q", receipt.SchemaVersion)
	}
	if receipt.Operation != expected.Operation || receipt.SourceSHA != expected.SourceSHA ||
		receipt.Root != expected.Root || receipt.SubjectKind != expected.SubjectKind ||
		receipt.SubjectSHA256 != expected.SubjectSHA256 || receipt.PlanRunID != expected.PlanRunID {
		return receipt, fmt.Errorf("approval receipt does not match the exact requested operation, source, root, subject digest, and plan run")
	}
	if receipt.Operation != "apply" && receipt.Operation != "recovery-observation" {
		return receipt, fmt.Errorf("unsupported approval operation %q", receipt.Operation)
	}
	if !fullSourceSHAPattern.MatchString(receipt.SourceSHA) || !hexSHA256Pattern.MatchString(receipt.SubjectSHA256) {
		return receipt, fmt.Errorf("approval receipt source and subject digests must be complete lowercase hashes")
	}
	if receipt.Operation == "apply" {
		if receipt.SubjectKind != "opentofu-saved-plan" || (receipt.Root != "root-trust" && receipt.Root != "recovery-plane") || !numericRunIDPattern.MatchString(receipt.PlanRunID) {
			return receipt, fmt.Errorf("apply approval must bind an OpenTofu saved plan, supported root, and numeric plan run")
		}
	} else if receipt.SubjectKind != "recovery-restore-manifest" || receipt.Root != "recovery-verification" || receipt.PlanRunID != "none" {
		return receipt, fmt.Errorf("recovery observation approval must bind the recovery restore manifest without pretending to authorize a plan")
	}
	issued := receipt.IssuedAt.UTC()
	expires := receipt.ExpiresAt.UTC()
	current := now.UTC()
	if !receipt.IssuedAt.Equal(issued.Truncate(time.Second)) || !receipt.ExpiresAt.Equal(expires.Truncate(time.Second)) {
		return receipt, fmt.Errorf("approval receipt timestamps must be whole UTC seconds")
	}
	if !expires.After(issued) || expires.Sub(issued) > 2*time.Hour {
		return receipt, fmt.Errorf("approval receipt validity must be positive and no longer than two hours")
	}
	if issued.After(current.Add(5 * time.Minute)) {
		return receipt, fmt.Errorf("approval receipt issue time is in the future")
	}
	if current.Before(issued) || !current.Before(expires) {
		return receipt, fmt.Errorf("approval receipt is not currently valid")
	}
	if len(receipt.Approvers) != 2 || len(publicKeyPaths) != 2 || len(signaturePaths) != 2 {
		return receipt, fmt.Errorf("approval receipt requires exactly two approvers, public keys, and signatures")
	}
	if receipt.Approvers[0].Principal >= receipt.Approvers[1].Principal {
		return receipt, fmt.Errorf("approval identities must be distinct and sorted by principal")
	}
	for index, approver := range receipt.Approvers {
		if !approvalPrincipalPattern.MatchString(approver.Principal) || !hexSHA256Pattern.MatchString(approver.PublicKeySHA256) {
			return receipt, fmt.Errorf("approval identity %d must contain a named user and SHA-256 public-key digest", index+1)
		}
		publicKeyBytes, err := readRegularFile(publicKeyPaths[index], maxApprovalReceiptBytes)
		if err != nil {
			return receipt, fmt.Errorf("read approval public key %d: %w", index+1, err)
		}
		block, trailing := pem.Decode(publicKeyBytes)
		if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(trailing)) != 0 {
			return receipt, fmt.Errorf("approval public key %d must be one PKIX PUBLIC KEY PEM block", index+1)
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return receipt, fmt.Errorf("parse approval public key %d: %w", index+1, err)
		}
		publicKey, ok := parsed.(*ecdsa.PublicKey)
		if !ok || publicKey.Curve != elliptic.P256() {
			return receipt, fmt.Errorf("approval public key %d must be ECDSA P-256", index+1)
		}
		if digest(block.Bytes) != approver.PublicKeySHA256 {
			return receipt, fmt.Errorf("approval public key %d digest mismatch", index+1)
		}
		signature, err := readRegularFile(signaturePaths[index], maxApprovalReceiptBytes)
		if err != nil {
			return receipt, fmt.Errorf("read approval signature %d: %w", index+1, err)
		}
		hash := sha256.Sum256(receiptBytes)
		if !ecdsa.VerifyASN1(publicKey, hash[:], signature) {
			return receipt, fmt.Errorf("approval signature %d is invalid", index+1)
		}
	}
	if receipt.Approvers[0].PublicKeySHA256 == receipt.Approvers[1].PublicKeySHA256 {
		return receipt, fmt.Errorf("approval public keys must be distinct")
	}
	return receipt, nil
}

// Create writes evidence bound to a plan and the seven manifests.
func Create(repositoryRoot, rootName, planPath, outputPath string, now time.Time) (Document, error) {
	if rootName != "root-trust" && rootName != "recovery-plane" {
		return Document{}, fmt.Errorf("unsupported root %q", rootName)
	}
	if _, err := manifest.ValidateRepository(repositoryRoot); err != nil {
		return Document{}, fmt.Errorf("validate source before evidence creation: %w", err)
	}
	planBytes, err := os.ReadFile(planPath)
	if err != nil {
		return Document{}, err
	}
	summary, err := plancheck.Analyze(planBytes)
	if err != nil {
		return Document{}, err
	}
	manifestDigests, err := digestManifests(repositoryRoot)
	if err != nil {
		return Document{}, err
	}
	sourceDigest, err := manifest.SourceDigest(repositoryRoot)
	if err != nil {
		return Document{}, err
	}
	document := Document{
		SchemaVersion:    SchemaVersion,
		Repository:       getenvDefault("GITHUB_REPOSITORY", "mindclade/bootstrap"),
		SourceSHA:        sourceSHA(repositoryRoot),
		SourceTreeSHA256: sourceDigest,
		Root:             rootName,
		PlanSHA256:       digest(planBytes),
		ManifestSHA256:   manifestDigests,
		Summary:          summary,
		CreatedAt:        now.UTC(),
		ExpiresAt:        now.UTC().Add(6 * time.Hour),
	}
	encoded, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return Document{}, err
	}
	encoded = append(encoded, '\n')
	if err := writePrivateFile(outputPath, encoded); err != nil {
		return Document{}, err
	}
	return document, nil
}

// Verify checks evidence integrity and freshness without contacting GCP.
func Verify(repositoryRoot, planPath, evidencePath string, now time.Time) (Document, error) {
	if _, err := manifest.ValidateRepository(repositoryRoot); err != nil {
		return Document{}, fmt.Errorf("validate source before evidence verification: %w", err)
	}
	evidenceBytes, err := os.ReadFile(evidencePath)
	if err != nil {
		return Document{}, err
	}
	var document Document
	decoder := json.NewDecoder(bytes.NewReader(evidenceBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&document); err != nil {
		return Document{}, fmt.Errorf("parse evidence: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return Document{}, err
	}
	if document.SchemaVersion != SchemaVersion {
		return document, fmt.Errorf("unsupported evidence schema %q", document.SchemaVersion)
	}
	if document.Repository != getenvDefault("GITHUB_REPOSITORY", "mindclade/bootstrap") {
		return document, fmt.Errorf("evidence repository mismatch")
	}
	if document.SourceSHA != sourceSHA(repositoryRoot) {
		return document, fmt.Errorf("evidence source SHA mismatch")
	}
	sourceDigest, err := manifest.SourceDigest(repositoryRoot)
	if err != nil {
		return document, err
	}
	if document.SourceTreeSHA256 != sourceDigest {
		return document, fmt.Errorf("evidence source tree digest mismatch")
	}
	if document.Root != "root-trust" && document.Root != "recovery-plane" {
		return document, fmt.Errorf("unsupported evidence root %q", document.Root)
	}
	if !document.ExpiresAt.Equal(document.CreatedAt.Add(6 * time.Hour)) {
		return document, fmt.Errorf("evidence validity window must be exactly six hours")
	}
	if document.CreatedAt.After(now.UTC().Add(5 * time.Minute)) {
		return document, fmt.Errorf("evidence creation time is in the future")
	}
	planBytes, err := os.ReadFile(planPath)
	if err != nil {
		return document, err
	}
	if document.PlanSHA256 != digest(planBytes) {
		return document, fmt.Errorf("plan digest mismatch")
	}
	if !now.UTC().Before(document.ExpiresAt) {
		return document, fmt.Errorf("plan evidence expired at %s", document.ExpiresAt.Format(time.RFC3339))
	}
	currentDigests, err := digestManifests(repositoryRoot)
	if err != nil {
		return document, err
	}
	if !mapsEqual(document.ManifestSHA256, currentDigests) {
		return document, fmt.Errorf("manifest digest mismatch")
	}
	summary, err := plancheck.Analyze(planBytes)
	if err != nil {
		return document, err
	}
	if summary.Creates != document.Summary.Creates || summary.Updates != document.Summary.Updates ||
		summary.Deletes != document.Summary.Deletes || summary.Replaces != document.Summary.Replaces ||
		summary.Reads != document.Summary.Reads || len(document.Summary.Violations) != 0 {
		return document, fmt.Errorf("plan summary mismatch")
	}
	return document, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("parse evidence: trailing JSON value")
		}
		return fmt.Errorf("parse evidence: %w", err)
	}
	return nil
}

func digestManifests(root string) (map[string]string, error) {
	paths, err := filepath.Glob(filepath.Join(root, "manifests", "*.yaml"))
	if err != nil {
		return nil, err
	}
	sort.Strings(paths)
	if len(paths) != 7 {
		return nil, fmt.Errorf("expected seven manifests, found %d", len(paths))
	}
	result := map[string]string{}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		result[filepath.Base(path)] = digest(data)
	}
	return result, nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func sourceSHA(root string) string {
	status := exec.Command("git", "-C", root, "status", "--porcelain=v1", "--untracked-files=all")
	statusOutput, err := status.Output()
	if err != nil || len(stringTrimSpace(statusOutput)) != 0 {
		return "uncommitted-source"
	}
	command := exec.Command("git", "-C", root, "rev-parse", "HEAD")
	output, err := command.Output()
	if err != nil {
		return "uncommitted-source"
	}
	head := stringTrimSpace(output)
	if value := os.Getenv("GITHUB_SHA"); value != "" && value != head {
		return "uncommitted-source"
	}
	return head
}

func writePrivateFile(path string, data []byte) error {
	directory := filepath.Dir(path)
	temporary, err := os.CreateTemp(directory, ".bootstrap-evidence-*")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		_ = temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(temporaryPath, path)
}

func stringTrimSpace(value []byte) string {
	start, end := 0, len(value)
	for start < end && (value[start] == ' ' || value[start] == '\n' || value[start] == '\r' || value[start] == '\t') {
		start++
	}
	for end > start && (value[end-1] == ' ' || value[end-1] == '\n' || value[end-1] == '\r' || value[end-1] == '\t') {
		end--
	}
	return string(value[start:end])
}

func mapsEqual(left, right map[string]string) bool {
	if len(left) != len(right) {
		return false
	}
	for key, value := range left {
		if right[key] != value {
			return false
		}
	}
	return true
}

func getenvDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
