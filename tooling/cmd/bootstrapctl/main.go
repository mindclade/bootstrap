// bootstrapctl validates and inspects Mindclade Ring-0 source. It never applies infrastructure.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/mindclade/bootstrap/tooling/internal/evidence"
	"github.com/mindclade/bootstrap/tooling/internal/manifest"
	plancheck "github.com/mindclade/bootstrap/tooling/internal/plan"
	"github.com/mindclade/bootstrap/tooling/internal/recovery"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "validate":
		err = validate(os.Args[2:])
	case "plan-check":
		err = planCheck(os.Args[2:])
	case "plan-resource-check":
		err = planResourceCheck(os.Args[2:])
	case "plan-source-check":
		err = planSourceCheck(os.Args[2:])
	case "evidence":
		err = evidenceCommand(os.Args[2:])
	case "approval":
		err = approvalCommand(os.Args[2:])
	case "recovery-verify":
		err = recoveryVerify(os.Args[2:])
	case "render-vars":
		err = renderVars(os.Args[2:])
	case "source-files":
		if len(os.Args) != 2 {
			err = fmt.Errorf("source-files does not accept arguments")
			break
		}
		printJSON(manifest.ExpectedFiles())
	case "help", "-h", "--help":
		usage()
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "bootstrapctl:", err)
		os.Exit(1)
	}
}

func approvalCommand(args []string) error {
	if len(args) == 0 || args[0] != "verify" {
		return fmt.Errorf("approval requires verify")
	}
	flags := flag.NewFlagSet("approval verify", flag.ContinueOnError)
	receiptPath := flags.String("receipt", "", "canonical approval receipt JSON")
	publicKeyOne := flags.String("public-key-1", "", "first approver PKIX ECDSA public key")
	publicKeyTwo := flags.String("public-key-2", "", "second approver PKIX ECDSA public key")
	signatureOne := flags.String("signature-1", "", "first detached ASN.1 ECDSA signature")
	signatureTwo := flags.String("signature-2", "", "second detached ASN.1 ECDSA signature")
	operation := flags.String("operation", "", "apply or recovery-observation")
	sourceSHA := flags.String("source-sha", "", "expected protected source SHA")
	root := flags.String("root", "", "expected root or recovery-verification")
	subjectKind := flags.String("subject-kind", "", "expected approved subject kind")
	subjectSHA256 := flags.String("subject-sha256", "", "expected saved-plan or restore-manifest SHA-256")
	planRunID := flags.String("plan-run-id", "", "expected plan run ID or none")
	nowValue := flags.String("now", "", "verification time for tests, RFC3339 UTC")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("approval verify does not accept positional arguments")
	}
	for name, value := range map[string]string{
		"--receipt": *receiptPath, "--public-key-1": *publicKeyOne, "--public-key-2": *publicKeyTwo,
		"--signature-1": *signatureOne, "--signature-2": *signatureTwo, "--operation": *operation,
		"--source-sha": *sourceSHA, "--root": *root, "--subject-kind": *subjectKind,
		"--subject-sha256": *subjectSHA256, "--plan-run-id": *planRunID,
	} {
		if value == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	now := time.Now()
	if *nowValue != "" {
		parsed, err := time.Parse(time.RFC3339, *nowValue)
		if err != nil {
			return fmt.Errorf("parse --now: %w", err)
		}
		now = parsed
	}
	receipt, err := evidence.VerifyApprovalReceipt(
		*receiptPath,
		[]string{*publicKeyOne, *publicKeyTwo},
		[]string{*signatureOne, *signatureTwo},
		evidence.ApprovalReceipt{
			Operation: *operation, SourceSHA: *sourceSHA, Root: *root,
			SubjectKind: *subjectKind, SubjectSHA256: *subjectSHA256, PlanRunID: *planRunID,
		},
		now,
	)
	printJSON(receipt)
	return err
}

func renderVars(args []string) error {
	flags := flag.NewFlagSet("render-vars", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	composition := flags.String("composition", "", "root-trust or recovery-plane")
	values := flags.String("values", "", "path to exact non-secret JSON string map")
	context := flags.String("context", "", "path to exact recovery root-output context projection")
	output := flags.String("output", "", "private output tfvars JSON path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("render-vars does not accept positional arguments")
	}
	if *composition == "" || *values == "" || *output == "" {
		return fmt.Errorf("--composition, --values, and --output are required")
	}
	result, err := manifest.RenderVariables(*root, *composition, *values, *context, *output)
	if err != nil {
		return err
	}
	printJSON(result)
	return nil
}

func validate(args []string) error {
	flags := flag.NewFlagSet("validate", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(args); err != nil {
		return err
	}
	result, err := manifest.ValidateRepository(*root)
	printJSON(result)
	return err
}

func planCheck(args []string) error {
	flags := flag.NewFlagSet("plan-check", flag.ContinueOnError)
	path := flags.String("plan", "", "path to tofu show -json output")
	root := flags.String("root", "", "root-trust or recovery-plane composition")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *path == "" || *root == "" {
		return fmt.Errorf("--plan and --root are required")
	}
	result, err := plancheck.AnalyzeFileForRoot(*path, *root)
	printJSON(result)
	return err
}

// planResourceCheck exercises the resource-level policy classifier without
// asserting composition completeness. It is a diagnostic command and is never
// an authorization substitute for root-aware plan-check.
func planResourceCheck(args []string) error {
	flags := flag.NewFlagSet("plan-resource-check", flag.ContinueOnError)
	path := flags.String("plan", "", "path to a tofu show -json policy fragment")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *path == "" {
		return fmt.Errorf("--plan is required")
	}
	result, err := plancheck.AnalyzeFile(*path)
	printJSON(result)
	return err
}

// planSourceCheck verifies the exact HCL snapshot embedded in an OpenTofu
// saved plan. This check must accompany plan-check before any saved-plan apply.
func planSourceCheck(args []string) error {
	flags := flag.NewFlagSet("plan-source-check", flag.ContinueOnError)
	path := flags.String("saved-plan", "", "path to the OpenTofu saved-plan archive")
	opentofuRoot := flags.String("opentofu-root", "", "reviewed OpenTofu source root")
	providerLock := flags.String("provider-lock", "", "generated provider lock embedded in the saved plan (defaults to the reviewed root lock)")
	root := flags.String("root", "", "root-trust or recovery-plane composition")
	initialLocalBackend := flags.Bool("initial-local-backend", false, "permit only the documented first root-trust backend.tf omission")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("plan-source-check does not accept positional arguments")
	}
	if *path == "" || *opentofuRoot == "" || *root == "" {
		return fmt.Errorf("--saved-plan, --opentofu-root, and --root are required")
	}
	if err := evidence.VerifyPlanConfiguration(*path, *opentofuRoot, *providerLock, *root, *initialLocalBackend); err != nil {
		return err
	}
	printJSON(map[string]any{"root": *root, "sourceSnapshot": "verified"})
	return nil
}

func evidenceCommand(args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("evidence requires create or verify")
	}
	switch args[0] {
	case "create":
		flags := flag.NewFlagSet("evidence create", flag.ContinueOnError)
		repositoryRoot := flags.String("repository-root", ".", "repository root")
		root := flags.String("root", "", "root-trust or recovery-plane")
		plan := flags.String("plan", "", "path to plan JSON")
		output := flags.String("output", "", "evidence output path")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *plan == "" || *output == "" {
			return fmt.Errorf("--plan and --output are required")
		}
		document, err := evidence.Create(*repositoryRoot, *root, *plan, *output, time.Now())
		printJSON(document)
		return err
	case "verify":
		flags := flag.NewFlagSet("evidence verify", flag.ContinueOnError)
		repositoryRoot := flags.String("repository-root", ".", "repository root")
		plan := flags.String("plan", "", "path to plan JSON")
		evidencePath := flags.String("evidence", "", "evidence path")
		if err := flags.Parse(args[1:]); err != nil {
			return err
		}
		if *plan == "" || *evidencePath == "" {
			return fmt.Errorf("--plan and --evidence are required")
		}
		document, err := evidence.Verify(*repositoryRoot, *plan, *evidencePath, time.Now())
		printJSON(document)
		return err
	default:
		return fmt.Errorf("unknown evidence command %q", args[0])
	}
}

func recoveryVerify(args []string) error {
	flags := flag.NewFlagSet("recovery-verify", flag.ContinueOnError)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := recovery.Verify(*root); err != nil {
		return err
	}
	printJSON(map[string]any{"status": "source-qualified", "mode": "isolated-source-simulation"})
	return nil
}

func printJSON(value any) {
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	_ = encoder.Encode(value)
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: bootstrapctl <validate|render-vars|plan-check|plan-resource-check|plan-source-check|evidence|approval|recovery-verify|source-files> [options]")
	os.Exit(2)
}
