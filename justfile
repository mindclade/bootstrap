set dotenv-load := false
set positional-arguments
set shell := ["bash", "-euo", "pipefail", "-c"]

repo_root := justfile_directory()

default:
    @just --list

fmt:
    tofu fmt -recursive opentofu
    gofmt -w tooling/cmd/bootstrapctl/main.go tooling/internal/*/*.go

fmt-check:
    tofu fmt -check -recursive opentofu
    @unformatted="$(gofmt -l tooling/cmd/bootstrapctl/main.go tooling/internal/*/*.go)"; test -z "$unformatted" || { printf '%s\n' "$unformatted"; exit 1; }

validate-manifests:
    go -C "{{ repo_root }}/tooling" run ./cmd/bootstrapctl validate --root "{{ repo_root }}"

validate-policy:
    conftest fmt --check --rego-version v1 policy
    conftest verify --policy policy
    conftest test manifests --policy policy --all-namespaces

validate-tofu:
    @validation_dir="$(mktemp -d)"; trap 'rm -rf "$validation_dir"' EXIT; \
      cp -R opentofu manifests "$validation_dir/"; \
      case "$(uname -s)/$(uname -m)" in \
        Linux/x86_64) provider_platform="linux_amd64"; provider_checksum="5b4bac33f039f94384a0b3468f63266fac023f69c00ebbc573d957b861f67171" ;; \
        Darwin/arm64) provider_platform="darwin_arm64"; provider_checksum="f028a366d9c7f427d3ed1a34df22c4476b6ebed4e8884b23e448ef1fb170eb44" ;; \
        *) printf 'unsupported provider qualification platform: %s/%s\n' "$(uname -s)" "$(uname -m)" >&2; exit 1 ;; \
      esac; \
      provider_probe="$validation_dir/provider-probe"; \
      if test -n "${BOOTSTRAP_PROVIDER_MIRROR:-}"; then \
        case "${BOOTSTRAP_PROVIDER_MIRROR}" in /*) ;; *) printf 'BOOTSTRAP_PROVIDER_MIRROR must be an absolute path\n' >&2; exit 1 ;; esac; \
        test -d "${BOOTSTRAP_PROVIDER_MIRROR}"; \
        test ! -L "${BOOTSTRAP_PROVIDER_MIRROR}"; \
        provider_mirror="${BOOTSTRAP_PROVIDER_MIRROR}"; \
      else \
        provider_mirror="$validation_dir/provider-mirror"; \
        mkdir -p "$provider_probe" "$provider_mirror"; \
        printf '%s\n' \
          'terraform {' \
          '  required_providers {' \
          '    google = {' \
          '      source  = "hashicorp/google"' \
          '      version = "7.42.0"' \
          '    }' \
          '  }' \
          '}' >"$provider_probe/versions.tf"; \
        tofu -chdir="$provider_probe" providers mirror -platform="$provider_platform" "$provider_mirror"; \
      fi; \
      provider_package="$provider_mirror/registry.opentofu.org/hashicorp/google/terraform-provider-google_7.42.0_${provider_platform}.zip"; \
      test -f "$provider_package"; \
      test ! -L "$provider_package"; \
      if command -v sha256sum >/dev/null 2>&1; then \
        actual_checksum="$(sha256sum "$provider_package" | cut -d ' ' -f1)"; \
      else \
        actual_checksum="$(shasum -a 256 "$provider_package" | cut -d ' ' -f1)"; \
      fi; \
      test "$actual_checksum" = "$provider_checksum"; \
      provider_config="$validation_dir/provider-installation.tfrc"; \
      printf 'provider_installation {\n  filesystem_mirror {\n    path    = "%s"\n    include = ["hashicorp/google"]\n  }\n  direct {\n    exclude = ["hashicorp/google"]\n  }\n}\n' "$provider_mirror" >"$provider_config"; \
      for ring0_root in root-trust recovery-plane; do \
        tofu_data_dir="$validation_dir/.tofu-${ring0_root}"; \
        TF_CLI_CONFIG_FILE="$provider_config" TF_DATA_DIR="$tofu_data_dir" tofu -chdir="$validation_dir/opentofu/live/${ring0_root}" init -backend=false -input=false; \
        lock_file="$validation_dir/opentofu/live/${ring0_root}/.terraform.lock.hcl"; \
        grep -Fq 'version     = "7.42.0"' "$lock_file"; \
        TF_CLI_CONFIG_FILE="$provider_config" TF_DATA_DIR="$tofu_data_dir" tofu -chdir="$validation_dir/opentofu/live/${ring0_root}" validate; \
      done

lint-ci:
    actionlint -ignore 'label "mindclade-ring0-ephemeral" is unknown' .github/workflows/*.yml

test-go:
    cd tooling && go test ./... && go vet ./...

test-python:
    PYTHONDONTWRITEBYTECODE=1 python3 -m unittest \
      tests/contract/test_manifest_schemas.py \
      tests/plan/test_minimum_privilege.py \
      tests/failure/test_partial_bootstrap_apply.py \
      tests/recovery/test_isolated_restore.py

test-bazel:
    USE_BAZEL_VERSION=9.1.1 bazel test --lockfile_mode=off //...

test: test-go test-python test-bazel

validate: fmt-check validate-manifests validate-policy validate-tofu lint-ci test

ci: validate

plan-check root plan_json:
    @case "{{ plan_json }}" in /*) plan_path="{{ plan_json }}" ;; *) plan_path="{{ repo_root }}/{{ plan_json }}" ;; esac; \
      go -C "{{ repo_root }}/tooling" run ./cmd/bootstrapctl plan-check --root "{{ root }}" --plan "$plan_path"

evidence plan_json ring0_root output:
    @case "{{ plan_json }}" in /*) plan_path="{{ plan_json }}" ;; *) plan_path="{{ repo_root }}/{{ plan_json }}" ;; esac; \
      case "{{ output }}" in /*) output_path="{{ output }}" ;; *) output_path="{{ repo_root }}/{{ output }}" ;; esac; \
      go -C "{{ repo_root }}/tooling" run ./cmd/bootstrapctl evidence create --repository-root "{{ repo_root }}" --plan "$plan_path" --root "{{ ring0_root }}" --output "$output_path"

recovery-verify:
    go -C "{{ repo_root }}/tooling" run ./cmd/bootstrapctl recovery-verify --root "{{ repo_root }}"
