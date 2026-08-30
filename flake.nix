{
  description = "Pinned system toolchain for github.com/mindclade/bootstrap";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "aarch64-darwin"
        "x86_64-linux"
      ];
      forAllSystems =
        function:
        builtins.listToAttrs (
          map (system: {
            name = system;
            value = function system (import nixpkgs { inherit system; });
          }) systems
        );
    in
    {
      packages = forAllSystems (
        system: pkgs:
        let
          conftestTarget =
            {
              aarch64-darwin = {
                asset = "Darwin_arm64";
                hash = "sha256-eDAtBF8OxS6XhqBsbGIaxFFrTF3R5U78gFDIbCm5ZNk=";
              };
              x86_64-linux = {
                asset = "Linux_x86_64";
                hash = "sha256-lvwvvxHwr95RJWZHEn5vAKZM6Dmk2aChrvJCbA5vSz8=";
              };
            }
            .${system};
          conftest = pkgs.runCommand "conftest-0.69.0" {
            nativeBuildInputs = [
              pkgs.gnutar
              pkgs.gzip
            ];
          } ''
            archive=${pkgs.fetchurl {
              url = "https://github.com/open-policy-agent/conftest/releases/download/v0.69.0/conftest_0.69.0_${conftestTarget.asset}.tar.gz";
              inherit (conftestTarget) hash;
            }}
            mkdir -p "$TMPDIR/unpack"
            tar -xzf "$archive" -C "$TMPDIR/unpack"
            install -D -m 0755 "$TMPDIR/unpack/conftest" "$out/bin/conftest"
          '';
          opaTarget =
            {
              aarch64-darwin = {
                asset = "opa_darwin_arm64";
                hash = "sha256-K4BdR2CZ+Bgo4KckZvI7fF9wNejlGCP14e88v08jIc4=";
              };
              x86_64-linux = {
                asset = "opa_linux_amd64";
                hash = "sha256-SBTKr4kGK5kp5zc8dF6xtzvoqjR75h2gZJH2j+kQJFs=";
              };
            }
            .${system};
          opa = pkgs.runCommand "opa-1.20.1" { } ''
            install -D -m 0755 ${pkgs.fetchurl {
              url = "https://github.com/open-policy-agent/opa/releases/download/v1.20.1/${opaTarget.asset}";
              inherit (opaTarget) hash;
            }} "$out/bin/opa"
          '';
          tofuTarget =
            {
              aarch64-darwin = {
                asset = "darwin_arm64";
                hash = "sha256-4IPuQ3kKueGa1m2ZM+JKckShQS4dVyjzeZmuIWP9rJU=";
              };
              x86_64-linux = {
                asset = "linux_amd64";
                hash = "sha256-XcQ9pPdQ8zhz3CXpRYcShwnoGeVEt76QFrJVMWFTw6g=";
              };
            }
            .${system};
          tofu = pkgs.runCommand "opentofu-1.12.6" { nativeBuildInputs = [ pkgs.unzip ]; } ''
            archive=${pkgs.fetchurl {
              url = "https://github.com/opentofu/opentofu/releases/download/v1.12.6/tofu_1.12.6_${tofuTarget.asset}.zip";
              inherit (tofuTarget) hash;
            }}
            mkdir -p "$TMPDIR/unpack"
            unzip -q "$archive" -d "$TMPDIR/unpack"
            install -D -m 0755 "$TMPDIR/unpack/tofu" "$out/bin/tofu"
          '';
          toolchainPackages =
            with pkgs;
            [
            actionlint
            bash
            bazelisk
            cacert
            conftest
            coreutils
            curl
            findutils
            git
            gnugrep
            gnused
            gnutar
            go_1_26
            google-cloud-sdk
            gzip
            jq
            just
            nixfmt-rfc-style
            opa
            openssl
            python314
            shellcheck
            tofu
            unzip
            yamllint
              yq-go
            ]
            ++ lib.optionals stdenv.hostPlatform.isDarwin [ darwin.libresolv ];
          toolchain = pkgs.buildEnv {
            name = "mindclade-bootstrap-toolchain";
            paths = toolchainPackages;
            pathsToLink = [
              "/bin"
              "/share"
            ];
            ignoreCollisions = false;
          };
        in
        {
          inherit toolchain;
          default = toolchain;
        }
      );

      devShells = forAllSystems (
        system: pkgs:
        let
          toolchain = self.packages.${system}.toolchain;
          darwinDeploymentTarget = pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isDarwin "14.0";
          common = {
            packages = [ toolchain ];
            BAZEL_NIX_LINKOPT = pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isDarwin "-L${pkgs.darwin.libresolv}/lib";
            MACOSX_DEPLOYMENT_TARGET = darwinDeploymentTarget;
            LANG = "C.UTF-8";
            LC_ALL = "C.UTF-8";
            TZ = "UTC";
            USE_BAZEL_VERSION = "9.1.1";
          };
        in
        {
          default = pkgs.mkShell common;
          ci = pkgs.mkShell (common // { CI = "true"; });
        }
      );

      formatter = forAllSystems (_: pkgs: pkgs.nixfmt-rfc-style);

      checks = forAllSystems (
        system: pkgs:
        let
          toolchain = self.packages.${system}.toolchain;
          darwinDeploymentTarget = pkgs.lib.optionalString pkgs.stdenv.hostPlatform.isDarwin "14.0";
          bootstrapctl = pkgs.buildGoModule {
            pname = "bootstrapctl";
            version = "0.0.0";
            src = "${self}/tooling";
            vendorHash = pkgs.lib.fakeHash;
            subPackages = [ "cmd/bootstrapctl" ];
          };
        in
        {
          toolchain = pkgs.runCommand "mindclade-bootstrap-toolchain-check" {
            nativeBuildInputs = [ toolchain ];
          } ''
            set -euo pipefail
            test "$(actionlint -version | head -n1)" = "1.7.12"
            test "$(conftest --version | head -n1)" = "Conftest: 0.69.0"
            test "$(go version | awk '{print $3}')" = "go1.26.7"
            test "$(just --version)" = "just 1.58.0"
            test "$(opa version | awk '/^Version:/ {print $2}')" = "1.20.1"
            test "$(python3 -c 'import platform; print(platform.python_version())')" = "3.14.7"
            test "$(tofu version -json | jq -r .terraform_version)" = "1.12.6"
            test "${pkgs.bazelisk.version}" = "1.29.0"
            test "${pkgs.google-cloud-sdk.version}" = "581.0.0"
            if test "${system}" = "aarch64-darwin"; then
              test "${darwinDeploymentTarget}" = "14.0"
            else
              test -z "${darwinDeploymentTarget}"
            fi
            grep -Fq 'go_sdk.download(version = "1.26.7")' ${self}/MODULE.bazel
            grep -Fq 'python_version = "3.14.7"' ${self}/MODULE.bazel
            grep -Fq 'USE_BAZEL_VERSION=9.1.1 bazelisk test' ${self}/justfile
            mkdir -p "$out"
            printf '%s\n' '${nixpkgs.rev}' > "$out/nixpkgs-revision"
          '';

          source = pkgs.runCommand "mindclade-bootstrap-source-check" {
            nativeBuildInputs = [
              bootstrapctl
              toolchain
            ];
          } ''
            set -euo pipefail
            mkdir -p "$out"
            bootstrapctl validate --root ${self} > "$out/validation.json"
            conftest verify --policy ${self}/policy > "$out/policy-verify.txt"
            conftest test ${self}/manifests --policy ${self}/policy --all-namespaces \
              > "$out/policy-test.txt"
          '';
        }
      );
    };
}
