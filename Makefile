include helper.mk

.PHONY: all app app-ci install dmg clean help \
        lint-swift lint-rust lint-invariants lint-invariants-selftest lint-license lint-third-party-licenses lint \
        format-swift format-rust format format-check-swift format-check-rust format-check \
        security-rust security test-swift test-rust test ci \
        check-source-signing-inputs \
        check-notary-auth check-release-build-sequence check-release-build-sequence-selftest check-build-order-selftest check-uninstall-selftest print-build-number \
        notarize notarize-check staple release release-build \
        sparkle-sign sparkle-keys \
        deps-update deps-check third-party-licenses

help:
	@echo "MacDNS Build System"
	@echo ""
	@echo "Build Commands:"
	@echo "  make app            - Build release .app bundle (universal binary)"
	@echo "  make dmg            - Build .app and create DMG for distribution"
	@echo ""
	@echo "Install:"
	@echo "  make install        - Install MacDNS.app to /Applications"
	@echo ""
	@echo "Distribution:"
	@echo "  make release        - Full release from .env or CI secrets: build, notarize, staple, sign with Sparkle"
	@echo "                        (build sequence derived from UTC time; override with"
	@echo "                        RELEASE_BUILD_SEQUENCE=<monotonic integer>)"
	@echo "  make notarize       - Submit DMG for notarization (requires dmg first)"
	@echo "  make notarize-check - Check notarization status"
	@echo "  make staple         - Staple notarization ticket to DMG"
	@echo "  make sparkle-sign   - Sign DMG with EdDSA and generate appcast.xml"
	@echo "  make sparkle-keys   - Generate Sparkle EdDSA keys (run once)"
	@echo ""
	@echo "CI Commands:"
	@echo "  make ci             - Canonical gate: lint + format + security + test + app-ci"
	@echo "  make app-ci         - Build non-runnable universal app bundle for CI validation"
	@echo "  make lint           - Run all linting (Swift + Rust + invariants + license)"
	@echo "  make lint-swift     - Run Swift linting"
	@echo "  make lint-rust      - Run Rust linting"
	@echo "  make lint-invariants - Enforce the critical invariants documented in AGENTS.md"
	@echo "  make lint-invariants-selftest - Prove the invariant rules still fire"
	@echo "  make lint-license   - Check every file declares copyright and license (REUSE)"
	@echo "  make lint-third-party-licenses - Check THIRD_PARTY_LICENSES.txt matches the dependencies"
	@echo "  make format         - Auto-format code (Swift + Rust)"
	@echo "  make format-check   - Check code formatting"
	@echo "  make security       - Run security audit"
	@echo "  make test           - Run all tests"
	@echo "  make check-source-signing-inputs - Validate proxy-control source inputs (no certificates)"
	@echo "  make check-release-build-sequence-selftest - Prove the build sequence is derived, numeric and exported"
	@echo "  make check-build-order-selftest - Verify release and assembly ordering with local stubs"
	@echo "  make check-uninstall-selftest - Verify Scripts/uninstall.sh in a sandbox with local stubs"
	@echo ""
	@echo "Dependencies:"
	@echo "  make deps-update    - Update all dependencies to latest stable versions"
	@echo "  make deps-check     - Check for outdated dependencies"
	@echo "  make third-party-licenses - Regenerate THIRD_PARTY_LICENSES.txt for the app bundle"
	@echo ""
	@echo "Cleanup:"
	@echo "  make clean          - Remove all build artifacts"
	@echo ""

all: app

app:
	@$(MAKE) -C Sources/MacDNS app-bundle

app-ci:
	@$(MAKE) -C Sources/MacDNS app-bundle SIGNING_MODE=ci

# Validates the proxy-control source inputs without a build or any signing
# asset, so CI can fail fast on a broken control-plane configuration.
check-source-signing-inputs:
	@$(MAKE) -C Sources/MacDNS check_source_signing_inputs

dmg:
	@$(MAKE) -C Sources/MacDNS dmg

install:
	@if [ ! -d "$(APP_BUNDLE)" ]; then \
		echo "Error: MacDNS.app not found. Run 'make app' first."; \
		exit 1; \
	fi
	@echo "Stopping MacDNS"
	@sudo pkill -x MacDNS 2>/dev/null || true
	@# Unload LaunchAgent BEFORE copying to prevent auto-restart race condition
	@launchctl bootout gui/$$(id -u)/app.macdns.agent 2>/dev/null || true
	@sleep 5
	@sudo pkill -9 -x MacDNS 2>/dev/null || true
	@sudo pkill -9 -x MacDNSAgent 2>/dev/null || true
	@sudo pkill -9 -x app.macdns.dnsproxy 2>/dev/null || true
	@echo "Installing MacDNS.app to /Applications..."
	@sudo rm -rf /Applications/MacDNS.app
	@sudo cp -R $(APP_BUNDLE) /Applications/
	@echo "MacDNS.app installed successfully!"
	@echo ""
	@echo "To run: open /Applications/MacDNS.app"

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf build
	@rm -rf .build
	@cd $(RUST_RESOLVER_DIR) && cargo clean
	@$(MAKE) -C Sources/MacDNS clean
	@echo "Clean complete"

SWIFTFORMAT_BIN = .build/release/swift-format

lint-swift:
	@echo "=== Swift Lint ==="
	@if [ ! -f "$(SWIFTFORMAT_BIN)" ]; then \
		echo "swift-format binary not found, building..."; \
		swift build -c release --product swift-format; \
	fi
	@$(SWIFTFORMAT_BIN) lint --strict --recursive Sources/

lint-rust:
	@echo "=== Rust Lint ==="
	@cd $(RUST_RESOLVER_DIR) && cargo clippy --locked --all-targets -- -D warnings

# Mechanical enforcement of the critical invariants documented in AGENTS.md.
# Pure POSIX shell + awk, so it adds no toolchain dependency and stays fast
# enough to run on every `make ci`.
lint-invariants:
	@sh Scripts/invariant-lint/run.sh

# Proves the invariant rules still fire, by running them against synthetic
# fixtures that violate each invariant on purpose. Deliberately NOT part of
# `lint` or `ci`: it validates the lint, it does not lint the tree. Run it when
# changing a rule, a shared helper, or the runner.
lint-invariants-selftest:
	@sh Scripts/invariant-lint/selftest/run.sh

# Every tracked file must declare its copyright and license, in a header or in
# REUSE.toml. See LICENSES/ for the license texts.
lint-license:
	@echo "=== License Lint ==="
	@if reuse --version >/dev/null 2>&1; then \
		reuse lint; \
	else \
		echo "reuse not found. Install with: brew install reuse"; \
		exit 1; \
	fi

third-party-licenses:
	@Scripts/third-party-licenses.sh

lint-third-party-licenses:
	@echo "=== Third-Party Licenses Lint ==="
	@Scripts/third-party-licenses.sh --check

# Invariants run first: they are the cheapest check in the pipeline and they fail
# on architectural regressions, so CI should not spend minutes on swift-format
# and clippy before reporting one.
lint: lint-invariants lint-license lint-third-party-licenses lint-swift lint-rust

format-swift:
	@echo "=== Swift Format (auto-fix) ==="
	@if [ ! -f "$(SWIFTFORMAT_BIN)" ]; then \
		echo "swift-format binary not found, building..."; \
		swift build -c release --product swift-format; \
	fi
	@$(SWIFTFORMAT_BIN) --in-place --recursive Sources/

format-check-swift:
	@echo "=== Swift Format Check ==="
	@if [ ! -f "$(SWIFTFORMAT_BIN)" ]; then \
		echo "swift-format binary not found, building..."; \
		swift build -c release --product swift-format; \
	fi
	@$(SWIFTFORMAT_BIN) lint --recursive Sources/

format-rust:
	@echo "=== Rust Format (auto-fix) ==="
	@cd $(RUST_RESOLVER_DIR) && cargo fmt

format-check-rust:
	@echo "=== Rust Format Check ==="
	@cd $(RUST_RESOLVER_DIR) && cargo fmt --check

format: format-swift format-rust

format-check: format-check-swift format-check-rust

# cargo audit only checks registry packages, so the vendored Hickory crates are
# marked as crates.io entries in a copy of Cargo.lock before the scan.
security-rust:
	@echo "=== Rust Security Audit ==="
	@if cargo audit --version >/dev/null 2>&1; then \
		mkdir -p "$(REPO_ROOT)/.build"; \
		audit_log="$(REPO_ROOT)/.build/cargo-audit.log"; \
		audit_lock="$(REPO_ROOT)/.build/Cargo.audit.lock"; \
		awk '/^\[\[package\]\]/ { patched = 0; has_source = 0 } \
			/^name = "hickory-(net|resolver)"$$/ { patched = 1 } \
			/^source = / { has_source = 1 } \
			patched && !has_source && /^dependencies =/ { \
				print "source = \"registry+https://github.com/rust-lang/crates.io-index\""; has_source = 1 \
			} { print }' "$(RUST_RESOLVER_DIR)/Cargo.lock" > "$$audit_lock" || exit 1; \
		(cd $(RUST_RESOLVER_DIR) && cargo audit --file "$$audit_lock" > "$$audit_log" 2>&1); \
		audit_status=$$?; \
		cat "$$audit_log"; \
		if [ $$audit_status -ne 0 ]; then \
			exit $$audit_status; \
		fi; \
		if grep -q '^error:' "$$audit_log"; then \
			echo "cargo audit reported errors but exited successfully; failing CI"; \
			exit 1; \
		fi; \
	else \
		echo "cargo-audit not found. Install with: cargo install cargo-audit"; \
		exit 1; \
	fi

security: security-rust

test-swift:
	@echo "=== Swift Tests ==="
	@if [ -d "Tests" ]; then \
		swift test $(SWIFTPM_WARNING_FLAGS); \
	else \
		echo "No Swift tests found (Tests/ directory does not exist)"; \
	fi

test-rust:
	@echo "=== Rust Tests ==="
	@cd $(RUST_RESOLVER_DIR) && cargo test --locked -- --test-threads=1

test: test-swift test-rust check-uninstall-selftest

# The canonical local gate. The bundle build runs last so cheap checks report first.
ci:
	@echo "======================================"
	@echo "Running CI Pipeline"
	@echo "======================================"
	@$(MAKE) lint
	@echo ""
	@$(MAKE) format-check
	@echo ""
	@$(MAKE) security
	@echo ""
	@$(MAKE) test
	@echo ""
	@$(MAKE) app-ci
	@echo ""
	@echo "======================================"
	@echo "CI Pipeline Completed Successfully"
	@echo "======================================"

deps-update:
	@echo "======================================"
	@echo "Updating Dependencies to Latest Stable"
	@echo "======================================"
	@echo ""
	@echo "=== Swift Dependencies ==="
	@swift package update
	@echo ""
	@echo "=== Rust Dependencies ==="
	@if ! command -v cargo-upgrade >/dev/null 2>&1; then \
		echo "Installing cargo-edit (provides cargo upgrade)..."; \
		cargo install cargo-edit; \
	fi
	@cd $(RUST_RESOLVER_DIR) && cargo upgrade --incompatible
	@cd $(RUST_RESOLVER_DIR) && cargo update
	@$(MAKE) third-party-licenses
	@echo ""
	@echo "======================================"
	@echo "Dependencies Updated"
	@echo "======================================"
	@echo ""
	@echo "Review changes with: git diff Package.resolved $(RUST_RESOLVER_DIR)/Cargo.toml $(RUST_RESOLVER_DIR)/Cargo.lock THIRD_PARTY_LICENSES.txt"

deps-check:
	@echo "======================================"
	@echo "Checking for Outdated Dependencies"
	@echo "======================================"
	@echo ""
	@echo "=== Swift Dependencies ==="
	@swift package show-dependencies
	@echo ""
	@echo "=== Rust Dependencies ==="
	@if ! command -v cargo-outdated >/dev/null 2>&1; then \
		echo "Installing cargo-outdated..."; \
		cargo install cargo-outdated; \
	fi
	@cd $(RUST_RESOLVER_DIR) && cargo outdated

# notarytool credentials, an App Store Connect API key:
# NOTARY_AUTH="--key <p8> --key-id <id> --issuer <uuid>". `make release` builds
# it from the NOTARY_* variables.
NOTARY_AUTH ?=
DMG_FILE = $(BUILD_DIR)/MacDNS.dmg

# Where the appcast says the DMG of this version is downloaded from.
RELEASE_DOWNLOAD_URL_PREFIX = https://github.com/MacDNS-app/macdns/releases/download/v$(VERSION)/

# Sparkle EdDSA private key. Empty uses the login Keychain. CI passes
# SPARKLE_KEY_ARGS="--ed-key-file <file>".
SPARKLE_KEY_ARGS ?=

# Sparkle tools (after swift package resolve)
SPARKLE_BIN = .build/artifacts/sparkle/Sparkle/bin
SPARKLE_SIGN = $(SPARKLE_BIN)/sign_update
SPARKLE_APPCAST = $(SPARKLE_BIN)/generate_appcast
SPARKLE_GENKEYS = $(SPARKLE_BIN)/generate_keys

notarize: check-notary-auth
	@if [ ! -f "$(DMG_FILE)" ]; then \
		echo "Error: $(DMG_FILE) not found. Run 'make dmg' first."; \
		exit 1; \
	fi
	@echo "=== Submitting for notarization ==="
	@echo "This may take several minutes..."
	@xcrun notarytool submit $(DMG_FILE) $(NOTARY_AUTH) --wait
	@echo "=== Notarization complete ==="

check-notary-auth:
	@if [ -z "$(NOTARY_AUTH)" ]; then \
		echo "Error: set NOTARY_AUTH=\"--key <p8> --key-id <id> --issuer <uuid>\". make release sets it from .env."; \
		exit 1; \
	fi

# Check notarization status (for async submissions)
notarize-check: check-notary-auth
	@echo "=== Checking notarization history ==="
	@xcrun notarytool history $(NOTARY_AUTH)

staple:
	@if [ ! -f "$(DMG_FILE)" ]; then \
		echo "Error: $(DMG_FILE) not found."; \
		exit 1; \
	fi
	@echo "=== Stapling notarization ticket ==="
	xcrun stapler staple $(DMG_FILE)
	@echo "=== Stapling complete ==="
	@echo ""
	@echo "Ready for distribution: $(DMG_FILE)"

sparkle-sign:
	@if [ ! -f "$(DMG_FILE)" ]; then \
		echo "Error: $(DMG_FILE) not found. Run 'make dmg' first."; \
		exit 1; \
	fi
	@if [ ! -f "$(SPARKLE_SIGN)" ]; then \
		echo "Sparkle tools not found. Running swift package resolve..."; \
		swift package resolve; \
	fi
	@echo "=== Signing DMG with Sparkle EdDSA ==="
	@$(SPARKLE_SIGN) $(SPARKLE_KEY_ARGS) $(DMG_FILE)
	@echo ""
	@echo "=== Generating appcast.xml ==="
	@$(SPARKLE_APPCAST) $(SPARKLE_KEY_ARGS) $(BUILD_DIR)/ \
		--download-url-prefix "$(RELEASE_DOWNLOAD_URL_PREFIX)" \
		-o $(BUILD_DIR)/appcast.xml
	@echo ""
	@echo "Appcast generated: $(BUILD_DIR)/appcast.xml"

sparkle-keys:
	@if [ ! -f "$(SPARKLE_GENKEYS)" ]; then \
		echo "Sparkle tools not found. Running swift package resolve..."; \
		swift package resolve; \
	fi
	@echo "=== Generating Sparkle EdDSA Keys ==="
	@echo "The private key will be stored in your macOS Keychain."
	@echo "Copy the public key to helper.mk (SPARKLE_PUBLIC_KEY)"
	@echo ""
	@$(SPARKLE_GENKEYS)

print-build-number:
	@echo "$(BUILD_NUMBER)"

# A published CFBundleVersion must never repeat or regress: extension-staleness
# detection compares the bundled build against the running one. The sequence
# comes from UTC time unless release automation injects one, so this guard only
# has to reject an injection that would produce an unusable build number.
check-release-build-sequence:
	@case "$(strip $(RELEASE_BUILD_SEQUENCE))" in \
		''|0*|*[!0-9]*) echo "Error: RELEASE_BUILD_SEQUENCE must be a positive integer without leading zeros (got '$(RELEASE_BUILD_SEQUENCE)')"; exit 1 ;; \
	esac
	@echo "Release build number: $(BUILD_NUMBER)"

check-release-build-sequence-selftest:
	@echo "=== Self-check: release build sequence guard ==="
	@if $(MAKE) --no-print-directory check-release-build-sequence RELEASE_BUILD_SEQUENCE= >/dev/null 2>&1; then \
		echo "FAIL: an explicitly empty RELEASE_BUILD_SEQUENCE was accepted"; \
		exit 1; \
	fi
	@if $(MAKE) --no-print-directory check-release-build-sequence RELEASE_BUILD_SEQUENCE=not-a-number >/dev/null 2>&1; then \
		echo "FAIL: release mode accepted a non-numeric RELEASE_BUILD_SEQUENCE"; \
		exit 1; \
	fi
	@for invalid in 0 00 007; do \
		if $(MAKE) --no-print-directory check-release-build-sequence RELEASE_BUILD_SEQUENCE=$$invalid >/dev/null 2>&1; then \
			echo "FAIL: release mode accepted zero or a leading zero ($$invalid)"; \
			exit 1; \
		fi; \
	done
	@if ! $(MAKE) --no-print-directory check-release-build-sequence RELEASE_BUILD_SEQUENCE=1 >/dev/null 2>&1; then \
		echo "FAIL: release mode rejected the smallest valid RELEASE_BUILD_SEQUENCE"; \
		exit 1; \
	fi
	@if ! $(MAKE) --no-print-directory check-release-build-sequence RELEASE_BUILD_SEQUENCE=12345 >/dev/null 2>&1; then \
		echo "FAIL: release mode rejected a valid RELEASE_BUILD_SEQUENCE"; \
		exit 1; \
	fi
	@actual=$$($(MAKE) --no-print-directory print-build-number RELEASE_BUILD_SEQUENCE=12345); \
	if [ "$$actual" != "$(VERSION).12345" ]; then \
		echo "FAIL: injected RELEASE_BUILD_SEQUENCE not used in BUILD_NUMBER (got '$$actual', expected '$(VERSION).12345')"; \
		exit 1; \
	fi
	@derived=$$($(MAKE) --no-print-directory print-build-number); \
	case "$${derived#$(VERSION).}" in \
		''|*[!0-9]*) echo "FAIL: an uninjected build number is not numeric (got '$$derived')"; exit 1 ;; \
	esac
	@[ -n "$$RELEASE_BUILD_SEQUENCE" ] || { \
		echo "FAIL: the build sequence is not exported, so sub-makes derive a second one"; \
		exit 1; \
	}
	@echo "OK: the build sequence is derived, numeric, and shared with every sub-make"

check-build-order-selftest:
	@sh Scripts/build-order-selftest.sh

check-uninstall-selftest:
	@sh Scripts/uninstall-selftest.sh

# The same command locally and in CI. Scripts/release.sh loads .env when it
# exists, sets up signing from those variables and runs release-build.
release:
	+@Scripts/release.sh

release-build: check-release-build-sequence
	+@$(MAKE) dmg
	+@$(MAKE) notarize
	+@$(MAKE) staple
	+@$(MAKE) sparkle-sign
	@echo ""
	@echo "======================================"
	@echo "Release build complete!"
	@echo "DMG: $(DMG_FILE)"
	@echo "Appcast: $(BUILD_DIR)/appcast.xml"
	@echo "======================================"

