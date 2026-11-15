include ../../helper.mk

SED_REPLACE = sed -e 's/@@VERSION@@/$(VERSION)/g' \
              -e 's/@@BUILD_NUMBER@@/$(BUILD_NUMBER)/g' \
              -e 's/@@DNS_PROXY_VERSION@@/$(DNS_PROXY_VERSION)/g' \
              -e 's|@@SPARKLE_FEED_URL@@|$(SPARKLE_FEED_URL)|g' \
              -e 's/@@SPARKLE_PUBLIC_KEY@@/$(SPARKLE_PUBLIC_KEY)/g' \
              -e 's/@@KEYGEN_TRIAL_TOKEN@@/$(KEYGEN_TRIAL_TOKEN)/g'

.PHONY: all app-bundle assemble-app-bundle release_signing_preflight clean build_resolver verify_build build_swift build_extension build_content_filter verify_swift_build FORCE prepare sign sign-release check_source_signing_inputs check_release_signing_assets verify_signing dmg

all: app-bundle

SIGNING_MODE ?= release

build_resolver:
	@echo "=== Building rust-resolver (universal dylib) ==="
	@cd ../../$(RUST_RESOLVER_DIR) && \
		cargo build --locked --release --target x86_64-apple-darwin && \
		cargo build --locked --release --target aarch64-apple-darwin
	@mkdir -p ../../$(RUST_RESOLVER_UNIVERSAL_DIR)
	@lipo -create \
		../../$(RUST_RESOLVER_DIR)/target/x86_64-apple-darwin/release/$(RUST_RESOLVER_DYLIB) \
		../../$(RUST_RESOLVER_DIR)/target/aarch64-apple-darwin/release/$(RUST_RESOLVER_DYLIB) \
		-output ../../$(RUST_RESOLVER_UNIVERSAL_DIR)/$(RUST_RESOLVER_DYLIB)
	@# Combine per-arch dSYM bundles into a universal dSYM alongside the dylib.
	@# cargo emits a .dSYM per target (split-debuginfo=packed). lipo merges the
	@# inner DWARF Mach-Os so `atos` can symbolicate either arch from a single
	@# bundle shipped next to the dylib.
	@rm -rf ../../$(RUST_RESOLVER_UNIVERSAL_DIR)/$(RUST_RESOLVER_DYLIB).dSYM
	@mkdir -p ../../$(RUST_RESOLVER_UNIVERSAL_DIR)/$(RUST_RESOLVER_DYLIB).dSYM/Contents/Resources/DWARF
	@cp ../../$(RUST_RESOLVER_DIR)/target/aarch64-apple-darwin/release/$(RUST_RESOLVER_DYLIB).dSYM/Contents/Info.plist \
		../../$(RUST_RESOLVER_UNIVERSAL_DIR)/$(RUST_RESOLVER_DYLIB).dSYM/Contents/Info.plist
	@lipo -create \
		../../$(RUST_RESOLVER_DIR)/target/x86_64-apple-darwin/release/$(RUST_RESOLVER_DYLIB).dSYM/Contents/Resources/DWARF/$(RUST_RESOLVER_DYLIB) \
		../../$(RUST_RESOLVER_DIR)/target/aarch64-apple-darwin/release/$(RUST_RESOLVER_DYLIB).dSYM/Contents/Resources/DWARF/$(RUST_RESOLVER_DYLIB) \
		-output ../../$(RUST_RESOLVER_UNIVERSAL_DIR)/$(RUST_RESOLVER_DYLIB).dSYM/Contents/Resources/DWARF/$(RUST_RESOLVER_DYLIB)

# Dylib sanity check: catches the "rebuild produced stale / half-universal
# artifact" class of bugs where `make clean` was the workaround. Fails fast
# if the universal slice is missing an arch or if the dylib mtime predates
# any Rust source file in the crate tree. Also asserts the resolver-options
# ABI the agent hard-requires: a dylib without it lets the app install and
# then rejects every config transaction, leaving DNS down with no crash.
verify_build:
	@echo "=== Verifying rust-resolver dylib ==="
	@DYLIB=../../$(RUST_RESOLVER_UNIVERSAL_DIR)/$(RUST_RESOLVER_DYLIB); \
	ARCHES=$$(lipo -info $$DYLIB 2>/dev/null || echo ""); \
	echo "$$ARCHES" | grep -q "arm64" || { echo "FAIL: dylib missing arm64 slice ($$ARCHES)"; exit 1; }; \
	echo "$$ARCHES" | grep -q "x86_64" || { echo "FAIL: dylib missing x86_64 slice ($$ARCHES)"; exit 1; }; \
	nm -gU $$DYLIB 2>/dev/null | grep -q ' T _dns_set_resolver_options$$' || { \
		echo "FAIL: dylib missing dns_set_resolver_options"; \
		echo "      The agent requires the resolver-options ABI (ResolverModule.applyResolverOptions)."; \
		echo "      Without it the resolver never starts and every config save is rejected."; \
		exit 1; \
	}; \
	NEWEST_SRC=$$(find ../../$(RUST_RESOLVER_DIR)/crates -name '*.rs' -type f -print0 \
	              | xargs -0 stat -f '%m %N' \
	              | sort -n | tail -1 | awk '{print $$2}'); \
	if [ -n "$$NEWEST_SRC" ] && [ "$$NEWEST_SRC" -nt "$$DYLIB" ]; then \
		echo "FAIL: dylib older than $$NEWEST_SRC — cargo thinks it is up-to-date but it is not"; \
		echo "      Run: (cd $(RUST_RESOLVER_DIR) && cargo clean -p macdns-resolver) && make app"; \
		exit 1; \
	fi; \
	echo "Dylib verified: $$ARCHES, newer than all .rs sources"

SPARKLE_FRAMEWORK = ../../.build/artifacts/sparkle/Sparkle/Sparkle.xcframework/macos-arm64_x86_64/Sparkle.framework
FRAMEWORKS_DIR = $(CONTENTS_DIR)/Frameworks

prepare:
	@echo "=== Preparing app bundle structure ==="
	@rm -rf ../../$(BUILD_DIR)
	@mkdir -p ../../$(MACOS_DIR)
	@mkdir -p ../../$(RESOURCES_DIR)
	@mkdir -p ../../$(SYSTEM_EXTENSIONS_DIR)
	@mkdir -p ../../$(LAUNCH_AGENTS_DIR)
	@mkdir -p ../../$(FRAMEWORKS_DIR)

build_swift:
	@echo "=== Building Swift components (universal) ==="
	@mkdir -p ../../$(BUILD_DIR)
	@mkdir -p ../../$(MACOS_DIR)
	$(call build_swift_universal,MacDNS)
	@$(SED_REPLACE) ../../Configuration/MacDNSAgent.Info.plist > ../../$(BUILD_DIR)/MacDNSAgent.Info.plist
	$(call build_swift_universal_with_info,MacDNSAgent,$(BUILD_DIR)/MacDNSAgent.Info.plist)

# System extensions compile with swiftc directly, so make tracks their inputs:
# an architecture recompiles only when its sources, their directories (a file
# added, removed or renamed), this Makefile, helper.mk or the toolchain stamp
# (compiler, SDK and flags) are newer than its binary.
EXTENSION_TOOLCHAIN_STAMP = ../../.build/extension-toolchain.stamp
DNS_PROXY_SOURCES = ../../Sources/DNSProxyExtension ../../Sources/SharedExtensionKit \
	$(wildcard ../../Sources/DNSProxyExtension/*.swift ../../Sources/SharedExtensionKit/*.swift)
CONTENT_FILTER_SOURCES = ../../Sources/ContentFilterExtension ../../Sources/SharedExtensionKit \
	$(wildcard ../../Sources/ContentFilterExtension/*.swift ../../Sources/SharedExtensionKit/*.swift)
EXTENSION_BUILD_INPUTS = Makefile ../../helper.mk $(EXTENSION_TOOLCHAIN_STAMP)

# Rewritten only when its content changes, so its mtime moves exactly when the
# compiler, the SDK or the extension flags do.
$(EXTENSION_TOOLCHAIN_STAMP): FORCE
	@mkdir -p $(@D)
	@current="$$(xcrun swiftc --version 2>&1; xcrun --show-sdk-path; echo "$(EXTENSION_SWIFTC_RELEASE_FLAGS) $(SWIFTC_WARNING_FLAGS)")"; \
	if [ ! -f $@ ] || [ "$$(cat $@)" != "$$current" ]; then printf '%s\n' "$$current" > $@; fi

FORCE:

../../.build/DNSProxyExtension_%: $(DNS_PROXY_SOURCES) $(EXTENSION_BUILD_INPUTS)
	@echo "Compiling DNS Proxy extension for $*..."
	cd ../.. && swiftc \
		$(EXTENSION_SWIFTC_RELEASE_FLAGS) $(SWIFTC_WARNING_FLAGS) \
		-module-name DNSProxyExtension \
		-target $*-apple-macosx14.0 \
		-sdk $(shell xcrun --show-sdk-path) \
		-framework NetworkExtension \
		-framework Network \
		-framework Foundation \
		-framework Security \
		-framework SystemConfiguration \
		-o .build/DNSProxyExtension_$* \
		Sources/DNSProxyExtension/*.swift Sources/SharedExtensionKit/*.swift

../../.build/ContentFilterExtension_%: $(CONTENT_FILTER_SOURCES) $(EXTENSION_BUILD_INPUTS)
	@echo "Compiling Content Filter extension for $*..."
	cd ../.. && swiftc \
		$(EXTENSION_SWIFTC_RELEASE_FLAGS) $(SWIFTC_WARNING_FLAGS) \
		-module-name ContentFilterExtension \
		-target $*-apple-macosx14.0 \
		-sdk $(shell xcrun --show-sdk-path) \
		-framework NetworkExtension \
		-framework Network \
		-framework Foundation \
		-framework Security \
		-o .build/ContentFilterExtension_$* \
		Sources/ContentFilterExtension/*.swift Sources/SharedExtensionKit/*.swift

build_extension: ../../.build/DNSProxyExtension_x86_64 ../../.build/DNSProxyExtension_arm64
	@echo "=== Building System Extension (DNS Proxy) ==="
	@mkdir -p ../../$(EXTENSION_BUNDLE)/Contents/MacOS
	cd ../.. && lipo -create -output $(EXTENSION_BUNDLE)/Contents/MacOS/app.macdns.dnsproxy \
		.build/DNSProxyExtension_x86_64 \
		.build/DNSProxyExtension_arm64
	@$(SED_REPLACE) ../../Sources/DNSProxyExtension/Info.plist > ../../$(EXTENSION_BUNDLE)/Contents/Info.plist

build_content_filter: ../../.build/ContentFilterExtension_x86_64 ../../.build/ContentFilterExtension_arm64
	@echo "=== Building Content Filter Extension ==="
	@mkdir -p ../../$(CONTENT_FILTER_BUNDLE)/Contents/MacOS
	cd ../.. && lipo -create -output $(CONTENT_FILTER_BUNDLE)/Contents/MacOS/app.macdns.contentfilter \
		.build/ContentFilterExtension_x86_64 \
		.build/ContentFilterExtension_arm64
	@$(SED_REPLACE) ../../Sources/ContentFilterExtension/Info.plist > ../../$(CONTENT_FILTER_BUNDLE)/Contents/Info.plist

# Validate signing inputs before any expensive build work. The source checks
# need no signing assets, so they run for every SIGNING_MODE including ci.
release_signing_preflight:
	@if [ "$(SIGNING_MODE)" != "release" ] && [ "$(SIGNING_MODE)" != "ci" ]; then \
		echo "Error: unsupported SIGNING_MODE '$(SIGNING_MODE)'"; \
		exit 1; \
	fi
	@$(MAKE) check_source_signing_inputs
	@if [ "$(SIGNING_MODE)" = "release" ]; then \
		$(MAKE) check_release_signing_assets; \
	fi

app-bundle: release_signing_preflight
	@$(MAKE) assemble-app-bundle SIGNING_MODE="$(SIGNING_MODE)"

# Swift builds are incremental. This check fails the build on the stale shapes
# an incremental build could ship silently: a binary missing an architecture,
# an agent whose embedded Info.plist carries another version, or an extension
# Info.plist without this build's number.
verify_swift_build:
	@echo "=== Verifying Swift binaries ==="
	@cd ../.. && for bin in $(MACOS_DIR)/MacDNS $(MACOS_DIR)/MacDNSAgent \
		$(EXTENSION_BUNDLE)/Contents/MacOS/app.macdns.dnsproxy \
		$(CONTENT_FILTER_BUNDLE)/Contents/MacOS/app.macdns.contentfilter; do \
		arches=$$(lipo -archs "$$bin" 2>/dev/null); \
		case " $$arches " in *" arm64 "*) ;; *) echo "FAIL: $$bin missing arm64 ($$arches)"; exit 1 ;; esac; \
		case " $$arches " in *" x86_64 "*) ;; *) echo "FAIL: $$bin missing x86_64 ($$arches)"; exit 1 ;; esac; \
	done; \
	for arch in x86_64 arm64; do \
		lipo $(MACOS_DIR)/MacDNSAgent -thin $$arch -output .build/MacDNSAgent.verify && \
		launchctl plist __TEXT,__info_plist .build/MacDNSAgent.verify 2>/dev/null \
			| grep -qF '"CFBundleShortVersionString" = "$(VERSION)";' || { \
			rm -f .build/MacDNSAgent.verify; \
			echo "FAIL: MacDNSAgent ($$arch) embedded Info.plist is not version $(VERSION)"; exit 1; }; \
	done; \
	rm -f .build/MacDNSAgent.verify; \
	for plist in $(EXTENSION_BUNDLE)/Contents/Info.plist $(CONTENT_FILTER_BUNDLE)/Contents/Info.plist; do \
		[ "$$(/usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' "$$plist" 2>/dev/null)" = "$(BUILD_NUMBER)" ] || { \
			echo "FAIL: $$plist CFBundleVersion is not $(BUILD_NUMBER)"; exit 1; }; \
	done; \
	echo "Swift binaries verified: universal, agent $(VERSION), extensions $(BUILD_NUMBER)"

assemble-app-bundle: prepare
	+@$(MAKE) build_resolver build_swift build_extension build_content_filter
	+@$(MAKE) verify_build verify_swift_build
	@echo "=== Assembling app bundle ==="
	@cp ../../$(RUST_RESOLVER_UNIVERSAL_DIR)/$(RUST_RESOLVER_DYLIB) ../../$(RESOURCES_DIR)/
	@cp ../../LICENSE ../../$(RESOURCES_DIR)/
	@cp ../../THIRD_PARTY_LICENSES.txt ../../$(RESOURCES_DIR)/
	@cp ../../Configuration/app.macdns.agent.plist ../../$(LAUNCH_AGENTS_DIR)/
	@chmod 644 ../../$(LAUNCH_AGENTS_DIR)/app.macdns.agent.plist
	@$(SED_REPLACE) ../../Configuration/Info.plist > ../../$(CONTENTS_DIR)/Info.plist
	@echo "APPL????" > ../../$(CONTENTS_DIR)/PkgInfo
	# The asset catalog build is always delegated. The icon Makefile stamps the
	# generated catalog against every source PNG, so an edited image regenerates
	# instead of shipping the stale catalog an "only if missing" guard would keep.
	@$(MAKE) -C ../../Icons
	@echo "=== Compiling Asset Catalog for App... ==="
	@xcrun actool --compile ../../$(RESOURCES_DIR) \
		--platform macosx \
		--minimum-deployment-target 14.0 \
		--app-icon AppIcon \
		--output-partial-info-plist ../../$(BUILD_DIR)/AssetCatalog-App.plist \
		../../Icons/Assets.xcassets
	@echo "=== Compiling Asset Catalog for DNS Proxy Extension... ==="
	@mkdir -p ../../$(EXTENSION_BUNDLE)/Contents/Resources
	@xcrun actool --compile ../../$(EXTENSION_BUNDLE)/Contents/Resources \
		--platform macosx \
		--minimum-deployment-target 14.0 \
		--app-icon AppIcon \
		--output-partial-info-plist ../../$(BUILD_DIR)/AssetCatalog-Extension.plist \
		../../Icons/Assets.xcassets
	@echo "=== Compiling Asset Catalog for Content Filter Extension... ==="
	@mkdir -p ../../$(CONTENT_FILTER_BUNDLE)/Contents/Resources
	@xcrun actool --compile ../../$(CONTENT_FILTER_BUNDLE)/Contents/Resources \
		--platform macosx \
		--minimum-deployment-target 14.0 \
		--app-icon AppIcon \
		--output-partial-info-plist ../../$(BUILD_DIR)/AssetCatalog-ContentFilter.plist \
		../../Icons/Assets.xcassets
	@echo "=== Copying Sparkle.framework... ==="
	@cp -R $(SPARKLE_FRAMEWORK) ../../$(FRAMEWORKS_DIR)/
	@echo "=== Adding rpath for Frameworks... ==="
	@install_name_tool -add_rpath @executable_path/../Frameworks ../../$(MACOS_DIR)/MacDNS
	@echo "=== App bundle created at $(APP_BUNDLE) ==="
	@$(MAKE) sign

sign:
	@if [ "$(SIGNING_MODE)" = "release" ]; then \
		$(MAKE) sign-release; \
	elif [ "$(SIGNING_MODE)" = "ci" ]; then \
		echo "=== Skipping distribution signing for CI-only bundle ==="; \
	else \
		echo "Error: unsupported SIGNING_MODE '$(SIGNING_MODE)'"; \
		exit 1; \
	fi

# Source-only proxy-control checks. They read files tracked in the repository
# and need no certificate, keychain or provisioning profile, so they run for
# every SIGNING_MODE. A regression here ships a DNS Proxy whose control-plane
# Mach service can never be reached, leaving the provider in permanent bypass.
check_source_signing_inputs:
	@echo "=== Validating DNS Proxy control-plane source inputs ==="
	@mach_name=$$(/usr/bin/plutil -extract NetworkExtension.NEMachServiceName raw -o - ../../Sources/DNSProxyExtension/Info.plist 2>/dev/null || true); \
	if [ "$$mach_name" != "group.app.macdns.proxy-control" ]; then \
		echo "Error: DNS Proxy Info.plist missing NetworkExtension.NEMachServiceName group.app.macdns.proxy-control (found '$$mach_name'); it must live INSIDE the NetworkExtension dict and be prefixed by the App Group, or sysextd rejects the extension (NE error 6)"; \
		exit 1; \
	fi
	@if ! /usr/libexec/PlistBuddy -c 'Print :com.apple.security.application-groups:0' \
		../../Configuration/DNSProxyExtension.entitlements 2>/dev/null | grep -q '^group.app.macdns$$'; then \
		echo "Error: DNS Proxy entitlements missing App Group group.app.macdns"; \
		exit 1; \
	fi
	@if ! /usr/libexec/PlistBuddy -c 'Print :com.apple.security.application-groups:0' \
		../../Configuration/MacDNSAgent.entitlements 2>/dev/null | grep -q '^group.app.macdns$$'; then \
		echo "Error: MacDNSAgent entitlements missing App Group group.app.macdns (agent cannot reach the proxy-control Mach service)"; \
		exit 1; \
	fi
	@# The proxy-control code-sign requirements hardcode the signing Team OU in
	@# Swift source. Signing with a different TEAM_ID then produces binaries that
	@# reject each other at runtime, and the provider never leaves bypass. The
	@# constants themselves are kept in sync by ProxyControlReportInteropTests.
	@# This check ties them to the identity the build actually signs with.
	@ou_files="../../Sources/Shared/ProxyControlProtocol.swift ../../Sources/DNSProxyExtension/ProxyControlListener.swift"; \
	found=0; \
	for f in $$ou_files; do \
		for ou in $$(sed -n 's/.*subject\.OU\] = \\"\([A-Z0-9]*\)\\".*/\1/p' "$$f"); do \
			found=$$((found + 1)); \
			if [ "$$ou" != "$(TEAM_ID)" ]; then \
				echo "Error: $$f pins code-sign Team OU '$$ou' but the build signs with TEAM_ID '$(TEAM_ID)'; the agent and DNS Proxy would reject each other and the provider would stay in permanent bypass"; \
				exit 1; \
			fi; \
		done; \
	done; \
	if [ "$$found" -lt 3 ]; then \
		echo "Error: expected 3 code-sign Team OU literals across $$ou_files, found $$found; the check can no longer see the requirement strings it is meant to guard"; \
		exit 1; \
	fi
	@echo "DNS Proxy control-plane source inputs verified"

# Signing assets: certificates, keychain identity and provisioning profiles.
# Release-only, because CI has none of them.
check_release_signing_assets:
	@if [ -z "$(TEAM_ID)" ]; then \
		echo "Error: TEAM_ID must be set for release signing."; \
		exit 1; \
	fi
	@case "$(KEYGEN_TRIAL_TOKEN)" in \
		'') echo "Error: KEYGEN_TRIAL_TOKEN must be set for a release build, or the app cannot create trials."; exit 1 ;; \
		*[!A-Za-z0-9-]*) echo "Error: KEYGEN_TRIAL_TOKEN may contain only letters, digits and '-'."; exit 1 ;; \
	esac
	@if [ -z "$(DEV_ID_APPLICATION)" ]; then \
		echo "Error: no Developer ID Application signing identity found for Team ID $(TEAM_ID). Set DEV_ID_APPLICATION explicitly or install the certificate in Keychain."; \
		exit 1; \
	fi
	@for profile in "$(APP_PROFILE)" "$(EXTENSION_PROFILE)" "$(CONTENT_FILTER_PROFILE)"; do \
		if [ ! -f "$$profile" ]; then \
			echo "Error: provisioning profile not found: $$profile"; \
			exit 1; \
		fi; \
	done
	@identity_line=$$(security find-identity -v -p codesigning | grep -F "$(DEV_ID_APPLICATION)" | head -n 1); \
	if [ -z "$$identity_line" ]; then \
		echo "Error: signing identity not found: $(DEV_ID_APPLICATION)"; \
		exit 1; \
	fi; \
	case "$$identity_line" in \
		*"Developer ID Application"*"($(TEAM_ID))"*) ;; \
		*) echo "Error: signing identity Team ID mismatch. Expected $(TEAM_ID), found: $$identity_line"; exit 1 ;; \
	esac
	@validate_profile() { \
		profile="$$1"; \
		expected_bundle_id="$$2"; \
		requires_extension_install="$$3"; \
		shift 3; \
		plist=$$(mktemp); \
		if ! security cms -D -i "$$profile" > "$$plist" 2>/dev/null; then \
			rm -f "$$plist"; \
			echo "Error: failed to decode provisioning profile: $$profile"; \
			exit 1; \
		fi; \
		profile_expiration=$$(/usr/bin/plutil -extract ExpirationDate raw -expect date -o - "$$plist" 2>/dev/null || true); \
		if [ -z "$$profile_expiration" ]; then \
			rm -f "$$plist"; \
			echo "Error: provisioning profile has missing or invalid ExpirationDate: $$profile"; \
			exit 1; \
		fi; \
		profile_expiration_epoch=$$(/bin/date -u -j -f "%Y-%m-%dT%H:%M:%SZ" "$$profile_expiration" "+%s" 2>/dev/null || true); \
		if [ -z "$$profile_expiration_epoch" ]; then \
			rm -f "$$plist"; \
			echo "Error: provisioning profile has invalid ExpirationDate '$$profile_expiration': $$profile"; \
			exit 1; \
		fi; \
		now_epoch=$$(/bin/date -u "+%s"); \
		if [ "$$profile_expiration_epoch" -le "$$now_epoch" ]; then \
			rm -f "$$plist"; \
			echo "Error: provisioning profile expired: $$profile (ExpirationDate: $$profile_expiration)"; \
			exit 1; \
		fi; \
		profile_team=$$(/usr/libexec/PlistBuddy -c "Print :TeamIdentifier:0" "$$plist" 2>/dev/null || true); \
		if [ "$$profile_team" != "$(TEAM_ID)" ]; then \
			rm -f "$$plist"; \
			echo "Error: provisioning profile Team ID mismatch: $$profile has '$$profile_team', expected '$(TEAM_ID)'"; \
			exit 1; \
		fi; \
		profile_app_id=$$(/usr/libexec/PlistBuddy -c "Print :Entitlements:com.apple.application-identifier" "$$plist" 2>/dev/null || /usr/libexec/PlistBuddy -c "Print :Entitlements:application-identifier" "$$plist" 2>/dev/null || true); \
		if [ -z "$$profile_app_id" ]; then \
			rm -f "$$plist"; \
			echo "Error: provisioning profile lacks application-identifier: $$profile"; \
			exit 1; \
		fi; \
		expected_app_id="$(TEAM_ID).$$expected_bundle_id"; \
		case "$$expected_app_id" in \
			$$profile_app_id) ;; \
			*) rm -f "$$plist"; echo "Error: provisioning profile App ID mismatch: $$profile has '$$profile_app_id', expected coverage for '$$expected_app_id'"; exit 1 ;; \
		esac; \
		if [ "$$requires_extension_install" = "true" ]; then \
			can_install=$$(/usr/libexec/PlistBuddy -c "Print :Entitlements:com.apple.developer.system-extension.install" "$$plist" 2>/dev/null || true); \
			if [ "$$can_install" != "true" ]; then \
				rm -f "$$plist"; \
				echo "Error: provisioning profile lacks com.apple.developer.system-extension.install: $$profile"; \
				exit 1; \
			fi; \
		fi; \
		network_extensions=$$(/usr/libexec/PlistBuddy -c "Print :Entitlements:com.apple.developer.networking.networkextension" "$$plist" 2>/dev/null || true); \
		for required_extension in "$$@"; do \
			case "$$network_extensions" in \
				*"$$required_extension"*) ;; \
				*) rm -f "$$plist"; echo "Error: provisioning profile lacks $$required_extension: $$profile"; exit 1 ;; \
			esac; \
		done; \
		rm -f "$$plist"; \
	}; \
	validate_profile "$(APP_PROFILE)" "app.macdns" true "dns-proxy-systemextension" "content-filter-provider-systemextension"; \
	validate_profile "$(EXTENSION_PROFILE)" "app.macdns.dnsproxy" false "dns-proxy-systemextension"; \
	validate_profile "$(CONTENT_FILTER_PROFILE)" "app.macdns.contentfilter" false "content-filter-provider-systemextension"
	@echo "=== Validating DNS Proxy control-plane provisioning ==="
	@ext_profile_plist=$$(mktemp); \
	if ! security cms -D -i "$(EXTENSION_PROFILE)" > "$$ext_profile_plist" 2>/dev/null; then \
		rm -f "$$ext_profile_plist"; \
		echo "Error: failed to decode extension provisioning profile for App Group check"; \
		exit 1; \
	fi; \
	groups=$$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.security.application-groups' "$$ext_profile_plist" 2>/dev/null || true); \
	rm -f "$$ext_profile_plist"; \
	case "$$groups" in \
		*"group.app.macdns"*) ;; \
		*) echo "Error: extension provisioning profile does not authorize App Group group.app.macdns"; exit 1 ;; \
	esac
	@app_profile_plist=$$(mktemp); \
	if ! security cms -D -i "$(APP_PROFILE)" > "$$app_profile_plist" 2>/dev/null; then \
		rm -f "$$app_profile_plist"; \
		echo "Error: failed to decode app provisioning profile for App Group check"; \
		exit 1; \
	fi; \
	groups=$$(/usr/libexec/PlistBuddy -c 'Print :Entitlements:com.apple.security.application-groups' "$$app_profile_plist" 2>/dev/null || true); \
	rm -f "$$app_profile_plist"; \
	case "$$groups" in \
		*"group.app.macdns"*) ;; \
		*) echo "Error: app provisioning profile does not authorize App Group group.app.macdns (nested agent relies on it)"; exit 1 ;; \
	esac

sign-release: check_source_signing_inputs check_release_signing_assets
	@echo "=== Signing app bundle (release) ==="
	# Embed provisioning profiles
	@cp $(APP_PROFILE) ../../$(CONTENTS_DIR)/embedded.provisionprofile
	@cp $(EXTENSION_PROFILE) ../../$(EXTENSION_BUNDLE)/Contents/embedded.provisionprofile
	@cp $(CONTENT_FILTER_PROFILE) ../../$(CONTENT_FILTER_BUNDLE)/Contents/embedded.provisionprofile
	# Sign resources
	@codesign --force --options runtime --timestamp --sign "$(DEV_ID_APPLICATION)" ../../$(RESOURCES_DIR)/$(RUST_RESOLVER_DYLIB)
	# Sign Sparkle.framework components individually (inside-out, per Sparkle docs)
	@codesign --force --options runtime --timestamp \
		--sign "$(DEV_ID_APPLICATION)" \
		../../$(FRAMEWORKS_DIR)/Sparkle.framework/Versions/B/XPCServices/Installer.xpc
	@codesign --force --options runtime --timestamp \
		--sign "$(DEV_ID_APPLICATION)" \
		../../$(FRAMEWORKS_DIR)/Sparkle.framework/Versions/B/XPCServices/Downloader.xpc
	@codesign --force --options runtime --timestamp \
		--sign "$(DEV_ID_APPLICATION)" \
		../../$(FRAMEWORKS_DIR)/Sparkle.framework/Versions/B/Autoupdate
	@codesign --force --options runtime --timestamp \
		--sign "$(DEV_ID_APPLICATION)" \
		../../$(FRAMEWORKS_DIR)/Sparkle.framework/Versions/B/Updater.app
	@codesign --force --options runtime --timestamp \
		--sign "$(DEV_ID_APPLICATION)" ../../$(FRAMEWORKS_DIR)/Sparkle.framework
	# Sign MacDNSAgent (bundle identifier for launchd + App Group for proxy-control XPC)
	@codesign --force --options runtime --timestamp \
		--identifier app.macdns.agent \
		--entitlements ../../Configuration/MacDNSAgent.entitlements \
		--sign "$(DEV_ID_APPLICATION)" ../../$(MACOS_DIR)/MacDNSAgent
	# Sign DNS Proxy extension (with embedded profile)
	@codesign --force --options runtime --timestamp \
		--identifier app.macdns.dnsproxy \
		--entitlements ../../Configuration/DNSProxyExtension.entitlements \
		--sign "$(DEV_ID_APPLICATION)" ../../$(EXTENSION_BUNDLE)
	# Sign Content Filter extension (with embedded profile)
	@codesign --force --options runtime --timestamp \
		--identifier app.macdns.contentfilter \
		--entitlements ../../Configuration/ContentFilterExtension.entitlements \
		--sign "$(DEV_ID_APPLICATION)" ../../$(CONTENT_FILTER_BUNDLE)
	# Sign main app executable
	@codesign --force --options runtime --timestamp \
		--identifier app.macdns \
		--entitlements ../../Configuration/MacDNS.app.entitlements \
		--sign "$(DEV_ID_APPLICATION)" ../../$(MACOS_DIR)/MacDNS
	# Sign entire bundle (with embedded profile)
	@codesign --force --options runtime --timestamp \
		--entitlements ../../Configuration/MacDNS.app.entitlements \
		--sign "$(DEV_ID_APPLICATION)" ../../$(APP_BUNDLE)
	@$(MAKE) verify_signing
	@echo "=== Release signing complete ==="

verify_signing:
	@echo "=== Verifying code signatures ==="
	@codesign --verify --strict ../../$(RESOURCES_DIR)/$(RUST_RESOLVER_DYLIB)
	@codesign --verify --strict ../../$(MACOS_DIR)/MacDNSAgent
	@codesign --verify --strict ../../$(EXTENSION_BUNDLE)
	@codesign --verify --strict ../../$(CONTENT_FILTER_BUNDLE)
	@codesign --verify --deep --strict ../../$(APP_BUNDLE)
	@# The agent dlopens the resolver dylib under the hardened runtime: library
	@# validation rejects it unless both carry the runtime flag and the same
	@# Team ID. `codesign --verify` does not check either, so parse the metadata.
	@echo "=== Verifying hardened runtime and team identity ==="
	@verify_runtime_and_team() { \
		artifact="$$1"; \
		info=$$(codesign -dvvv "$$artifact" 2>&1) || { echo "Error: codesign -dvvv failed for $$artifact" >&2; exit 1; }; \
		flags=$$(printf '%s\n' "$$info" | sed -n 's/^CodeDirectory .*flags=\([^ ]*\).*/\1/p' | head -n 1); \
		case "$$flags" in \
			*runtime*) ;; \
			*) echo "Error: $$artifact is not signed with --options runtime (flags='$$flags'); dlopen fails under hardened runtime" >&2; exit 1 ;; \
		esac; \
		team=$$(printf '%s\n' "$$info" | sed -n 's/^TeamIdentifier=//p' | head -n 1); \
		if [ -z "$$team" ] || [ "$$team" = "not set" ]; then \
			echo "Error: $$artifact has no TeamIdentifier (found '$$team')" >&2; \
			exit 1; \
		fi; \
		printf '%s\n' "$$team"; \
	}; \
	dylib_team=$$(verify_runtime_and_team ../../$(RESOURCES_DIR)/$(RUST_RESOLVER_DYLIB)) || exit 1; \
	agent_team=$$(verify_runtime_and_team ../../$(MACOS_DIR)/MacDNSAgent) || exit 1; \
	if [ "$$dylib_team" != "$$agent_team" ]; then \
		echo "Error: TeamIdentifier mismatch: $(RUST_RESOLVER_DYLIB) is '$$dylib_team', MacDNSAgent is '$$agent_team'"; \
		exit 1; \
	fi; \
	echo "Hardened runtime and TeamIdentifier $$dylib_team verified on $(RUST_RESOLVER_DYLIB) and MacDNSAgent"

# Finder resolves volumes by name, so the layout step needs /Volumes/MacDNS to be
# the image it just attached, not an older MacDNS.dmg still mounted.
DMG_VOLUME = /Volumes/$(BASE_APP_NAME)
DMG_STAGE = ../../$(BUILD_DIR)/dmg_temp
DMG_RW = ../../$(BUILD_DIR)/MacDNS-rw.dmg

dmg: app-bundle
	@echo "=== Creating DMG ==="
	@if [ -e "$(DMG_VOLUME)" ]; then \
		echo "Error: $(DMG_VOLUME) is already mounted. Eject it and run 'make dmg' again."; \
		exit 1; \
	fi
	@rm -rf ../../$(BUILD_DIR)/MacDNS.dmg $(DMG_RW) $(DMG_STAGE)
	@mkdir -p $(DMG_STAGE)/.background
	@cp -R ../../$(APP_BUNDLE) $(DMG_STAGE)/
	@ln -s /Applications $(DMG_STAGE)/Applications
	@tiffutil -cathidpicheck ../../Icons/dmg/background.png ../../Icons/dmg/background@2x.png \
		-out $(DMG_STAGE)/.background/background.tiff
	@diskutil image create from --format RAW --volumeName "$(BASE_APP_NAME)" $(DMG_STAGE) $(DMG_RW)
	@diskutil image attach $(DMG_RW)
	@osascript ../../Scripts/dmg-layout.applescript "$(DMG_VOLUME)" "$(BASE_APP_NAME).app" \
		&& test -s "$(DMG_VOLUME)/.DS_Store" \
		|| { echo "Error: Finder did not save the DMG window layout"; diskutil eject "$(DMG_VOLUME)"; exit 1; }
	@sync
	@diskutil eject "$(DMG_VOLUME)"
	@diskutil image create from --format UDZO $(DMG_RW) ../../$(BUILD_DIR)/MacDNS.dmg
	@rm -rf $(DMG_RW) $(DMG_STAGE)
	@echo "=== DMG created: $(BUILD_DIR)/MacDNS.dmg ==="

clean:
	@echo "=== Cleaning ==="
	@rm -rf ../../$(BUILD_DIR)
	@rm -rf ../../.build
	@$(MAKE) -C ../../Icons clean 2>/dev/null || true

# One build per product for both architectures: swiftbuild keeps a cache per
# architecture and links the universal binary itself, so an unchanged product
# relinks nothing and switching architectures never invalidates the other.
SWIFT_UNIVERSAL_ARCHS = --arch arm64 --arch x86_64

define build_swift_universal
	@echo "Building $1 (universal)..."
	cd ../.. && swift build -c release --product $1 $(SWIFT_UNIVERSAL_ARCHS) $(SWIFTPM_WARNING_FLAGS)
	cd ../.. && cp "$$(swift build -c release --product $1 $(SWIFT_UNIVERSAL_ARCHS) --show-bin-path)/$1" $(MACOS_DIR)/$1
endef

# For standalone executables, which carry their Info.plist in __TEXT,__info_plist.
define build_swift_universal_with_info
	@echo "Building $1 (universal, with Info.plist)..."
	cd ../.. && swift build -c release --product $1 $(SWIFT_UNIVERSAL_ARCHS) $(SWIFTPM_WARNING_FLAGS) \
		-Xlinker -sectcreate -Xlinker __TEXT -Xlinker __info_plist -Xlinker $2
	cd ../.. && cp "$$(swift build -c release --product $1 $(SWIFT_UNIVERSAL_ARCHS) --show-bin-path)/$1" $(MACOS_DIR)/$1
endef
