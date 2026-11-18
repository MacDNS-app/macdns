BASE_APP_NAME = MacDNS
BASE_PKG_ID = app.macdns
REPO_ROOT := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))

# Semantic version (MAJOR.MINOR.PATCH)
VERSION = 2.7.1

# Build number: VERSION + build sequence (e.g. 2.0.1.20260725213412).
# Used as CFBundleVersion in extensions so macOS detects updates even when
# VERSION stays the same, and by extension-staleness detection when comparing
# the bundled build against the running one. It must never repeat or regress
# between builds.
#
# Apple documents CFBundleVersion as up to three integers. Four components are
# deliberate: sysextd replaces an extension when the version differs, and
# Sparkle compares any number of components. Changing the scheme needs a
# migration so the first build under the new one still compares as newer.
#
# UTC wall-clock time has one-second resolution and needs no repository history.
# Builds in the same second can repeat it, and clock adjustments can regress it.
# Release automation may inject a unique, increasing RELEASE_BUILD_SEQUENCE.
# Either way the value is exported, so every sub-make of the same build stamps
# the identical number instead of deriving a second one.
RELEASE_BUILD_SEQUENCE ?= $(shell date -u +%Y%m%d%H%M%S)
export RELEASE_BUILD_SEQUENCE
ifeq ($(strip $(RELEASE_BUILD_SEQUENCE)),)
$(error RELEASE_BUILD_SEQUENCE is set to an empty value; leave it unset to derive the sequence from UTC time)
endif
BUILD_SEQUENCE := $(strip $(RELEASE_BUILD_SEQUENCE))
BUILD_NUMBER := $(VERSION).$(BUILD_SEQUENCE)

# Rust resolver version (sourced from Cargo.toml for plist stamping)
DNS_PROXY_VERSION := $(shell awk -F'"' '/^version/ {print $$2; exit}' $(REPO_ROOT)/rust-resolver/crates/macdns-resolver/Cargo.toml)

# Sparkle configuration
SPARKLE_FEED_URL = https://raw.githubusercontent.com/MacDNS-app/macdns/main/appcast.xml
SPARKLE_PUBLIC_KEY = uDNilFeKCKXvBgVTpU5uQ2kfFmWThiBEqn+czU8lito=

# Keygen token that creates trial licenses. It comes from the environment
# (Scripts/release.sh, .env locally) and never from the repository. Release
# builds require it.
KEYGEN_TRIAL_TOKEN ?=

# Build directories
BUILD_DIR = build
DIST_DIR = $(BUILD_DIR)/dist

# App bundle paths
APP_BUNDLE = $(DIST_DIR)/$(BASE_APP_NAME).app
CONTENTS_DIR = $(APP_BUNDLE)/Contents
MACOS_DIR = $(CONTENTS_DIR)/MacOS
RESOURCES_DIR = $(CONTENTS_DIR)/Resources
PLUGINS_DIR = $(CONTENTS_DIR)/PlugIns
LAUNCH_AGENTS_DIR = $(CONTENTS_DIR)/Library/LaunchAgents
SYSTEM_EXTENSIONS_DIR = $(CONTENTS_DIR)/Library/SystemExtensions

# System Extension bundles
EXTENSION_BUNDLE = $(SYSTEM_EXTENSIONS_DIR)/app.macdns.dnsproxy.systemextension
CONTENT_FILTER_BUNDLE = $(SYSTEM_EXTENSIONS_DIR)/app.macdns.contentfilter.systemextension

# Code signing identities
TEAM_ID ?= MY427949GW

ifeq ($(strip $(DEV_ID_APPLICATION)),)
DEV_ID_APPLICATION := $(shell security find-identity -v -p codesigning 2>/dev/null | awk -F'"' -v team="$(TEAM_ID)" '/Developer ID Application/ { if (team == "" || $$2 ~ "\\(" team "\\)$$") { print $$2; exit } }')
endif

# Provisioning profiles
PROFILE_DIR ?= $(HOME)/Downloads
APP_PROFILE ?= $(PROFILE_DIR)/MacDNS_Developer_ID.provisionprofile
EXTENSION_PROFILE ?= $(PROFILE_DIR)/MacDNS_Extension_Developer_ID.provisionprofile
CONTENT_FILTER_PROFILE ?= $(PROFILE_DIR)/MacDNS_Content_Filter_Developer_ID.provisionprofile

# Release optimization for the direct `swiftc` extension builds. Nothing from
# `swift build -c release` reaches those invocations and swiftc defaults to
# -Onone, so the shipped DNS Proxy and Content Filter would run unoptimized on
# the query hot path unless the level is stated here.
EXTENSION_SWIFTC_RELEASE_FLAGS = -O -wmo

# Swift compiler warnings fail the build. Set SWIFT_WARNINGS_AS_ERRORS=0 only to
# unblock an emergency build. CI always runs with the default.
SWIFT_WARNINGS_AS_ERRORS ?= 1
ifeq ($(strip $(SWIFT_WARNINGS_AS_ERRORS)),1)
SWIFTC_WARNING_FLAGS = -warnings-as-errors
SWIFTPM_WARNING_FLAGS = -Xswiftc -warnings-as-errors
else
SWIFTC_WARNING_FLAGS =
SWIFTPM_WARNING_FLAGS =
endif

# rust-resolver workspace (DNS resolver dylib)
RUST_RESOLVER_DIR = rust-resolver
RUST_RESOLVER_DYLIB = libmacdns_resolver.dylib
RUST_RESOLVER_UNIVERSAL_DIR = $(RUST_RESOLVER_DIR)/target/universal/release
