#!/bin/bash

# MacDNS Uninstallation Script
#
# Removes the user-level MacDNS components (agent, configuration, logs, caches,
# preferences) and the application bundle.
#
# It cannot remove the NetworkExtension configuration or deactivate the System
# Extensions: only the signed MacDNS.app can, and macOS asks the user for
# approval and a password. While extensions are installed, this script waits for
# the in-app "Uninstall…" flow (Settings > Advanced > Danger Zone) and stops or
# removes nothing until they are gone. Deleting the app first would leave DNS
# interception and DoH/DoT blocking with no signed app left to remove them.
#
# The gate reads `systemextensionsctl`, which reports System Extension state
# only. NEDNSProxyManager / NEFilterManager preferences live in a store no shell
# tool can read, so a leftover NE configuration with no System Extension behind
# it goes undetected here. The in-app flow clears both.

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

stop_services() {
    log_info "Stopping MacDNS services..."

    launchctl bootout "gui/$(id -u)/app.macdns.agent" 2>/dev/null || true

    killall -9 MacDNS 2>/dev/null || true
    killall -9 MacDNSAgent 2>/dev/null || true

    log_success "MacDNS services stopped"
}

remove_app() {
    log_info "Removing MacDNS application..."

    if [[ -d "/Applications/MacDNS.app" ]]; then
        rm -rf "/Applications/MacDNS.app"
        log_success "MacDNS.app removed from /Applications"
    else
        log_warning "MacDNS.app not found in /Applications"
    fi
}

remove_user_configs() {
    log_info "Removing user configuration files..."

    local config_dir="$HOME/Library/Application Support/MacDNS"
    if [[ -d "$config_dir" ]]; then
        rm -rf "$config_dir"
        log_success "Configuration directory removed: $config_dir"
    else
        log_warning "Configuration directory not found"
    fi
}

remove_user_logs() {
    log_info "Removing log files..."

    local log_dir="$HOME/Library/Logs/MacDNS"
    if [[ -d "$log_dir" ]]; then
        rm -rf "$log_dir"
        log_success "Log directory removed: $log_dir"
    else
        log_warning "Log directory not found"
    fi
}

# macOS keeps caches, URL session storage and preferences under the bundle
# identifiers of the app and the agent.
BUNDLE_ID_PREFIXES=(app.macdns)

# Prints the entries of a directory named after a MacDNS bundle identifier,
# exactly or followed by a dot, so neighbours like app.macdnsx are left alone.
bundle_id_entries() {
    local dir=$1 suffix=$2 prefix path
    for prefix in "${BUNDLE_ID_PREFIXES[@]}"; do
        for path in "$dir/$prefix$suffix" "$dir/$prefix".*"$suffix"; do
            [[ -e "$path" ]] && printf '%s\n' "$path"
        done
    done
    return 0
}

remove_user_caches() {
    log_info "Removing caches and URL session storage..."

    local dirs=("$HOME/Library/Caches" "$HOME/Library/HTTPStorages" "$HOME/Library/WebKit")
    local user_cache_dir
    if user_cache_dir=$(getconf DARWIN_USER_CACHE_DIR 2>/dev/null) && [[ -n "$user_cache_dir" ]]; then
        dirs+=("${user_cache_dir%/}")
    fi

    local dir path
    for dir in "${dirs[@]}"; do
        while IFS= read -r path; do
            rm -rf "$path"
            log_success "Removed $path"
        done < <(bundle_id_entries "$dir" "")
    done
}

remove_preferences() {
    log_info "Removing user preferences..."

    local path domain
    while IFS= read -r path; do
        domain=${path##*/}
        domain=${domain%.plist}
        # Through cfprefsd first, or its cached copy is written back later.
        defaults delete "$domain" 2>/dev/null || true
        rm -f "$path"
        log_success "Removed preferences: $domain"
    done < <(bundle_id_entries "$HOME/Library/Preferences" ".plist")
}

# Prints MacDNS system extensions that are still activated. A deactivated one
# can linger as "terminated waiting to uninstall on reboot", which does not block
# removing the app.
#
# Returns 0 with the matching rows, or 2 when the listing itself failed. A failed
# listing must never read as "nothing found", or a broken check deletes the app
# with live extensions behind it.
active_system_extensions() {
    local listing
    if ! listing=$(systemextensionsctl list 2>/dev/null); then
        return 2
    fi
    printf '%s\n' "$listing" \
        | grep -E 'app\.macdns\.(dnsproxy|contentfilter)' \
        | grep -F 'activated' || true
}

# Only the signed app can remove the DNS Proxy / Content Filter preferences and
# the System Extensions, through a flow that prompts the user. This waits for
# that flow, because macOS does not clean them up on its own.
require_extension_teardown() {
    log_info "Checking MacDNS Network Extensions..."

    # Fail closed: without a way to verify teardown, deleting the app would strand
    # whatever is still installed with no signed binary left to manage it.
    if ! command -v systemextensionsctl &> /dev/null; then
        log_error "systemextensionsctl not available; cannot verify extension state."
        log_error "Remove the extensions from the app first: MacDNS > Settings > Advanced >"
        log_error "Danger Zone > \"Uninstall…\", then re-run this script."
        return 1
    fi

    local remaining
    if ! remaining=$(active_system_extensions); then
        log_error "systemextensionsctl list failed; cannot verify extension state."
        log_error "Remove the extensions from the app first: MacDNS > Settings > Advanced >"
        log_error "Danger Zone > \"Uninstall…\", then re-run this script."
        return 1
    fi
    if [[ -z "$remaining" ]]; then
        log_success "No active MacDNS system extension found"
        return 0
    fi

    echo
    log_warning "MacDNS System Extensions are still installed:"
    printf '%s\n' "$remaining"
    echo
    log_info "Remove them from the app: MacDNS > Settings > Advanced > Danger Zone >"
    log_info "\"Uninstall…\". macOS will ask for approval and your password."
    echo

    if [[ ! -t 0 ]]; then
        log_error "Non-interactive run: cannot wait for the in-app removal."
        return 1
    fi

    if [[ -d "/Applications/MacDNS.app" ]]; then
        local answer
        read -r -p "Open MacDNS now? [Y/n] " answer
        case "$answer" in
            [nN]*) ;;
            *) open -a "/Applications/MacDNS.app" 2>/dev/null || log_warning "Could not open MacDNS.app" ;;
        esac
    fi

    read -r -p "Press Enter once the in-app \"Uninstall…\" has finished... " _

    # `errexit` does not apply inside a function invoked as an `if !` condition,
    # so an unchecked failure here would read as an empty listing and clear the
    # gate.
    if ! remaining=$(active_system_extensions); then
        log_error "systemextensionsctl list failed; cannot confirm the extensions are gone."
        log_error "Re-run this script once the in-app removal has completed."
        return 1
    fi
    if [[ -n "$remaining" ]]; then
        log_error "MacDNS System Extensions are still active:"
        printf '%s\n' "$remaining"
        return 1
    fi

    log_success "MacDNS system extensions removed"
    return 0
}

flush_dns_cache() {
    log_info "Flushing DNS cache..."

    dscacheutil -flushcache 2>/dev/null || true
    sudo killall -HUP mDNSResponder 2>/dev/null || true

    log_success "DNS cache flushed"
}

main() {
    echo "========================================"
    echo "MacDNS Uninstallation"
    echo "========================================"
    echo

    # Network Extensions first: this needs the app alive and the user present.
    if ! require_extension_teardown; then
        log_error "Uninstall aborted. Nothing was stopped or removed."
        return 1
    fi

    stop_services

    remove_user_configs
    remove_user_logs
    remove_user_caches
    remove_preferences

    if [[ -d "/Applications/MacDNS.app" ]]; then
        if [[ -w "/Applications/MacDNS.app" ]]; then
            remove_app
        else
            log_info "Need sudo to remove /Applications/MacDNS.app"
            sudo rm -rf "/Applications/MacDNS.app"
            log_success "MacDNS.app removed from /Applications"
        fi
    fi

    flush_dns_cache

    echo
    log_success "MacDNS has been uninstalled!"
    echo
    log_info "Note: verify in System Settings > General > Login Items that"
    log_info "      MacDNS is no longer listed."
    echo
}

usage() {
    echo "Usage: $0 [--help]"
    echo
    echo "This script removes MacDNS from your system."
    echo "It will:"
    echo "  - Wait for the in-app removal of the Network Extensions (see below)"
    echo "  - Stop the MacDNS app and agent"
    echo "  - Remove the MacDNS application from /Applications"
    echo "  - Remove all configuration files from ~/Library/Application Support/MacDNS"
    echo "  - Remove all log files from ~/Library/Logs/MacDNS"
    echo "  - Remove caches, URL session storage and preferences kept under the"
    echo "    app.macdns bundle identifiers"
    echo "  - Flush DNS cache"
    echo
    echo "Network Extensions: the DNS Proxy and Content Filter configuration and"
    echo "      System Extensions can only be removed by the signed MacDNS.app,"
    echo "      through MacDNS > Settings > Advanced > Danger Zone > \"Uninstall…\"."
    echo "      macOS prompts for approval and your password there, so this script"
    echo "      is interactive whenever they are still installed, and it stops or"
    echo "      removes nothing until they are gone."
    echo
    echo "Note: This script does NOT require sudo for most operations,"
    echo "      but may request it for removing /Applications/MacDNS.app."
    echo
    echo "WARNING: This action cannot be undone!"
    echo
}

case "${1:-}" in
    -h|--help)
        usage
        exit 0
        ;;
    "")
        main
        ;;
    *)
        log_error "Unknown option: $1"
        usage
        exit 1
        ;;
esac
