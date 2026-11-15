# J15 — protection status is derived from the agent's reported interception
# state, never guessed from NEDNSProxyManager.isEnabled.

VIEW=Sources/MacDNS/Views/GeneralTabView.swift
VIEWMODEL=Sources/MacDNS/ViewModels/AppViewModel.swift
POLICY=Sources/Shared/ProtectionStatusPolicy.swift

begin "J15 fails when the invariant leaves AGENTS.md"
drop AGENTS.md 'never guess'
expect J15 fail "no longer in AGENTS.md"

begin "J15 catches protection wording outside the policy"
add "$VIEW" 'Text("Protection Active")'
expect J15 fail "protection status wording outside ProtectionStatusPolicy"

# The allowlist is per line and keyed on the flag being rendered, so the
# system-extension activation label stays legal while a hardcoded protection
# label does not.
begin "J15 does not flag the system-extension activation label"
add "$VIEW" 'Text(extensionActive ? "Active" : "Off")'
expect J15 ok

begin "J15 catches interception decided in a second place"
add "$VIEWMODEL" 'providerState = .intercepting'
expect J15 fail "interception decided outside RuntimeStatePresentationPolicy"

begin "J15 catches interception derived from an isEnabled flag"
add "$VIEWMODEL" 'let intercepting = manager.isEnabled'
expect J15 fail "interception derived from an isEnabled flag"

begin "J15 catches the App composing its own status message"
swap "$VIEWMODEL" 'statusMessage = protectionDisplayState.statusPolicy.statusMessage' \
    '        statusMessage = "Protection Off"'
expect J15 fail "no longer takes its status message from the policy"

begin "J15 catches the active state no longer coming from the intercepting branch"
swap "$POLICY" 'return .active' '            return .degraded'
expect J15 fail "no longer derives .active from the .intercepting branch"

begin "J15 fails when the presentation policy stops reading the reported state"
drop Sources/MacDNS/ViewModels/RuntimeStatePresentationPolicy.swift 'proxyInterceptionState'
expect J15 fail "no longer reads the agent's reported interception state"
