# J14 — Darwin notifications are unauthenticated wake-up hints only.

VIEWMODEL=Sources/MacDNS/ViewModels/AppViewModel.swift
PROVIDER=Sources/DNSProxyExtension/DNSProxyProvider.swift

begin "J14 fails when the invariant leaves AGENTS.md"
drop AGENTS.md 'Darwin notifications are unauthenticated wake-up hints only'
expect J14 fail "no longer in AGENTS.md"

begin "J14 catches a hint assigning interception state"
swap "$VIEWMODEL" 'model.enqueueHealthEvaluation()' '                model.providerState = .intercepting'
expect J14 fail "forbidden in a callback body"

begin "J14 catches a hint driving bypass directly"
swap "$PROVIDER" 'provider.signalHealthEvaluation()' '                provider.bypassDisable()'
expect J14 fail "forbidden in a callback body"

begin "J14 catches a hint doing work instead of handing it off"
swap "$VIEWMODEL" 'model.enqueueHealthEvaluation()' '                model.refreshRuntimeState()'
expect J14 fail "callback body never hands work off"

begin "J14 catches an observer in a file the rule does not lint"
put Sources/MacDNSAgent/Services/HintObserver.swift \
    'CFNotificationCenterAddObserver(center, ptr, callback, name, nil, .deliverImmediately)'
expect J14 fail "registered in a file this rule does not lint"

begin "J14 fails when its anchor no longer matches a linted file"
drop "$PROVIDER" 'CFNotificationCenterAddObserver('
expect J14 fail "no callback body found"
