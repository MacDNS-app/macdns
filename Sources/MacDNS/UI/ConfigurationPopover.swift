// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import Shared
import SwiftUI

struct ConfigurationPopover: View {
    @ObservedObject var viewModel: AppViewModel
    @Binding var isPresented: Bool
    @Environment(\.colorScheme) private var colorScheme

    private var isDisabled: Bool {
        !viewModel.agentInstalled
            || !viewModel.persistedStateAvailability.allowsConfigurationMutation
    }

    private var isFlushDisabled: Bool {
        !viewModel.isEnabled || !viewModel.agentInstalled || !viewModel.servicesRunning
    }

    private var textColor: Color {
        colorScheme == .dark ? .white : .black
    }

    var body: some View {
        VStack(spacing: 0) {
            ConfigToggleRow(
                title: "DNSSEC Validation",
                isOn: Binding(
                    get: { viewModel.dnssecEnabled },
                    set: { viewModel.setDNSSEC(enabled: $0) }
                ),
                textColor: textColor,
                disabled: isDisabled
            )
            ConfigToggleRow(
                title: "Log Lookups",
                isOn: $viewModel.logQueriesEnabled,
                textColor: textColor,
                disabled: isDisabled
            )
            ConfigToggleRow(
                title: "Log Answers",
                isOn: $viewModel.logRepliesEnabled,
                textColor: textColor,
                disabled: isDisabled
            )
            ConfigToggleRow(
                title: "Prefetch",
                isOn: $viewModel.prefetchEnabled,
                textColor: textColor,
                disabled: isDisabled
            )
            ConfigToggleRow(
                title: "Serve Expired",
                isOn: $viewModel.serveExpiredEnabled,
                textColor: textColor,
                disabled: isDisabled
            )
            ConfigProviderMenuRow(viewModel: viewModel, textColor: textColor, disabled: isDisabled)
            ConfigDispatchMenuRow(viewModel: viewModel, textColor: textColor, disabled: isDisabled)
            ConfigToggleRow(
                title: "Answer Refinement",
                isOn: $viewModel.dnsAnswerRefinementEnabled,
                textColor: textColor,
                disabled: isDisabled
            )
            ConfigToggleRow(
                title: "Block Other Encrypted DNS",
                isOn: $viewModel.blockDohDotEnabled,
                textColor: textColor,
                disabled: isDisabled
            )
            .help(
                "Some apps send lookups through their own encrypted DNS and skip your blocklists. This blocks every DNS over TLS (DoT) and DNS over QUIC (DoQ) connection, plus DNS over HTTPS (DoH) to well-known providers. DoH sent to an unknown server is not blocked."
            )

            ConfigActionRow(
                title: "Clear DNS Cache",
                icon: "trash",
                textColor: textColor,
                disabled: isFlushDisabled
            ) {
                viewModel.flushDNSCache { _ in }
                isPresented = false
            }
        }
        .padding(8)
        .frame(width: 280)
        .foregroundColor(textColor)
        .contentShape(Rectangle())
    }
}

// MARK: - DoH Policy Rows
struct ConfigProviderMenuRow: View {
    @ObservedObject var viewModel: AppViewModel
    let textColor: Color
    let disabled: Bool
    @State private var isHovered = false

    var body: some View {
        HStack(spacing: 8) {
            Text("DNS Providers")
                .font(.menu)
                .lineLimit(1)
            Spacer()
            Menu {
                ForEach(DoHProviderID.allCases, id: \.self) { provider in
                    Toggle(
                        provider.displayName,
                        isOn: Binding(
                            get: { viewModel.dohProviders.contains(provider) },
                            set: { _ in viewModel.toggleDoHProvider(provider) }
                        )
                    )
                }
            } label: {
                ConfigMenuValueLabel(
                    text: viewModel.dohProviderSummary,
                    isHighlighted: isHovered && !disabled
                )
            }
            .menuStyle(.button)
            .buttonStyle(.plain)
            .menuIndicator(.hidden)
            .fixedSize()
            .focusable(false)
            .disabled(disabled)
        }
        .frame(height: 24)
        .padding(.horizontal, 8)
        .background(isHovered && !disabled ? Color.accentColor : Color.clear)
        .foregroundColor(isHovered && !disabled ? .white : textColor)
        .cornerRadius(4)
        .opacity(disabled ? 0.4 : 1.0)
        .onHover { isHovered = $0 }
    }
}

struct ConfigDispatchMenuRow: View {
    @ObservedObject var viewModel: AppViewModel
    let textColor: Color
    let disabled: Bool
    @State private var isHovered = false

    var body: some View {
        HStack(spacing: 8) {
            Text("Query Mode")
                .font(.menu)
                .lineLimit(1)
            Spacer()
            Menu {
                Picker("", selection: $viewModel.dohDispatchMode) {
                    ForEach(DoHDispatchMode.allCases, id: \.self) { mode in
                        Text(mode.displayName).tag(mode)
                    }
                }
                .labelsHidden()
                .pickerStyle(.inline)
            } label: {
                ConfigMenuValueLabel(
                    text: viewModel.dohDispatchMode.displayName,
                    isHighlighted: isHovered && !disabled
                )
            }
            .menuStyle(.button)
            .buttonStyle(.plain)
            .menuIndicator(.hidden)
            .fixedSize()
            .focusable(false)
            .disabled(disabled)
        }
        .frame(height: 24)
        .padding(.horizontal, 8)
        .background(isHovered && !disabled ? Color.accentColor : Color.clear)
        .foregroundColor(isHovered && !disabled ? .white : textColor)
        .cornerRadius(4)
        .opacity(disabled ? 0.4 : 1.0)
        .onHover { isHovered = $0 }
    }
}

/// Borderless value label for configuration menu rows in the popover and in
/// Settings. A bezeled control keeps its own tint on the popover's highlighted
/// row and loses contrast against the accent color.
struct ConfigMenuValueLabel: View {
    let text: String
    let isHighlighted: Bool

    var body: some View {
        HStack(spacing: 4) {
            Text(text)
                .font(.menu)
                .lineLimit(1)
            Image(systemName: "chevron.up.chevron.down")
                .font(.system(size: 9, weight: .semibold))
                .foregroundColor(isHighlighted ? .white.opacity(0.7) : .secondary)
        }
        .foregroundColor(isHighlighted ? .white : .secondary)
    }
}

// MARK: - Toggle Row
struct ConfigToggleRow: View {
    let title: String
    @Binding var isOn: Bool
    let textColor: Color
    let disabled: Bool
    @State private var isHovered = false

    var body: some View {
        HStack(spacing: 8) {
            Text(title)
                .font(.menu)
                .lineLimit(1)

            Spacer()

            Toggle("", isOn: $isOn)
                .toggleStyle(.switch)
                .labelsHidden()
                .scaleEffect(0.7)
                .frame(width: 38)
                .allowsHitTesting(false)
                .focusable(false)
                .disabled(disabled)
        }
        .frame(height: 24)
        .padding(.horizontal, 8)
        .background(isHovered && !disabled ? Color.accentColor : Color.clear)
        .foregroundColor(isHovered && !disabled ? .white : textColor)
        .cornerRadius(4)
        .opacity(disabled ? 0.4 : 1.0)
        .contentShape(Rectangle())
        .onTapGesture {
            if !disabled {
                isOn.toggle()
            }
        }
        .onHover { isHovered = $0 }
    }
}

// MARK: - Action Row
struct ConfigActionRow: View {
    let title: String
    let icon: String
    let textColor: Color
    let disabled: Bool
    let action: () -> Void
    @State private var isHovered = false

    var body: some View {
        Button(action: action) {
            HStack {
                Text(title)
                    .font(.menu)
                Spacer()
                Image(systemName: icon)
                    .font(.system(size: 12))
                    .foregroundColor(isHovered && !disabled ? .white.opacity(0.7) : .secondary)
            }
            .frame(height: 24)
            .padding(.horizontal, 8)
            .background(isHovered && !disabled ? Color.accentColor : Color.clear)
            .foregroundColor(isHovered && !disabled ? .white : textColor)
            .cornerRadius(4)
            .opacity(disabled ? 0.4 : 1.0)
        }
        .buttonStyle(.plain)
        .focusable(false)
        .disabled(disabled)
        .onHover { isHovered = $0 }
    }
}
