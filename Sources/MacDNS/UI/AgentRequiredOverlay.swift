// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import SwiftUI

/// Veil shown over settings that need the MacDNS Agent while protection is off.
/// The content is inert and the veil offers a button that turns protection on.
struct AgentRequiredOverlay: ViewModifier {
    let isAgentActive: Bool
    let canTurnOn: Bool
    let onTurnOn: () -> Void

    func body(content: Content) -> some View {
        content
            .allowsHitTesting(isAgentActive)
            .disabled(!isAgentActive)
            .accessibilityHidden(!isAgentActive)
            .overlay {
                if !isAgentActive {
                    Rectangle()
                        .fill(.ultraThinMaterial)
                        .overlay {
                            // Compact fallback keeps the button reachable on short cards.
                            ViewThatFits(in: .vertical) {
                                VStack(spacing: 8) {
                                    shield(size: 44)
                                        .padding(.bottom, 4)
                                    Text("Protection is off")
                                        .font(.system(size: 15, weight: .semibold))
                                    Text("Turn on protection to change these settings.")
                                        .font(.system(size: 12.5))
                                        .foregroundStyle(Color.settingsSecondaryText)
                                    turnOnButton
                                        .padding(.top, 6)
                                }
                                .multilineTextAlignment(.center)
                                .padding(.horizontal, 28)
                                .padding(.vertical, 22)
                                .background(veilCard)

                                HStack(spacing: 10) {
                                    shield(size: 22)
                                    Text("Protection is off")
                                        .font(.system(size: 13, weight: .semibold))
                                    turnOnButton
                                }
                                .padding(.horizontal, 14)
                                .padding(.vertical, 8)
                                .background(veilCard)
                            }
                            .padding(12)
                        }
                        .clipShape(RoundedRectangle(cornerRadius: SettingsMetrics.cardCornerRadius, style: .continuous))
                }
            }
    }

    private func shield(size: CGFloat) -> some View {
        Image("StatusOff")
            .resizable()
            .aspectRatio(contentMode: .fit)
            .frame(width: size, height: size)
    }

    private var veilCard: some View {
        let shape = RoundedRectangle(cornerRadius: 12, style: .continuous)
        return
            shape
            .fill(Color.settingsCard)
            .overlay(shape.strokeBorder(Color.settingsCardStroke, lineWidth: 1))
            .shadow(color: .black.opacity(0.12), radius: 12, y: 4)
    }

    private var turnOnButton: some View {
        Button("Turn On Protection", action: onTurnOn)
            .buttonStyle(.borderedProminent)
            .disabled(!canTurnOn)
    }
}

extension View {
    /// Covers the view with a veil that offers to turn protection on when the agent is not running.
    func requiresAgent(isActive: Bool, canTurnOn: Bool, onTurnOn: @escaping () -> Void) -> some View {
        modifier(AgentRequiredOverlay(isAgentActive: isActive, canTurnOn: canTurnOn, onTurnOn: onTurnOn))
    }
}
