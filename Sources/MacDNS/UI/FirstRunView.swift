// SPDX-FileCopyrightText: 2025-2026 Marcus Grando
// SPDX-License-Identifier: LicenseRef-FCL-1.0-ALv2

import SwiftUI

/// One closure per first-run button, so the view renders without a view model.
struct FirstRunActions {
    /// Turn On and Continue on the resumed window.
    var turnOn: () -> Void
    /// Not now, Close, Done and OK.
    var close: () -> Void
    var tryAgain: () -> Void
    /// Continue while a step waits for it.
    var continueStep: () -> Void
    var skipNotifications: () -> Void
    var moveToApplications: () -> Void
    var quit: () -> Void
    var activate: (String) -> Void
    var getLicense: () -> Void
}

/// The first-run window content. `message` carries the activation error on
/// Trial ended, the copy-failed text on Move and the status message when
/// setup failed.
struct FirstRunView: View {
    static let brandBlue = Color(red: 0x02 / 255, green: 0x76 / 255, blue: 0xBD / 255)
    static let brandBlueDark = Color(red: 0x01 / 255, green: 0x56 / 255, blue: 0x9A / 255)

    let setup: FirstRunSetupPolicy
    let message: String?
    let actions: FirstRunActions
    /// False while another license request runs, so Activate never silently no-ops.
    var canActivate = true

    @State private var licenseKey = ""

    var body: some View {
        VStack(spacing: 20) {
            Image("FirstRunLogo")
                .resizable()
                .aspectRatio(contentMode: .fit)
                .frame(width: 72, height: 72)
                .accessibilityHidden(true)

            content
        }
        .padding(.horizontal, 32)
        .padding(.top, 8)
        .padding(.bottom, 24)
        .frame(width: 560)
        .fixedSize(horizontal: false, vertical: true)
        .foregroundStyle(.white)
        .background(
            LinearGradient(
                colors: [Self.brandBlue, Self.brandBlueDark],
                startPoint: .top,
                endPoint: .bottom
            )
        )
    }

    @ViewBuilder
    private var content: some View {
        switch setup.screen {
        case .steps(let phase):
            steps(phase)
        case .moveToApplications:
            VStack(spacing: 12) {
                row(
                    title: "Move MacDNS to Applications",
                    body:
                        "macOS only allows network extensions from apps in the Applications folder. MacDNS will move itself there and reopen."
                ) {
                    messageText
                } primary: {
                    Button("Move to Applications", action: actions.moveToApplications)
                        .buttonStyle(FirstRunPrimaryButtonStyle())
                }
                secondary("Quit", action: actions.quit)
            }
        case .trialEnded:
            VStack(spacing: 12) {
                row(
                    title: "Your MacDNS trial has ended",
                    body: "Enter a license key to turn MacDNS back on."
                ) {
                    TextField("License key", text: $licenseKey)
                        .textFieldStyle(.roundedBorder)
                        .foregroundStyle(.primary)
                        .environment(\.colorScheme, .light)
                        .padding(.top, 4)
                    messageText
                } primary: {
                    Button("Activate") { actions.activate(licenseKey) }
                        .buttonStyle(FirstRunPrimaryButtonStyle())
                        .disabled(!canActivate || licenseKey.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
                }
                secondary("Get License", action: actions.getLicense)
            }
        }
    }

    private func steps(_ phase: FirstRunStepsPhase) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            VStack(alignment: .leading, spacing: 8) {
                Text(Self.title(for: phase))
                    .font(.title3.weight(.semibold))
                if let body = phaseBody(phase) {
                    Text(body)
                        .foregroundStyle(.white.opacity(0.9))
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            VStack(alignment: .leading, spacing: 10) {
                ForEach(setup.visibleSteps, id: \.self) { step in
                    stepRow(step, phase: phase)
                }
                if setup.showsTurningOnProtection {
                    HStack(spacing: 10) {
                        ProgressView()
                            .controlSize(.small)
                            .environment(\.colorScheme, .dark)
                            .frame(width: 18)
                        Text("Turning on protection")
                    }
                }
            }
            if setup.showsLocalNetworkNote {
                Text(Self.localNetworkNote)
                    .font(.callout)
                    .foregroundStyle(.white.opacity(0.85))
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack(spacing: 16) {
                Spacer()
                stepsButtons(phase)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private func stepRow(_ step: FirstRunSetupStep, phase: FirstRunStepsPhase) -> some View {
        let status = setup.status(of: step)
        return HStack(alignment: .firstTextBaseline, spacing: 10) {
            statusMark(status, running: phase == .running && !setup.awaitsContinue)
                .frame(width: 18)
            VStack(alignment: .leading, spacing: 6) {
                Text(Self.title(for: step))
                    .fontWeight(status == .current ? .semibold : .regular)
                    .foregroundStyle(.white.opacity(status == .pending ? 0.7 : 1))
                if status == .current {
                    Text(Self.body(for: step))
                        .foregroundStyle(.white.opacity(0.9))
                        .fixedSize(horizontal: false, vertical: true)
                    if let instruction = instruction(for: step) {
                        Text(instruction)
                            .font(.callout.weight(.medium))
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
        }
    }

    @ViewBuilder
    private func statusMark(_ status: FirstRunStepStatus, running: Bool) -> some View {
        switch status {
        case .done:
            Image(systemName: "checkmark.circle.fill")
        case .failed:
            Image(systemName: "xmark.circle.fill")
        case .current where running:
            ProgressView()
                .controlSize(.small)
                .environment(\.colorScheme, .dark)
        case .current:
            Image(systemName: "circle.inset.filled")
        case .pending:
            Image(systemName: "circle")
                .foregroundStyle(.white.opacity(0.7))
        }
    }

    @ViewBuilder
    private func stepsButtons(_ phase: FirstRunStepsPhase) -> some View {
        switch phase {
        case .notStarted:
            primary("Turn On", action: actions.turnOn)
            secondaryButton("Not now", action: actions.close)
        case .resumed:
            primary("Continue", action: actions.turnOn)
            secondaryButton("Not now", action: actions.close)
        case .running:
            if setup.awaitsContinue {
                primary("Continue", action: actions.continueStep)
            }
            if setup.offersSkip {
                secondaryButton("Skip", action: actions.skipNotifications)
            }
        case .failed:
            primary("Try Again", action: actions.tryAgain)
            secondaryButton("Close", action: actions.close)
        case .restartRequired:
            primary("OK", action: actions.close)
        case .done:
            primary("Done", action: actions.close)
        }
    }

    private func phaseBody(_ phase: FirstRunStepsPhase) -> String? {
        switch phase {
        case .failed:
            return message
        case .restartRequired:
            return
                "macOS finishes installing MacDNS after a restart. Then open MacDNS and turn it on in the menu bar."
        case .notStarted, .resumed, .running, .done:
            return nil
        }
    }

    private static func title(for phase: FirstRunStepsPhase) -> String {
        switch phase {
        case .notStarted, .resumed, .running: return "Set up MacDNS"
        case .failed: return "MacDNS didn't start"
        case .restartRequired: return "Restart to finish setting up MacDNS"
        case .done: return "MacDNS is protecting this Mac"
        }
    }

    private static func title(for step: FirstRunSetupStep) -> String {
        switch step {
        case .prepare: return "Get MacDNS ready"
        case .networkExtension: return "Allow the network extension"
        case .dnsFilter: return "Allow DNS filtering"
        case .notifications: return "Allow notifications"
        }
    }

    private static func body(for step: FirstRunSetupStep) -> String {
        switch step {
        case .prepare:
            return
                "MacDNS installs its background service and starts your free trial. macOS may show a notification that MacDNS added a background item."
        case .networkExtension:
            return
                "MacDNS reads the DNS lookups on this Mac through a macOS network extension. That is how it blocks ads, trackers and malware and sends your lookups encrypted. MacDNS can't protect this Mac without it."
        case .dnsFilter:
            return
                "MacDNS turns on its DNS filter in macOS. It only handles DNS lookups and never reads the rest of your traffic."
        case .notifications:
            return
                "MacDNS reminds you before your trial ends and tells you when your Mac needs a restart to finish an update."
        }
    }

    /// The app can neither trigger nor read this request, so the window only
    /// explains it.
    static let localNetworkNote =
        "macOS may also ask to let MacDNS find devices on your local network. Click Allow so local names and Wi-Fi sign-in pages keep working. To change your answer later, go to System Settings > Privacy & Security > Local Network."

    private func instruction(for step: FirstRunSetupStep) -> String? {
        switch step {
        case .prepare:
            guard setup.showsAgentApprovalInstruction else { return nil }
            return "MacDNS opened System Settings. Turn on MacDNS under Login Items & Extensions."
        case .networkExtension:
            // System Settings moved the extension approval in macOS 15.
            return setup.inputs.macOSMajorVersion >= 15
                ? "After you click Continue, macOS asks about a new network extension. Click Open System Settings, turn on MacDNS under Network Extensions, and enter your password."
                : "After you click Continue, MacDNS opens System Settings. Click Allow under Privacy & Security and enter your password."
        case .dnsFilter:
            return "After you click Continue, click Allow if macOS asks whether MacDNS can filter network content."
        case .notifications:
            return "After you click Continue, click Allow when macOS asks."
        }
    }

    private func primary(_ title: String, action: @escaping () -> Void) -> some View {
        Button(title, action: action)
            .buttonStyle(FirstRunPrimaryButtonStyle())
    }

    private func row(
        title: String,
        body: String,
        @ViewBuilder detail: () -> some View,
        @ViewBuilder primary: () -> some View
    ) -> some View {
        HStack(alignment: .center, spacing: 24) {
            VStack(alignment: .leading, spacing: 8) {
                Text(title)
                    .font(.title3.weight(.semibold))
                Text(body)
                    .foregroundStyle(.white.opacity(0.9))
                    .fixedSize(horizontal: false, vertical: true)
                detail()
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            primary()
        }
    }

    @ViewBuilder
    private var messageText: some View {
        if let message {
            Text(message)
                .font(.callout.weight(.medium))
                .fixedSize(horizontal: false, vertical: true)
                .frame(maxWidth: .infinity, alignment: .leading)
        }
    }

    private func secondary(_ title: String, action: @escaping () -> Void) -> some View {
        secondaryButton(title, action: action)
            .frame(maxWidth: .infinity, alignment: .trailing)
    }

    private func secondaryButton(_ title: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Text(title)
                .font(.callout)
                .underline()
        }
        .buttonStyle(.plain)
        .foregroundStyle(.white.opacity(0.85))
    }
}

private struct FirstRunPrimaryButtonStyle: ButtonStyle {
    @Environment(\.isEnabled) private var isEnabled

    func makeBody(configuration: Configuration) -> some View {
        configuration.label
            .font(.body.weight(.semibold))
            .foregroundStyle(FirstRunView.brandBlueDark)
            .padding(.horizontal, 18)
            .padding(.vertical, 9)
            .background(RoundedRectangle(cornerRadius: 8).fill(.white))
            .opacity(isEnabled ? (configuration.isPressed ? 0.8 : 1) : 0.5)
            .fixedSize()
    }
}
