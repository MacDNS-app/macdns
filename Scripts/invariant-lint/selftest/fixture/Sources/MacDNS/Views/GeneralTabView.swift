import SwiftUI

struct GeneralTabView: View {
    let extensionActive: Bool

    var body: some View {
        // NEGATIVE CONTROL for J15: the system-extension activation label, not
        // protection status. J15's only allowlist entry keys on this flag.
        Text(extensionActive ? "Active" : "Inactive")
    }
}
