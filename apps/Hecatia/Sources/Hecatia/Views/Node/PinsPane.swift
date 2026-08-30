import SwiftUI

/// Explicit operator pins. Replica-held content is shown with its replica.
struct PinsPane: View {
  @Binding var confirmation: ConfirmationRequest?

  var body: some View {
    ScrollView {
      PinsSection(confirmation: $confirmation)
        .padding(Theme.Space.xl)
    }
  }
}

#if DEBUG
#Preview("Pins") {
  PinsPane(confirmation: .constant(nil))
    .environment(NodeStore.preview())
    .frame(width: 760, height: 560)
}
#endif
