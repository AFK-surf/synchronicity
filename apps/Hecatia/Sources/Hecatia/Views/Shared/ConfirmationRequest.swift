import SwiftUI

/// One pending confirmation.
struct ConfirmationRequest: Identifiable {
  let id = UUID()
  let title: String
  /// What will actually happen, computed rather than boilerplate.
  let consequence: String
  let verb: String
  let gate: Operation.Gate
  /// What the user must type, for the strongest gate.
  var typedPhrase: String?
  var commandLine: String?
  var isDestructive = true
  let perform: () -> Void
}
