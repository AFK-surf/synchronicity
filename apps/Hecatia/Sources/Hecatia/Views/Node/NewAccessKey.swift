import SwiftUI

/// A secret the app just generated, held only long enough to show it once.
struct NewAccessKey: Identifiable, Equatable {
  var id: String { keyID }
  let keyID: String
  let secret: String
}
