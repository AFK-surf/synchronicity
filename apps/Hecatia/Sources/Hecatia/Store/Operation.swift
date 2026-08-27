import Foundation

/// One thing the daemon can be asked to do.
///
/// The registry below is the single place an operation is described, and the
/// menu item, the confirmation, the disabled-with-a-reason state, the cache
/// invalidation and the `synch` command line an operator can check all fall
/// out of it. That is what makes adding the next operation a value rather than
/// a redesign.
struct Operation: Identifiable, Sendable {
  /// How much ceremony the operation gets, chosen by its consequence rather
  /// than by its verb.
  enum Gate: Sendable {
    /// Reads, and writes that change nothing a user can lose.
    case none
    /// A plain confirmation naming the object. Half its value is correcting
    /// the user's guess about what the operation does.
    case confirm
    /// A confirmation whose consequence the app computes and states.
    case consequence
    /// Typed confirmation, behind a disclosure that resets on quit.
    case typed
    /// No control at all until the condition that makes it the only fix.
    case conditional
  }

  /// Which window it belongs to. Files takes only operations that name a file
  /// or a folder; everything else is the Node window's.
  enum Surface: String, Sendable {
    case files
    case node
    /// Reached from the menu bar item or the Activity window only.
    case ambient
    /// Used by the app, never presented as a command (the multipart calls are
    /// the transfer engine, not a menu item).
    case machinery
    /// Deliberately not surfaced, with the reason recorded.
    case notSurfaced
  }

  let id: String
  let title: String
  /// The equivalent `synch` invocation. Shown in Node-window sheets and in the
  /// Activity transcript, never in a Files dialog: an operator verifying what
  /// the GUI is about to do is a real need; showing it to someone who will
  /// never open Terminal is noise.
  let commandLine: String
  let gate: Gate
  let surface: Surface
  /// Topics this operation *invalidates*. Reads leave this empty — a read that
  /// claimed to dirty what it fills re-enters its own refresh forever.
  let dirties: [Topic]
  /// Topics this operation *fills*, for a read.
  let provides: [Topic]
  /// Why it is not surfaced, when it is not.
  let omission: String?

  init(
    _ id: String,
    _ title: String,
    _ commandLine: String,
    gate: Gate = .none,
    surface: Surface = .node,
    dirties: [Topic] = [],
    provides: [Topic] = [],
    omission: String? = nil
  ) {
    self.id = id
    self.title = title
    self.commandLine = commandLine
    self.gate = gate
    self.surface = surface
    self.dirties = dirties
    self.provides = provides
    self.omission = omission
  }
}
