#if DEBUG
import AppKit

/// Writes down what the caret does, so a fault only a person can reproduce
/// can still be read afterwards.
///
/// The in-process probe drives this app with synthetic events, and for focus
/// that is not enough: a synthetic Escape never reaches an `NSSearchField`'s
/// field editor, and synthetic clicks move the caret in cases a real one does
/// not. So when the checks pass and the app is still wrong, this records the
/// real session instead — every click, with what was under it, and every
/// change of first responder, with what asked for it.
///
/// Inert unless `HECATIA_FOCUS_TRACE` is set.
@MainActor
enum FocusTrace {
  private static var last = ""
  private static var started: Date?
  private static var monitors: [Any] = []

  /// Read once. `claim` is called from `mouseDown`, and reaching into
  /// `ProcessInfo.environment` rebuilds a dictionary each time it is asked.
  static let isOn = ProcessInfo.processInfo.environment["HECATIA_FOCUS_TRACE"] != nil

  static func startIfAsked() {
    guard isOn, monitors.isEmpty else { return }
    started = .now
    say("watching. Do the sequence, then quit the app and send this back.")

    for mask in [NSEvent.EventTypeMask.leftMouseDown, .leftMouseUp, .keyDown] {
      let monitor = NSEvent.addLocalMonitorForEvents(matching: mask) { event in
        note(event)
        return event
      }
      if let monitor { monitors.append(monitor) }
    }

    // Polled rather than observed: AppKit posts no notification when the first
    // responder changes, and the point of this is to catch the change nobody
    // in this app asked for.
    Task { @MainActor in
      while !Task.isCancelled {
        try? await Task.sleep(for: .milliseconds(60))
        // `keyWindow` is nil whenever the app is not frontmost — including
        // under the probe, where this recorded nothing at all until it fell
        // back.
        guard let window = NSApp.keyWindow ?? NSApp.mainWindow
          ?? NSApp.windows.first(where: { $0.isVisible && $0.canBecomeKey })
        else { continue }
        let now = describe(window.firstResponder)
        if now != last {
          say("caret: \(last.isEmpty ? "—" : last) -> \(now)")
          last = now
        }
      }
    }
  }

  /// Called by the things in this app that move the caret on purpose, so a
  /// change it made can be told from one AppKit made.
  ///
  /// `@autoclosure`, so "inert unless asked" is true of the message as well as
  /// of the write. Spelled as a plain `String` this built its argument at every
  /// call site whatever the flag said — and one of those call sites is
  /// `becomeFirstResponder`.
  static func claim(_ who: String, _ what: @autoclosure () -> String) {
    guard isOn else { return }
    say("\(who) asked for the caret: \(what())")
  }

  private static func note(_ event: NSEvent) {
    guard let window = event.window else { return }
    switch event.type {
    case .keyDown:
      say("key \(event.keyCode) \(event.charactersIgnoringModifiers.map { "“\($0)”" } ?? "")")
    default:
      let point = event.locationInWindow
      let hit = window.contentView?.hitTest(point)
      say("\(event.type == .leftMouseDown ? "down" : "up  ") at "
        + "\(Int(point.x)),\(Int(point.y)) over \(hit.map { String(describing: type(of: $0)) } ?? "nothing")"
        + " accepts=\(hit?.acceptsFirstResponder ?? false)")
    }
  }

  private static func describe(_ responder: NSResponder?) -> String {
    guard let responder else { return "nothing" }
    let name = String(describing: type(of: responder))
    guard let text = responder as? NSText, let owner = text.delegate else { return name }
    return "\(name)(editing \(String(describing: type(of: owner))))"
  }

  private static func say(_ line: String) {
    let elapsed = started.map { Date.now.timeIntervalSince($0) } ?? 0
    FileHandle.standardError.write(Data(String(format: "focus %6.2fs  %@\n", elapsed, line).utf8))
  }
}
#endif
