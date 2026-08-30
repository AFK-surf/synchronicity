#if DEBUG
import SwiftUI
import Testing
@testable import Hecatia

/// Renders the app's surfaces off-screen so they can be looked at.
///
/// `screencapture` needs a screen-recording grant a headless build does not
/// have, and a visual change nobody sees is a change nobody checked. Set
/// `HECATIA_SNAPSHOT_DIR` and this writes a PNG per surface.
///
/// Two limits worth knowing before trusting a file here. `ImageRenderer` runs
/// one layout pass with no window behind it, so a `ScrollView`'s contents and
/// some AppKit-backed controls come back empty or as a placeholder swatch; and
/// the appearance cannot be changed, so everything is light. The real windows,
/// captured by ``WindowSnapshot``, have neither limit and are what a doubtful
/// case should be checked against.
///
/// It is a *tool*, not an assertion: there are no golden images to drift.
/// Without the variable set it does nothing, so `make test` stays fast.
@MainActor
struct Snapshots {

  @Test func renderEverySurface() throws {
    guard let directory = ProcessInfo.processInfo.environment["HECATIA_SNAPSHOT_DIR"] else { return }
    let root = URL(fileURLWithPath: directory)
    try? FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)

    for surface in Self.surfaces() {
      // Light only, and deliberately. The theme resolves semantic AppKit
      // colours against `NSApp.effectiveAppearance`, and this process has no
      // running application to change — neither a drawing appearance pushed
      // around the render nor `NSApplication.shared.appearance` reaches
      // `ImageRenderer`, so a "dark" file here would be a light one with a
      // misleading name. Dark is checked where it can be: against the real
      // windows, via `HECATIA_SNAPSHOT_APPEARANCE=dark` (see `WindowSnapshot`).
      let written = Self.write(
        surface.view, to: root.appendingPathComponent("\(surface.name).png"),
        width: surface.width)
      #expect(written, "\(surface.name) rendered nothing")
    }
  }

  struct Surface {
    let name: String
    let width: Double
    let view: AnyView
  }

  private static func write(_ view: AnyView, to url: URL, width: CGFloat) -> Bool {
    let framed = view
      .frame(width: width)
      .background(Color(nsColor: .windowBackgroundColor))
    let renderer = ImageRenderer(content: framed)
    renderer.scale = 2
    guard let image = renderer.cgImage,
          let data = NSBitmapImageRep(cgImage: image).representation(using: .png, properties: [:])
    else { return false }
    try? data.write(to: url)
    return true
  }

  private static func surfaces() -> [Surface] {
    let node = NodeStore.preview(transfers: SampleData.transfers)
    let empty = Binding<ConfirmationRequest?>(get: { nil }, set: { _ in })

    return [
      Surface(name: "01-chrome", width: 560, view: AnyView(
        VStack(alignment: .leading, spacing: 14) {
          HStack(spacing: 8) {
            StatusChip(text: "static", tint: Theme.accent)
            StatusChip(text: "3", tint: Theme.warning, systemImage: "arrow.triangle.branch")
            StatusChip(text: "attached", tint: Theme.online)
            StatusChip(text: "retiring", tint: Theme.danger)
          }
          DetailRow(label: "Path", value: "journal/2026/01-15.md", mono: true, copyable: "x")
          DetailRow(label: "Contents", value: "a1b2c3d4e5f60718293a4b5c6d7e8f90", mono: true, copyable: "full")
          AlarmBanner(
            text: "A peer advertises a newer published position for this Mac than it holds.",
            tint: Theme.danger, actionTitle: "Resume…", action: {})
          ParseWarningChip(lines: ["a line a later daemon added"])
        }.padding(20))),

      Surface(name: "02-transfers", width: 380, view: AnyView(
        TransfersPopover().environment(node))),

      // The *empty* inspector, deliberately. With a row selected this surface
      // is headed by a segmented `Picker`, and `ImageRenderer` cannot draw an
      // AppKit-backed control: it substitutes a yellow "nosign" bar and leaves
      // the `ScrollView` under it blank. The populated inspector is covered by
      // the other channel — `WindowSnapshot` photographs the real window, and
      // that one draws it correctly. Between the two every surface is visible
      // in one of them; see the note on `WindowSnapshot`.
      Surface(name: "03-inspector-empty", width: 340, view: AnyView(
        FileInspector(model: FilesModel.preview(rows: []), confirmation: empty)
          .environment(node).frame(height: 260))),

      Surface(name: "04-first-run-no-daemon", width: 640, view: AnyView(
        FirstRunView(state: .cannotConnect(
          DaemonFailure(code: .unavailable, detail: "Nothing is listening on control.sock.")))
          .environment(node).frame(height: 420))),

      Surface(name: "05-first-run-no-folders", width: 640, view: AnyView(
        FirstRunView(state: .noSpaces({})).environment(node).frame(height: 380))),

      // No 06: Overview went with the Node window. Its status lines are part
      // of Diagnostics now, and 15 photographs those.

      Surface(name: "07-keys", width: 720, view: AnyView(
        KeysPane(confirmation: empty).environment(node).frame(height: 560))),

      Surface(name: "08-members", width: 780, view: AnyView(
        MembersPane(confirmation: empty).environment(node).frame(height: 520))),

      Surface(name: "09-replicas-and-pins", width: 720, view: AnyView(
        PinsPane(confirmation: empty).environment(node).frame(height: 520))),

      Surface(name: "10-remote-access", width: 720, view: AnyView(
        RemoteAccessPane(confirmation: empty).environment(node).frame(height: 560))),

      Surface(name: "11-bucket-sheet", width: 460, view: AnyView(
        BucketSheet().environment(node))),

      Surface(name: "12-access-key-sheet", width: 480, view: AnyView(
        AccessKeySheet(generated: { _ in }).environment(node))),

      Surface(name: "13-add-folder", width: 480, view: AnyView(
        AddSourceSheet().environment(node))),

      Surface(name: "14-network", width: 760, view: AnyView(
        NetworkPane().environment(node).frame(height: 460))),

      Surface(name: "15-diagnostics", width: 720, view: AnyView(
        DiagnosticsPane(confirmation: empty).environment(node).frame(height: 520))),

      Surface(name: "16-activity", width: 760, view: AnyView(
        ActivityWindow().environment(node).frame(height: 460))),

      Surface(name: "17-glance", width: 320, view: AnyView(
        NodeGlance().environment(node))),

      // The whole window now, not a 520-wide tab strip: this is where the eight
      // operator pages live since the Node window was folded in, so the surface
      // worth rendering is the sidebar and a page beside it.
      Surface(name: "18-settings", width: 980, view: AnyView(
        PreferencesView(route: SettingsRoute(pane: .general)).environment(node))),

      Surface(name: "19-settings-node-page", width: 980, view: AnyView(
        PreferencesView(route: SettingsRoute(pane: .spaces)).environment(node))),
    ]
  }
}
#endif
