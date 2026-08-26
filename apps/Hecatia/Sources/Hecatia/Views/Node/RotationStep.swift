import SwiftUI

/// One numbered step of the key-rotation flow, with its own controls.
///
/// The actions are stored as a built value rather than as an escaping
/// `@ViewBuilder` closure — the same shape as ``BorderedTable``'s action bar.
struct RotationStep<Actions: View>: View {
  let number: Int
  let title: String
  let done: Bool
  let detail: String
  @ViewBuilder var actions: Actions

  var body: some View {
    HStack(alignment: .top, spacing: Theme.Space.m) {
      ZStack {
        Circle().fill(done ? Theme.online.opacity(0.2) : Theme.accentSoft).frame(width: 22, height: 22)
        if done {
          Image(systemName: "checkmark").imageScale(.small).fontWeight(.bold)
            .foregroundStyle(Theme.ink(Theme.online))
        } else {
          // `Theme.ink`, because this is the accent on the accent's own 12%
          // wash — about 1.4:1 with a light system accent, against a 4.5:1
          // floor for a bold caption. Steps 2, 3 and 4 are never "done", so it
          // was on screen every time the pane opened.
          Text("\(number)").font(.caption.weight(.bold))
            .foregroundStyle(Theme.ink(Theme.accent))
        }
      }
      VStack(alignment: .leading, spacing: Theme.Space.xs) {
        Text(title).font(.callout.weight(.semibold))
        Text(detail).font(.caption).foregroundStyle(Theme.muted)
          .fixedSize(horizontal: false, vertical: true)
      }
      Spacer(minLength: Theme.Space.s)
      HStack(spacing: Theme.Space.snug) { actions }.controlSize(.small)
    }
  }
}

#if DEBUG
// The previews are all `Theme.measure` wide with the page's padding inside it,
// which lands within a few points of what the card on the Keys page leaves a
// step. The settings window does not resize, so that is the only width these
// are ever drawn at.

#Preview("A step to do") {
  RotationStep(
    number: 3, title: "Check that they have it",
    done: false,
    detail: "Ask each device what it holds. Do not go further until the count is everybody."
  ) {
    Button("Ask the Other Devices…") {}
  }
  .padding(Theme.Space.xl)
  .frame(width: Theme.measure)
}

#Preview("A step already done") {
  RotationStep(
    number: 1, title: "Generate a new key",
    done: true,
    detail: "Creates a second key alongside the current one. Nothing changes for anyone yet."
  ) {
    Button("Generate") {}.disabled(true)
  }
  .padding(Theme.Space.xl)
  .frame(width: Theme.measure)
}

#Preview("A step with nothing to press") {
  // Step 2 before a key is staged: the actions build to nothing, and the row
  // still has to read as a step of the procedure rather than as a paragraph.
  RotationStep(
    number: 2, title: "Publish it where the other devices look",
    done: false,
    detail: "If you use a membership zone, update its record. If you trust devices individually, add the new key on each of them."
  ) {}
  .padding(Theme.Space.xl)
  .frame(width: Theme.measure)
}

#Preview("A step with two actions") {
  // Step 4, the widest of the four: two buttons against the longest title, and
  // the explanation has to wrap around them rather than push them off the row.
  RotationStep(
    number: 4, title: "Switch signing over, then retire the old key",
    done: false,
    detail: "Retiring deletes the old secret. There is no undo and no backup."
  ) {
    Button("Switch to the New Key") {}
    Button("Retire ab12cd34…", role: .destructive) {}
  }
  .padding(Theme.Space.xl)
  .frame(width: Theme.measure)
}
#endif
