import SwiftUI

struct DropHighlight: View {
  let canAccept: Bool

  var body: some View {
    RoundedRectangle(cornerRadius: Theme.Radius.l)
      .fill((canAccept ? Theme.accent : Theme.warning).opacity(0.1))
      .overlay {
        RoundedRectangle(cornerRadius: Theme.Radius.l)
          .stroke(canAccept ? Theme.accent : Theme.warning, style: StrokeStyle(lineWidth: 2, dash: [8]))
        VStack(spacing: Theme.Space.s) {
          Image(systemName: canAccept ? "arrow.down.doc.fill" : "xmark.circle")
            .font(.largeTitle)
            .foregroundStyle(canAccept ? Theme.accent : Theme.warning)
          Text(canAccept ? "Drop to add to this space" : "Choose a space first")
            .font(.headline)
        }
      }
      .padding(Theme.Space.m)
      .allowsHitTesting(false)
  }
}

#if DEBUG
#Preview("Drop target") {
  VStack(spacing: Theme.Space.l) {
    DropHighlight(canAccept: true)
    DropHighlight(canAccept: false)
  }
  .padding(Theme.Space.xl)
  .frame(width: 420, height: 320)
}
#endif
