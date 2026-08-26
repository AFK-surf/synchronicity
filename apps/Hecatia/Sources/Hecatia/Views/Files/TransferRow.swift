import SwiftUI

struct TransferRow: View {
  @Environment(NodeStore.self) private var node
  let transfer: Transfer

  var body: some View {
    HStack(spacing: Theme.Space.m) {
      Image(systemName: transfer.direction == .upload ? "arrow.up.doc" : "arrow.down.doc")
        .foregroundStyle(Theme.muted)
        .frame(width: 22)

      VStack(alignment: .leading, spacing: Theme.Space.xs) {
        Text(transfer.name).font(.callout).lineLimit(1).truncationMode(.middle)
        HStack(spacing: Theme.Space.snug) {
          Text(transfer.statusLabel).font(.caption).foregroundStyle(statusColor)
          // What time it finished, because a list that keeps its rows is a
          // history and a history says when. Wall-clock rather than "2 minutes
          // ago": these rows are read next to each other, and an ordering is
          // what is wanted from them.
          if let finishedAt = transfer.finishedAt {
            Text(finishedAt, format: .dateTime.hour().minute())
              .font(.caption).foregroundStyle(Theme.muted)
              .accessibilityLabel("at \(finishedAt.formatted(date: .omitted, time: .shortened))")
          }
          if transfer.uploadID != nil, transfer.isActive {
            StatusChip(text: "resumable", tint: Theme.accent)
          }
          if transfer.resumedFrom > 0, transfer.isActive {
            StatusChip(text: "continued", tint: Theme.accent)
              .help("Picked up from the \(ByteCountFormatter.string(fromByteCount: transfer.resumedFrom, countStyle: .file)) the last attempt left on disk.")
          }
        }
        if transfer.isActive, transfer.total > 0 {
          ProgressView(value: transfer.progress).controlSize(.small)
        }
      }

      Spacer(minLength: Theme.Space.xs)

      if transfer.isActive {
        Button { node.transfers.cancel(transfer.id) } label: {
          Image(systemName: "xmark.circle.fill").glyphButton()
        }
        .buttonStyle(.plain)
        .foregroundStyle(Theme.muted)
        .help("Cancel this transfer")
        .accessibilityLabel("Cancel \(transfer.name)")
      } else if case .completed = transfer.state {
        Image(systemName: "checkmark.circle.fill").foregroundStyle(Theme.online)
      } else {
        HStack(spacing: Theme.Space.snug) {
          if case .failed = transfer.state {
            Image(systemName: "exclamationmark.circle.fill").foregroundStyle(Theme.danger)
          }
          if node.transfers.canRetry(transfer.id) {
            // A stopped transfer that cannot be started again is a dead row.
            Button("Retry") { node.transfers.retry(transfer.id) }
              .buttonStyle(.borderless).font(.caption)
              .help("Continue from what is already transferred")
              .accessibilityLabel("Retry \(transfer.name)")
          }
        }
      }
    }
    .padding(.horizontal, Theme.Space.l).padding(.vertical, Theme.Space.s)
    .accessibilityElement(children: .combine)
  }

  private var statusColor: Color {
    switch transfer.state {
    case .failed: return Theme.danger
    case .completed: return Theme.online
    default: return Theme.muted
    }
  }
}

#if DEBUG
#Preview("Uploading") {
  let uploading = SampleData.transfers[0]
  return TransferRow(transfer: uploading)
    .environment(NodeStore.preview(transfers: [uploading]))
    .frame(width: 380)
}

#Preview("Downloaded") {
  let finished = SampleData.transfers[1]
  return TransferRow(transfer: finished)
    .environment(NodeStore.preview(transfers: [finished]))
    .frame(width: 380)
}

#Preview("Failed") {
  // The queue in the environment is the one holding this row. Retry is the
  // queue's answer and not the row's, so a row put in front of a store that
  // has never seen it is drawn without one — which is not a state the app can
  // reach.
  let failed = SampleData.transfers[2]
  return TransferRow(transfer: failed)
    .environment(NodeStore.preview(transfers: [failed]))
    .frame(width: 380)
}

#Preview("Narrow") {
  // 380 is the popover these rows live in, and it is the only width they ever
  // get. Narrower than that the name truncates in the middle and the daemon's
  // refusal wraps, rather than either of them crowding out the cancel.
  let store = NodeStore.preview(transfers: SampleData.transfers)
  return VStack(spacing: 0) {
    ForEach(store.transfers.listed) { TransferRow(transfer: $0) }
  }
  .environment(store)
  .frame(width: 240)
}
#endif
