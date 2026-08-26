import SwiftUI

struct VersionPolicyMenu: View {
  @Bindable var model: FilesModel
  let ownOrigin: String?
  /// How to print an origin for a person; a device key is not a name.
  let label: (String) -> String

  var body: some View {
    // A *read* setting, not a filter: the listing is folded under Newest and
    // the policy marks the rows it will not open, so a policy can never make a
    // folder look smaller than it is. That took work — the daemon's `List`
    // applies the policy itself and omits what it refuses — and the promise is
    // kept in `FilesModel.withheldPaths`.
    Menu {
      Picker("Version", selection: $model.policy) {
        Text("Newest").tag(VersionPolicy.newest)
        Text("Strict").tag(VersionPolicy.strict)
      }
      .pickerStyle(.inline)
      if !originChoices.isEmpty {
        Divider()
        Menu("From a device") {
          ForEach(originChoices, id: \.self) { origin in
            Button(origin) { model.policy = .origin(origin) }
          }
        }
      }
    } label: {
      Label(title, systemImage: "arrow.triangle.branch")
    }
    // The one control that makes this app different from a file browser, so
    // it keeps its word. A toolbar menu shows only its glyph by default,
    // which left an unlabelled branch icon meaning nothing to anyone.
    .labelStyle(.titleAndIcon)
    .help("Which version of a file this window opens")
    .onChange(of: model.policy) { _, _ in Task { await model.reload() } }
  }

  /// "From nas@cluster", not "From key:ao6bbsx33qwbyets4qzm…" — which is 57
  /// characters of identifier in a toolbar that has four other controls in it.
  private var title: String {
    if case .origin(let id) = model.policy { return "From \(label(id))" }
    return model.policy.label
  }

  /// The devices this folder's rows came from.
  ///
  /// Computed from `rows` rather than `visibleRows` so a filter cannot make a
  /// device disappear from the menu — and read only while the menu is being
  /// built, which is why the whole control is its own view: as an expression
  /// inside `FilesToolbar` it built a `Set` over every row and sorted it on
  /// every toolbar pass, menu closed or not.
  private var originChoices: [String] {
    var origins = Set(model.rows.lazy.map(\.origin).filter { !$0.isEmpty })
    if let ownOrigin { origins.insert(ownOrigin) }
    return origins.sorted()
  }
}

#if DEBUG
/// The control where it lives. A toolbar menu draws its label differently from
/// one in a `Form`, and the label is the whole point of this view.
private struct PolicyMenuPreview: View {
  var policy: VersionPolicy = .newest
  var width: CGFloat = 460
  var store: NodeStore = NodeStore.preview()

  var body: some View {
    let model = FilesModel.preview(rows: SampleData.rows, space: "notes", store: store)
    // Assigned before the menu is ever built, so it is the state the preview
    // starts in rather than a change that would send the model reloading.
    model.policy = policy
    return NavigationStack {
      Color.clear.toolbar {
        ToolbarItem(placement: .navigation) {
          VersionPolicyMenu(
            model: model, ownOrigin: store.origin, label: store.label(forOrigin:))
        }
      }
    }
    .frame(width: width, height: 120)
  }
}

#Preview("Version policy") {
  PolicyMenuPreview()
}

#Preview("Strict") {
  PolicyMenuPreview(policy: .strict)
}

#Preview("From a device") {
  PolicyMenuPreview(policy: .origin("nas@x.example"))
}

#Preview("From a device with no name") {
  // `key:` and 52 characters of z-base-32 is what the policy holds; what the
  // toolbar gets is six of them and a word. The narrow frame is the point.
  PolicyMenuPreview(
    policy: .origin("key:" + String(repeating: "y", count: 52)), width: 380)
}
#endif
