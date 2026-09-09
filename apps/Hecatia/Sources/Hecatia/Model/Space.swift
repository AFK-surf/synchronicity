import Foundation

/// One known namespace plus this node's independent local roles.
struct Space: Identifiable, Hashable, Sendable {
  let id: String
  /// Filesystem source path. Nil for API sources and nodes that do not publish.
  let localPath: String?
  let sourceKind: String?
  let sourceUnavailable: Bool
  let sourceError: String?
  let replicationSummary: String?
  let replicate: ReplicaPolicy?
  let graceSeconds: Int64?
  let budgetBytes: UInt64?
  let checkoutPath: String?
  let heldBytes: UInt64?
  let wanted: UInt64?

  init(
    id: String, localPath: String?, sourceKind: String? = nil,
    sourceUnavailable: Bool = false, sourceError: String? = nil,
    replicationSummary: String? = nil, replicate: ReplicaPolicy? = nil,
    graceSeconds: Int64? = nil, budgetBytes: UInt64? = nil,
    checkoutPath: String? = nil, heldBytes: UInt64? = nil, wanted: UInt64? = nil
  ) {
    self.id = id
    self.localPath = localPath
    self.sourceKind = sourceKind ?? (localPath == nil ? nil : "filesystem")
    self.sourceUnavailable = sourceUnavailable
    self.sourceError = sourceError
    self.replicationSummary = replicationSummary
    self.replicate = replicate
    self.graceSeconds = graceSeconds
    self.budgetBytes = budgetBytes
    self.checkoutPath = checkoutPath
    self.heldBytes = heldBytes
    self.wanted = wanted
  }

  init(_ info: Synch_Control_V1_SpaceInfo) {
    let replicate = info.hasRetention ? ReplicaPolicy(rawValue: info.retention) : nil
    let budgetBytes = info.hasBudget ? info.budget : nil
    let heldBytes = info.hasHeldBytes ? info.heldBytes : nil
    let wanted = info.hasWanted ? info.wanted : nil
    id = info.id
    localPath = info.hasSourcePath ? info.sourcePath : nil
    sourceKind = info.hasSourceKind ? info.sourceKind : nil
    sourceUnavailable = info.sourceState == .unavailable
    sourceError = info.hasSourceError ? info.sourceError : nil
    self.replicate = replicate
    graceSeconds = replicate == .current ? info.graceSecs : nil
    self.budgetBytes = budgetBytes
    checkoutPath = info.hasCheckoutPath ? info.checkoutPath : nil
    self.heldBytes = heldBytes
    self.wanted = wanted
    replicationSummary = replicate.map { policy in
      var value = "\(policy.label.lowercased()) retention"
      if let budgetBytes { value += " · \(budgetBytes) B budget" }
      if let heldBytes { value += " · \(heldBytes) B held" }
      if let wanted { value += " · \(wanted) wanted" }
      return value
    }
  }

  var isReplicating: Bool { replicate != nil }
  var isRemoteOnly: Bool { sourceKind == nil }
  var hasFilesystemSource: Bool { sourceKind == "filesystem" }
  var isSourceUnavailable: Bool { hasFilesystemSource && sourceUnavailable }
  var isSource: Bool { sourceKind != nil }

  /// What to show where a path would go.
  var pathLabel: String {
    localPath ?? (sourceKind == "api" ? "API source" : "Not published by this Mac")
  }
}
