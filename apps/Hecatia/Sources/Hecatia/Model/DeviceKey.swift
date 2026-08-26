import Foundation

/// One device key this node holds, from `id` / `key ls`.
struct DeviceKey: Identifiable, Hashable, Sendable {
  enum State: String, Sendable { case staged, active, retiring, unknown }
  var id: String { key }
  let key: String
  let state: State
  /// `key ls` adds how many peers have seen this key. Absent from `id`.
  var peersHolding: String?
}
