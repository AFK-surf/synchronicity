import Foundation

/// An upload the daemon still holds parts for, and the folder it belongs to.
///
/// `UploadInfo` names the path and the id but not the space, while the request
/// that lists them names the space — so the pairing exists only at the call
/// site, and keeping it is the difference between a discard that works and one
/// the daemon answers as an upload that never existed.
struct ResumableUpload: Identifiable, Sendable, Equatable {
  let space: String
  let info: Synch_Control_V1_UploadInfo

  var id: String { info.uploadID }
  var path: String { info.path }
  var name: String { (info.path as NSString).lastPathComponent }
}
