//! The local control service: the CLI's only way to reach a node (§9.3).
//!
//! [`transport`] is the platform socket the gRPC connection runs over, [`proto`]
//! the service schema and the types that cross it, [`server`] the daemon side,
//! [`client`] the caller's side.

pub mod client;
pub mod proto;
pub mod server;
pub mod transport;

pub use client::{
    Chunks, Client, CompletedUpload, Deleted, Entries, Frames, OpenUpload, PartUpload, Put,
    RecordedPart, StreamedWrite, UploadRef, WriteFamily, Written,
};
pub use proto::{Command, ControlError, EntryInfo, ErrorCode, Frame, CONTROL_VERSION};
pub use server::{Pending, Server};
