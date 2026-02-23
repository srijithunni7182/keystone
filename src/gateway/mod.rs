// Keystone — Gateway Module
//
// Unix Domain Socket (UDS) server for direct IPC with custom agents.
// Provides JSON-RPC 2.0 over Unix sockets with caller verification.

mod caller;
mod protocol;
mod uds;

pub use caller::CallerInfo;
pub use uds::UdsServer;
