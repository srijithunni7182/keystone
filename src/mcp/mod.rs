// Keystone — MCP Server Module
//
// Exposes credential operations as MCP tools that AI assistants
// (Claude, Cursor, etc.) can discover and call via stdio transport.

mod server;

pub use server::KeystoneServer;
