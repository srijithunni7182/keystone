# 🔐 Keystone

> The intelligent credential librarian for AI agents.

Keystone is a local, high-performance security daemon that manages API keys and secrets for autonomous AI agents. Instead of static environment variables, agents discover credentials through **semantic intent** — and raw keys never enter an agent's memory.

📖 **[Read the Vision: Why AI Agents Need a USB Vault](docs/VISION.md)**
📖 **[View the full CLI Reference Guide](docs/CLI_GUIDE.md)**

## Architecture

```text
┌─────────────┐     ┌──────────────┐     ┌─────────────────┐
│   CLI/MCP   │────▶│  Enclave     │────▶│ Platform Keyring│
│  Interface  │     │  (Argon2id)  │     │ (Keychain/DPAPI │
│             │     │              │     │  /libsecret)    │
└──────┬──────┘     └──────────────┘     └─────────────────┘
       │
       ▼
┌──────────────┐
│  Credential  │
│    Store     │
│  (SQLCipher) │
└──────────────┘
```

**Key Components:**

- **Enclave:** Secures the Master Key using native OS Keyrings and Argon2id derivation.
- **Store:** Encrypted SQLite (SQLCipher) retaining zero-knowledge of secrets until checked out.
- **Intelligence Layer:** Uses local `fastembed` AI models and cosine similarity to match agent intentions to stored API keys safely.
- **Guardrails:** Acts as a firewall enforcing Just-In-Time (JIT) token expiration and Human-In-The-Loop approvals for sensitive checkouts.

## Quick Start

### Prerequisites

- **Rust** 1.70+ (`curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`)
- **OpenSSL dev headers** (`sudo apt install libssl-dev` on Debian/Ubuntu)
- **C compiler** (`build-essential` on Debian/Ubuntu)

### Build

```bash
cargo build --release
```

### Initialize

```bash
cargo run --release -- init
```

This creates the encrypted database and stores the master key in your platform's native keyring.

### Quick Commands

*For an exhaustive list, including advanced Guardrail usages like approvals and audits, see the [CLI Guide](docs/CLI_GUIDE.md).*

Add a protected credential:

```bash
cargo run -- add \
  --provider github \
  --intent "GitHub PAT for CI/CD deployment pipeline" \
  --secret "ghp_your_token_here" \
  --require-approval \
  --max-ttl "1h"
```

Search your vault via Semantic Intent:

```bash
cargo run -- search "deploy to production cluster"
```

Start the daemon for AI Agents (MCP):

```bash
cargo run -- serve --transport stdio
```

Run Tests:

```bash
cargo test
```

## Security Design

| Layer | Mechanism |
| --- | --- |
| **Master Key Storage** | Platform keyring (Keychain / DPAPI / libsecret) |
| **Key Derivation** | Argon2id (64 MiB, 3 iterations, 4 lanes) |
| **Database Encryption** | SQLCipher (AES-256-GCM) |
| **Secret Redaction** | Private field, custom `Debug` impl, never in logs |
| **Audit Trail** | Every access logged with actor, action, timestamp |

## Project Structure

```text
src/
├── main.rs              # Entry point, CLI dispatch
├── lib.rs               # Library root
├── error.rs             # Top-level error types
├── enclave/
│   ├── mod.rs           # Enclave module
│   ├── provider.rs      # MasterKeyProvider trait + KeyringProvider
│   └── error.rs         # Enclave errors
├── store/
│   ├── mod.rs           # Store module
│   ├── models.rs        # Credential, Policy, CredentialSummary
│   ├── db.rs            # SQLCipher database wrapper
│   ├── repository.rs    # CredentialStore trait + CRUD impl
│   └── error.rs         # Store errors
├── intelligence/
│   ├── mod.rs           # Intelligence module
│   └── embeddings.rs    # Semantic search & fastembed logic
├── mcp/
│   └── server.rs        # Universal Gateway (MCP Server)
├── gateway/
│   ├── uds.rs           # Unix Domain Socket Server
│   └── protocol.rs      # Gateway protocol formats
└── cli/
    ├── mod.rs           # CLI definition (clap)
    └── commands.rs      # Command handlers
```

## Roadmap

- [x] **Phase I**: Secure Foundation (Storage, Enclave, CLI)
- [x] **Phase II**: Universal Gateway (MCP Server, Unix Domain Sockets)
- [x] **Phase III**: Intelligence Layer (Semantic Search, Embeddings)
- [x] **Phase IV**: Safety Guardrails (JIT Tokens, HITL, Audit)

## License

Apache-2.0 — see [LICENSE](LICENSE).
