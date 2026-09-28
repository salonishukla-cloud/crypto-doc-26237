# Developer Environment & Workstation Setup Guide

## 1. Prerequisites & Toolchain

* **Rust Toolchain**: Rust 1.75+ (stable)
  * Install via [rustup.rs](https://rustup.rs/):
    ```bash
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
    ```
* **Git**: 2.30+
* **PostgreSQL** (Optional metadata storage, version 14+)
* **Modern Web Browser**: Microsoft Edge, Chrome, or Firefox (for Fluent UI workstation)

---

## 2. Workspace Initialization

Clone the repository and inspect the Cargo workspace:

```bash
# Clone the repository
git clone <repository_url> cryptographic-attribution
cd cryptographic-attribution

# View workspace structure
cargo check
```

---

## 3. Team Member Branching Setup

Each developer must work in their assigned feature branch:

```bash
# Member 1 — Encryption
git checkout feature/member1-encryption

# Member 2 — Watermark
git checkout feature/member2-watermark

# Member 3 — Post-Quantum Cryptography
git checkout feature/member3-pqcrypto

# Member 4 — Offline Ledger
git checkout feature/member4-ledger

# Member 5 — Integration & UI
git checkout feature/member5-integration
```

---

## 4. Running Tests

Run unit tests within your specific module:

```bash
# Member 1
cargo test -p encryption

# Member 2
cargo test -p watermark

# Member 3
cargo test -p pqcrypto

# Member 4
cargo test -p ledger

# Member 5
cargo test -p integration

# Run all workspace unit and integration tests
cargo test --workspace
```

---

## 5. Previewing the Fluent UI Workstation

The frontend is built using standard Vanilla HTML, CSS, and JavaScript with the Fluent UI design system and Nexa typography tokens. It operates 100% offline without remote CDN dependencies once cached:

```bash
# Preview directly using any local HTTP static server or open in browser:
# Using python:
python -m http.server 8080 --directory integration/frontend

# Or using Node / npx:
npx -y serve integration/frontend
```

Open `http://localhost:8080` to interact with the workstation shell, test the Dark/Light mode toggle, and inspect the DecryptionEvent contract.
