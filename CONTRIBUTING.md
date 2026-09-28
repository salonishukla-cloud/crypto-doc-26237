# Contributing & Team Collaboration Guidelines

Welcome to the **Cryptographic Attribution & Immutable Decryption Provenance** engineering repository.

To enable **5 independent developers** to work simultaneously without merge conflicts, code clobbering, or protocol drift, everyone must adhere strictly to these rules and Git workflows.

---

## 1. Team Ownership Matrix

Each developer owns exactly one module. **No one should edit another member's module except during joint integration phases.**

| Role | Domain Module | Owned Directory | Assigned Branch |
| :--- | :--- | :--- | :--- |
| **Member 1** | Encryption & Packaging | `encryption/` | `feature/member1-encryption` |
| **Member 2** | Forensic Watermarking | `watermark/` | `feature/member2-watermark` |
| **Member 3** | Post-Quantum Crypto & Identity | `pqcrypto/` | `feature/member3-pqcrypto` |
| **Member 4** | Offline Permissioned Ledger | `ledger/` | `feature/member4-ledger` |
| **Member 5** | Integration, Forensics & UI | `integration/` | `feature/member5-integration` |
| **Shared** | Schemas, Models & Constants | `shared/` | *Requires consensus across all 5 members* |

---

## 2. Git Branching Strategy

```text
main (Protected — Production releases only)
│
├── develop (Integration branch — All PRs target develop)
│
├── feature/member1-encryption
├── feature/member2-watermark
├── feature/member3-pqcrypto
├── feature/member4-ledger
└── feature/member5-integration
```

### Core Branching Rules
1. **Never commit directly to `main` or `develop`**.
2. All daily work occurs on your assigned `feature/memberX-*` branch.
3. Keep your branch synchronized with `develop` by rebasing or merging regularly:
   ```bash
   git checkout develop
   git pull origin develop
   git checkout feature/memberX-domain
   git merge develop
   ```
4. Merge into `develop` only through a reviewed and approved **Pull Request (PR)**.
5. Final release merges from `develop` into `main` require unanimous sign-off and passing e2e tests.

---

## 3. Strict Development Rules

1. **One Feature Branch per Member**: Stay in your assigned branch.
2. **One Pull Request per Feature**: Break work into discrete, reviewable PRs.
3. **No Direct Commits to Main**: Branch protection is strictly enforced.
4. **Write Tests Before Merging**: Every PR must include unit tests in your module's `tests/` directory. All tests must pass:
   ```bash
   cargo test --workspace
   ```
5. **Preserve Event Schema Compatibility**: Never alter or invent field names. The schema in [`shared/schemas/decryption_event.json`](shared/schemas/decryption_event.json) is immutable.
6. **Follow Fluent UI Design Guidelines**: Any frontend work must follow [`docs/ui-ux-design-system.md`](docs/ui-ux-design-system.md) with native Dark and Light mode support.

---

## 4. Semantic Commit Message Convention

Commits must follow the Conventional Commits format: `<type>(<scope>): <description>`.

### Allowed Types
* `feat`: A new feature or capability
* `fix`: A bug fix or patch
* `docs`: Documentation updates
* `test`: Adding or refactoring tests
* `refactor`: Code restructuring without behavioral changes
* `chore`: Build scripts, dependencies, or toolchain changes

### Scope
Use your module name as the scope: `encryption`, `watermark`, `pqcrypto`, `ledger`, `integration`, `shared`, or `api`.

### Examples
```text
feat(encryption): add AES package structure and KEM envelope serializer

feat(watermark): create watermark payload generator with spread spectrum

fix(ledger): correct event lookup index for reverse hash query

docs(api): update event schema with canonical RFC 8785 notes

test(pqcrypto): add ML-DSA signature verification roundtrip tests

style(integration): refine Fluent UI acrylic panel blur and dark tokens
```

---

## 5. Pull Request Checklist

Before submitting a PR targeting `develop`:

- [ ] My code lives strictly within my owned directory (or shared with consensus).
- [ ] New methods conform to the traits defined in `docs/api-contract.md`.
- [ ] Schema fields strictly match `shared/schemas/decryption_event.json`.
- [ ] Unit tests are written and passing (`cargo test -p <my-crate>`).
- [ ] No hardcoded cryptographic keys, passwords, or secrets are checked in.
- [ ] Commit history is clean with semantic messages.
