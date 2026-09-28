# Member 5 — Integration & Verification Workstation Module

## Ownership Scope

* **Owner**: Member 5 (Systems Integrator, UI/UX Lead, & Forensic Workstation Architect)
* **Assigned Git Branch**: `feature/member5-integration`
* **Core Responsibilities**:
  * End-to-end decryption workflow orchestration across Members 1, 2, 3, and 4.
  * Forensic attribution workstation engine for leaked document analysis.
  * Forensic Evidence Report generator (cryptographic provenance audit trail).
  * Air-gapped UI workstation implementation built with **Microsoft Fluent UI** design system, **Nexa** typography, and native dark/light modes.
  * Final milestone demonstration and test harnesses.

## Implemented API Contract

Every implementation of Member 5 must fulfill the trait defined in [`src/lib.rs`](src/lib.rs):

```rust
pub trait ForensicOrchestrator {
    fn run_decryption_workflow(&self, request: DecryptionWorkflowRequest) -> Result<DecryptionWorkflowResult, IntegrationError>;
    fn verify_leaked_document(&self, leaked_document_bytes: &[u8]) -> Result<ForensicEvidenceReport, IntegrationError>;
    fn generate_report(&self, report: &ForensicEvidenceReport) -> Result<String, IntegrationError>;
}
```

## Directory Structure

```text
integration/
├── Cargo.toml
├── README.md
├── src/
│   └── lib.rs             # Primary ForensicOrchestrator trait stubs
├── backend/
│   ├── mod.rs             # Backend orchestrator exports
│   └── orchestrator.rs    # Decryption workflow types and errors
├── verification/
│   ├── mod.rs             # Verification exports
│   └── forensics.rs       # ForensicEvidenceReport data model
└── frontend/
    ├── index.html         # Fluent UI Secure Workstation Shell
    ├── styles/
    │   ├── theme.css      # Central Fluent design tokens, light/dark themes, Nexa typography
    │   └── components.css # Fluent acrylic cards, buttons, badges, tables
    └── scripts/
        └── theme.js       # Dark/light mode switcher and state controller
```

## Frontend Design Standards

All UI components across the repository must adhere to the design rules in [`docs/ui-ux-design-system.md`](../docs/ui-ux-design-system.md):
1. **Design Language**: Microsoft Fluent UI 2.0 (acrylic surfaces, mica backdrop blur, elevation shadows, rounded corners).
2. **Typography**: Nexa font stack with modern sans-serif fallbacks.
3. **Themes**: Seamless Light and Dark mode switching using semantic CSS variables (`var(--bg-canvas)`, `var(--accent-default)`).
4. **Motion**: Fluid micro-animations with `cubic-bezier(0.1, 0.9, 0.2, 1.0)` timing curves (150ms-250ms).

## Git Workflow for Member 5

1. Checkout assigned feature branch:
   ```bash
   git checkout feature/member5-integration
   ```
2. Integrate domain crates, build UI layouts, and author forensic reporting tools.
3. Commit with semantic messages:
   ```bash
   git commit -m "feat(integration): build Fluent UI workstation shell and theme tokens"
   ```
4. Submit Pull Request targeting `develop`.
