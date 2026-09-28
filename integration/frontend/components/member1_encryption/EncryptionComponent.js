/**
 * Member 1: Encryption & Document Packaging Component
 * Owns:
 * - Confidential PDF upload & AES-256-GCM encryption trigger
 * - ML-KEM recipient key encapsulation list
 * - EncryptedDocumentPackage preview & download
 */

export class EncryptionComponent {
  constructor(containerId) {
    this.container = document.getElementById(containerId);
  }

  render() {
    if (!this.container) return;
    this.container.innerHTML = `
      <div class="fluent-card">
        <div class="card-header">
          <div>
            <h3 class="card-title">AES-256-GCM & ML-KEM Packaging</h3>
            <p style="font-size: var(--font-size-xs); color: var(--text-tertiary);">Owner: Member 1 (Encryption)</p>
          </div>
          <span class="badge badge-crypto">ML-KEM-768</span>
        </div>
        <div class="card-body">
          <div style="display: flex; flex-direction: column; gap: 12px;">
            <label style="font-size: var(--font-size-sm); font-weight: 500;">Confidential PDF Source</label>
            <input type="file" accept=".pdf" class="fluent-input" id="encryption-file-input" style="padding: 8px; border: 1px dashed var(--border-default); border-radius: var(--radius-sm); background: var(--bg-surface-secondary); color: var(--text-primary);" />
            
            <div style="display: flex; gap: 8px; margin-top: 8px;">
              <button class="btn btn-primary" id="btn-encrypt-package">🔒 Package & Encrypt</button>
              <button class="btn btn-secondary" id="btn-inspect-dek">Inspect DEK Envelopes</button>
            </div>
          </div>
        </div>
      </div>
    `;
  }
}
