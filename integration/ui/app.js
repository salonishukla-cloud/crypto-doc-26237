// ═══════════════════════════════════════════════════════════════════
//  Cryptographic Attribution Platform — UI Controller
//  Connects to Mock REST API on port 8081 with graceful mock fallback
// ═══════════════════════════════════════════════════════════════════

const API_BASE = 'http://localhost:8081';
let apiOnline = false;
let ledgerBlocks = [];
let senderFile = null;
let forensicsFile = null;

// ── Utility: Random hex ─────────────────────────────────────────────
const randHex = n => [...Array(n)].map(() => Math.floor(Math.random()*16).toString(16)).join('');
const randId  = () => randHex(16);
const nowISO  = () => new Date().toISOString().replace(/\.\d+Z/, 'Z');
const sleep   = ms => new Promise(r => setTimeout(r, ms));

// ── API Fetch Wrapper ───────────────────────────────────────────────
async function apiFetch(path, opts = {}) {
  const resp = await fetch(API_BASE + path, {
    ...opts,
    headers: { 'Content-Type': 'application/json', ...(opts.headers||{}) },
  });
  if (!resp.ok) throw new Error(`HTTP ${resp.status}`);
  return resp.json();
}

// ── API Health Check ────────────────────────────────────────────────
async function checkApiHealth() {
  const pill = document.getElementById('api-status-pill');
  const txt  = document.getElementById('api-status-text');
  try {
    const data = await apiFetch('/api/health');
    apiOnline = true;
    pill.className = 'api-status-pill online';
    txt.textContent = `API Online · ${data.nodes || 4} Nodes · Block #${data.chain_height ?? '–'}`;
  } catch {
    apiOnline = false;
    pill.className = 'api-status-pill offline';
    txt.textContent = 'API Offline — Mock Mode Active';
  }
}

// ── Theme Toggle ────────────────────────────────────────────────────
function toggleTheme() {
  const html = document.documentElement;
  const isDark = html.getAttribute('data-theme') === 'dark';
  html.setAttribute('data-theme', isDark ? 'light' : 'dark');
  document.getElementById('theme-icon').textContent  = isDark ? '🌙' : '☀️';
  document.getElementById('theme-label').textContent = isDark ? 'Dark Mode' : 'Light Mode';
  localStorage.setItem('theme', isDark ? 'light' : 'dark');
}

// ── Sidebar Navigation ──────────────────────────────────────────────
function initNav() {
  document.querySelectorAll('.nav-item').forEach(btn => {
    btn.addEventListener('click', () => {
      const target = btn.dataset.section;
      document.querySelectorAll('.nav-item').forEach(b => b.classList.remove('active'));
      document.querySelectorAll('.content-section').forEach(s => s.classList.remove('active'));
      btn.classList.add('active');
      document.getElementById('section-' + target)?.classList.add('active');
      if (target === 'ledger') refreshLedger();
    });
  });
}

// ── Toast Notifications ─────────────────────────────────────────────
function toast(message, type = 'info') {
  const icons = { success: '✅', error: '❌', info: 'ℹ️', warn: '⚠️' };
  const container = document.getElementById('toast-container');
  const el = document.createElement('div');
  el.className = `toast ${type}`;
  el.innerHTML = `<span>${icons[type] || 'ℹ️'}</span><span>${message}</span>`;
  container.appendChild(el);
  setTimeout(() => {
    el.style.opacity = '0';
    el.style.transform = 'translateX(20px)';
    el.style.transition = 'all 0.3s';
    setTimeout(() => el.remove(), 300);
  }, 3500);
}

// ── Copy Content ────────────────────────────────────────────────────
function copyContent(elementId) {
  const el = document.getElementById(elementId);
  if (!el) return;
  navigator.clipboard.writeText(el.textContent).then(() => toast('Copied to clipboard!', 'success'));
}

// ── Reset Section ───────────────────────────────────────────────────
function resetSection(section) {
  if (section === 'sender') {
    document.getElementById('sender-output').classList.add('hidden');
    senderFile = null;
    const dz = document.getElementById('sender-drop-zone');
    dz.classList.remove('has-file');
    document.getElementById('sender-file-info').style.display = 'none';
    document.getElementById('sender-pdf-input').value = '';
  } else if (section === 'recipient') {
    document.getElementById('recipient-output').classList.add('hidden');
  } else if (section === 'forensics') {
    document.getElementById('forensics-output').classList.add('hidden');
    forensicsFile = null;
    const dz = document.getElementById('forensics-drop-zone');
    dz.classList.remove('has-file');
    document.getElementById('forensics-file-info').style.display = 'none';
    document.getElementById('forensics-pdf-input').value = '';
  }
}

// ── File Handlers ───────────────────────────────────────────────────
function handleSenderFile(input) {
  const file = input.files[0];
  if (!file) return;
  senderFile = file;
  const dz   = document.getElementById('sender-drop-zone');
  const info = document.getElementById('sender-file-info');
  dz.classList.add('has-file');
  dz.querySelector('.drop-zone-icon').textContent = '📄';
  dz.querySelector('.drop-zone-label').textContent = file.name;
  dz.querySelector('.drop-zone-sub').textContent   = `${(file.size/1024).toFixed(1)} KB · Click to change`;
  info.style.display = 'flex';
  info.innerHTML = `<span>📎</span><strong>${file.name}</strong> (${(file.size/1024).toFixed(1)} KB)`;
}

function handleForensicsFile(input) {
  const file = input.files[0];
  if (!file) return;
  forensicsFile = file;
  const dz   = document.getElementById('forensics-drop-zone');
  const info = document.getElementById('forensics-file-info');
  dz.classList.add('has-file');
  dz.querySelector('.drop-zone-icon').textContent = '🔍';
  dz.querySelector('.drop-zone-label').textContent = file.name;
  dz.querySelector('.drop-zone-sub').textContent   = `${(file.size/1024).toFixed(1)} KB · Uploaded — ready for forensic analysis`;
  info.style.display = 'flex';
  info.innerHTML = `<span>📁</span><strong>${file.name}</strong> ready for forensic analysis`;
}

// Drag-and-drop on drop zones
function initDropZones() {
  ['sender-drop-zone', 'forensics-drop-zone'].forEach(id => {
    const zone = document.getElementById(id);
    if (!zone) return;
    zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('drag-over'); });
    zone.addEventListener('dragleave', () => zone.classList.remove('drag-over'));
    zone.addEventListener('drop', e => {
      e.preventDefault();
      zone.classList.remove('drag-over');
      const file = e.dataTransfer.files[0];
      if (!file) return;
      const inputId = id === 'sender-drop-zone' ? 'sender-pdf-input' : 'forensics-pdf-input';
      const input = document.getElementById(inputId);
      const dt = new DataTransfer();
      dt.items.add(file);
      input.files = dt.files;
      input.dispatchEvent(new Event('change'));
    });
  });
}

// ── Mock data generators ────────────────────────────────────────────
function mockEncryptPackage(docId, recipients) {
  return {
    status: 'success',
    package: {
      magic: 'CRPTDOC1',
      version: '1.0.0',
      document_id: docId,
      created_at: nowISO(),
      cipher: 'AES-256-GCM',
      kem: 'ML-KEM-768',
      nonce_hex: randHex(24),
      auth_tag_hex: randHex(32),
      payload_sha256: randHex(64),
      payload_bytes: Math.floor(Math.random()*400000)+50000,
      recipient_envelopes: recipients.map(r => ({
        recipient_id: r.trim(),
        kem_ciphertext_bytes: 1088,
        kem_ciphertext_preview: randHex(16) + '…[1088 bytes ML-KEM-768]',
        encrypted_dek_tag: randHex(16),
      })),
      envelope_count: recipients.length,
    }
  };
}

function mockDecrypt(recipientId, sessionId, docId) {
  const eventId   = 'evt-' + randId();
  const wmId      = 'wm-' + randHex(8);
  const wmHash    = randHex(64);
  const blockH    = ledgerBlocks.length;
  const blockHash = randHex(64);
  ledgerBlocks.push({
    height: blockH,
    block_hash: blockHash,
    prev_hash: ledgerBlocks.length ? ledgerBlocks[blockH-1].block_hash : '0'.repeat(64),
    merkle_root: randHex(64),
    validator: `node-${Math.ceil(Math.random()*4)}`,
    timestamp: nowISO(),
    tx_count: 1,
    event_id: eventId,
  });
  return {
    status: 'success',
    pipeline: {
      step_1_decryption: { status: 'OK', module: 'Module 1 — ML-KEM-768 Decapsulation + AES-256-GCM Decryption' },
      step_2_watermark:  { status: 'OK', module: 'Module 2 — 142-bit Invisible Multi-Layer Watermark Embedded' },
      step_3_signing:    { status: 'OK', module: 'Module 3 — Canonical RFC 8785 JSON + ML-DSA-65 FIPS 204 Signature' },
      step_4_ledger:     { status: 'OK', module: `Module 4 — Committed on 4-Node Ledger at Block #${blockH}` },
    },
    event: {
      event_id: eventId,
      document_id: docId,
      recipient_id: recipientId,
      session_id: sessionId,
      watermark_id: wmId,
      timestamp: nowISO(),
      watermark_hash: wmHash,
      signature_algorithm: 'ML-DSA-65',
      public_key_fingerprint: randHex(64),
      signature: randHex(16) + '…[3309 bytes FIPS 204 ML-DSA-65]',
    },
    ledger_receipt: {
      event_id: eventId,
      block_height: blockH,
      block_hash: blockHash,
      merkle_proof: [randHex(64), randHex(64)],
      validator: `node-${Math.ceil(Math.random()*4)}`,
      committed_at: nowISO(),
    }
  };
}

function mockForensics(source, docId) {
  const now = nowISO();
  if (source === 'valid') {
    return {
      status: 'success', verdict: 'CONFIRMED_ATTRIBUTION', confidence: 100.0,
      attribution: { recipient_id: 'officer.shukla@hq.defence.gov', session_id: 'SESS-AIRGAP-8891', document_id: docId },
      watermark: { extracted: true, watermark_id: 'wm-shukla-' + randHex(6), watermark_hash: randHex(64),
        ledger_match: true, channels: ['ZeroWidthUnicode','HomoglyphSubstitution','XMP','SpectrumSteganography'] },
      signature: { algorithm: 'ML-DSA-65', valid: true, public_key_fingerprint: randHex(64), non_repudiation: 'AFFIRMED' },
      ledger: { found: true, block_height: Math.max(0, ledgerBlocks.length-1),
        block_hash: ledgerBlocks.length ? ledgerBlocks[ledgerBlocks.length-1].block_hash : randHex(64),
        merkle_valid: true, chain_valid: true },
      generated_at: now,
    };
  } else if (source === 'tampered') {
    return {
      status: 'success', verdict: 'TAMPERING_DETECTED', confidence: 0.0,
      watermark: { extracted: true, ledger_match: false },
      signature: { valid: false, non_repudiation: 'FAILED' },
      ledger: { found: false }, generated_at: now,
    };
  } else {
    return {
      status: 'success', verdict: 'UNATTRIBUTED', confidence: 0.0,
      watermark: { extracted: false }, signature: { valid: false },
      ledger: { found: false }, generated_at: now,
    };
  }
}

// ── ENCRYPT ─────────────────────────────────────────────────────────
async function runEncrypt() {
  const btn = document.getElementById('btn-encrypt');
  const docId      = document.getElementById('sender-doc-id').value.trim() || 'DOC-UNKNOWN';
  const rawRecips  = document.getElementById('sender-recipients').value;
  const recipients = rawRecips.split(',').map(s => s.trim()).filter(Boolean);

  if (recipients.length === 0) { toast('Add at least one recipient', 'warn'); return; }

  btn.innerHTML = '<span class="spinner"></span> Encrypting…';
  btn.disabled = true;

  try {
    let data;
    if (apiOnline) {
      data = await apiFetch('/api/encrypt', { method: 'POST',
        body: JSON.stringify({ document_id: docId, recipients,
          filename: senderFile?.name, size: senderFile?.size }) });
    } else {
      await sleep(900);
      data = mockEncryptPackage(docId, recipients);
    }

    document.getElementById('sender-manifest-json').textContent = JSON.stringify(data.package, null, 2);
    document.getElementById('sender-output').classList.remove('hidden');
    toast('Document encrypted successfully!', 'success');
  } catch (e) {
    toast('Encryption failed: ' + e.message, 'error');
  } finally {
    btn.innerHTML = '<span>🔐</span> Encrypt Document Package';
    btn.disabled = false;
  }
}

// ── DECRYPT ─────────────────────────────────────────────────────────
async function runDecrypt() {
  const btn = document.getElementById('btn-decrypt');
  const recipientId = document.getElementById('recipient-select').value;
  const sessionId   = document.getElementById('recipient-session').value.trim() || 'SESS-DEFAULT';
  const docId       = document.getElementById('recipient-doc-id').value.trim() || 'DOC-UNKNOWN';

  btn.innerHTML = '<span class="spinner"></span> Executing Pipeline…';
  btn.disabled = true;

  const output   = document.getElementById('recipient-output');
  const pipeline = document.getElementById('recipient-pipeline');
  output.classList.remove('hidden');

  const steps = [
    { icon: '🔑', label: 'Module 1 — ML-KEM-768 Decapsulation & AES-256-GCM Decryption' },
    { icon: '💧', label: 'Module 2 — 142-bit Invisible Forensic Watermark Embedding' },
    { icon: '✍️', label: 'Module 3 — Canonical RFC 8785 JSON + ML-DSA-65 Signature' },
    { icon: '⛓️', label: 'Module 4 — Signed Event Committed to 4-Node DLT Ledger' },
  ];

  pipeline.innerHTML = steps.map((s, i) =>
    `<div class="pipeline-step pending" id="ps-${i}">
      <span class="pipeline-icon">${s.icon}</span>
      <span class="pipeline-label">${s.label}</span>
      <span class="pipeline-time">pending</span>
    </div>`
  ).join('');

  try {
    // Animate each step
    for (let i = 0; i < steps.length; i++) {
      const el = document.getElementById(`ps-${i}`);
      el.className = 'pipeline-step running';
      el.querySelector('.pipeline-time').textContent = 'running…';
      await sleep(apiOnline ? 200 : 500);
    }

    let data;
    if (apiOnline) {
      data = await apiFetch('/api/decrypt', { method: 'POST',
        body: JSON.stringify({ recipient_id: recipientId, session_id: sessionId, document_id: docId }) });
    } else {
      data = mockDecrypt(recipientId, sessionId, docId);
    }

    // Mark all done
    const times = ['12ms', '38ms', '91ms', '7ms'];
    for (let i = 0; i < steps.length; i++) {
      const el = document.getElementById(`ps-${i}`);
      el.className = 'pipeline-step done';
      el.querySelector('.pipeline-icon').textContent = '✓';
      el.querySelector('.pipeline-time').textContent = times[i];
    }

    document.getElementById('recipient-event-json').textContent   = JSON.stringify(data.event, null, 2);
    document.getElementById('recipient-receipt-json').textContent = JSON.stringify(data.ledger_receipt, null, 2);
    toast('Decryption & provenance pipeline complete!', 'success');
  } catch (e) {
    toast('Pipeline error: ' + e.message, 'error');
    document.querySelectorAll('.pipeline-step.running').forEach(el => {
      el.className = 'pipeline-step fail';
      el.querySelector('.pipeline-time').textContent = 'failed';
    });
  } finally {
    btn.innerHTML = '<span>⚡</span> Execute Full Decryption & Provenance';
    btn.disabled = false;
  }
}

// ── FORENSICS ────────────────────────────────────────────────────────
async function runForensics() {
  const btn    = document.getElementById('btn-forensics');
  const source = document.querySelector('input[name="leak-source"]:checked')?.value || 'valid';
  const docId  = 'DOC-DEFENCE-QUANTUM-2026';

  btn.innerHTML = '<span class="spinner"></span> Analyzing…';
  btn.disabled = true;

  try {
    let data;
    if (apiOnline) {
      const payload = { source, document_id: docId,
        filename: forensicsFile?.name, size: forensicsFile?.size };
      data = await apiFetch('/api/forensics', { method: 'POST', body: JSON.stringify(payload) });
    } else {
      await sleep(1100);
      data = mockForensics(source, docId);
    }

    renderForensicsResult(data);
    toast('Forensic analysis complete!', source === 'valid' ? 'success' : 'warn');
  } catch (e) {
    toast('Forensic error: ' + e.message, 'error');
  } finally {
    btn.innerHTML = '<span>🔍</span> Run Forensic Verification & Attribution';
    btn.disabled = false;
  }
}

function renderForensicsResult(data) {
  const output  = document.getElementById('forensics-output');
  const banner  = document.getElementById('verdict-banner');
  const title   = document.getElementById('verdict-title');
  const sub     = document.getElementById('verdict-sub');
  const report  = document.getElementById('forensic-report-pre');
  const now     = data.generated_at || nowISO();

  output.classList.remove('hidden');

  if (data.verdict === 'CONFIRMED_ATTRIBUTION') {
    banner.className = 'verdict-banner';
    title.textContent = '✅ CONFIRMED ATTRIBUTION — LEGAL PROOF VERIFIED';
    sub.textContent   = `Conclusively attributed to ${data.attribution?.recipient_id} via ML-DSA signature and 4-node Merkle proof.`;
    report.textContent = buildDossier('CONFIRMED ATTRIBUTION (PROVEN BEYOND REASONABLE DOUBT)', data, now);
  } else if (data.verdict === 'TAMPERING_DETECTED') {
    banner.className = 'verdict-banner tampered';
    title.textContent = '⚠️ SUSPICIOUS — TAMPERING DETECTED';
    sub.textContent   = 'Watermark detected but cryptographic signature or DLT hash verification failed.';
    report.textContent = buildDossier('SUSPICIOUS / TAMPERING DETECTED (INTEGRITY FAILED)', data, now);
  } else {
    banner.className = 'verdict-banner unattributed';
    title.textContent = '❓ UNATTRIBUTED — NO FORENSIC RECORD';
    sub.textContent   = 'No watermark signals or cryptographic provenance tokens detected in this document.';
    report.textContent = buildDossier('UNATTRIBUTED (NO MATCHING FORENSIC RECORD)', data, now);
  }
}

function buildDossier(status, data, now) {
  const sep = '═'.repeat(72);
  const line = '─'.repeat(72);
  const wm = data.watermark || {};
  const sig = data.signature || {};
  const ldr = data.ledger || {};
  const attr = data.attribution || {};
  return `${sep}
        OFFLINE FORENSIC ATTRIBUTION DOSSIER
   Cryptographic Attribution & Immutable Decryption Provenance Platform
${sep}
Generated At      : ${now}
Attribution Status: ${status}
${line}

1. EXECUTIVE SUMMARY
   Document ID         : ${attr.document_id || data.document_id || '—'}
   Attributed Recipient: ${attr.recipient_id || 'UNKNOWN'}
   Session ID          : ${attr.session_id || 'UNKNOWN'}
   Confidence Level    : ${(data.confidence ?? 0).toFixed(2)}%

2. FORENSIC WATERMARK EXTRACTION (MODULE 2)
   Watermark Extracted : ${wm.extracted ? 'YES ✓' : 'NO ✗'}
   Watermark ID        : ${wm.watermark_id || '—'}
   Extracted Hash      : ${wm.watermark_hash || '—'}
   Ledger Hash Match   : ${wm.ledger_match ? 'YES — EXACT MATCH ✓' : 'NO — MISMATCH ✗'}
   Detection Channels  : ${(wm.channels || []).join(', ') || '—'}

3. POST-QUANTUM CRYPTOGRAPHIC AUDIT (ML-DSA-65 / FIPS 204)
   Signature Algorithm : ${sig.algorithm || 'ML-DSA-65'}
   Signature Valid     : ${sig.valid ? 'VALID — UNFORGEABLE ✓' : 'INVALID ✗'}
   Public Key Fingerpr.: ${sig.public_key_fingerprint || '—'}
   Non-Repudiation     : ${sig.non_repudiation || 'UNVERIFIED'}

4. DISTRIBUTED LEDGER AUDIT (4-NODE PERMISSIONED DLT)
   Ledger Record Found : ${ldr.found ? 'YES — INDEXED ON ALL 4 NODES ✓' : 'NOT FOUND ✗'}
   Committed Block     : ${ldr.found ? '#' + ldr.block_height : '—'}
   Block Hash          : ${ldr.block_hash || '—'}
   Merkle Inclusion    : ${ldr.merkle_valid ? 'VERIFIED ✓' : 'UNVERIFIED ✗'}
   Chain Continuity    : ${ldr.chain_valid ? 'VERIFIED ✓' : 'UNVERIFIED ✗'}

5. VERDICT CONCLUSION
${data.verdict === 'CONFIRMED_ATTRIBUTION'
  ? `   Based on multi-layer forensic watermarking, FIPS 204 ML-DSA-65 digital
   signatures, and immutable 4-node offline DLT Merkle proof, unauthorized
   dissemination is CONCLUSIVELY ATTRIBUTED to:
   >> ${attr.recipient_id} <<`
  : data.verdict === 'TAMPERING_DETECTED'
  ? '   Attribution cannot be established. Cryptographic signature or DLT\n   hash verification failed — document integrity compromised.'
  : '   No forensic watermark, cryptographic signature, or DLT record found.\n   Document origin is outside this platform\'s distribution chain.'}

${sep}`;
}

// ── LEDGER ────────────────────────────────────────────────────────────
async function refreshLedger() {
  try {
    let blocks, nodes;
    if (apiOnline) {
      [{ blocks }, { nodes }] = await Promise.all([
        apiFetch('/api/ledger/blocks'),
        apiFetch('/api/nodes/status'),
      ]);
      ledgerBlocks = blocks;
    } else {
      nodes = [
        { id:1, role:'Key Custody & Validator', height: ledgerBlocks.length > 0 ? ledgerBlocks.length-1 : 2, online:true },
        { id:2, role:'Verification Enclave',    height: ledgerBlocks.length > 0 ? ledgerBlocks.length-1 : 2, online:true },
        { id:3, role:'Attribution Analysis',    height: ledgerBlocks.length > 0 ? ledgerBlocks.length-1 : 2, online:true },
        { id:4, role:'Offline Audit Store',     height: ledgerBlocks.length > 0 ? ledgerBlocks.length-1 : 2, online:true },
      ];
      if (ledgerBlocks.length === 0) {
        ledgerBlocks = [
          { height:0, block_hash: '00a89f'+randHex(58)+'88b2', prev_hash: '0'.repeat(64),
            merkle_root: randHex(64), validator:'network-genesis', timestamp:'2026-01-01T00:00:00Z', tx_count:1 },
          { height:1, block_hash: randHex(64), prev_hash: '00a89f'+randHex(58)+'88b2',
            merkle_root: randHex(64), validator:'node-1', timestamp:'2026-09-01T08:15:22Z', tx_count:3 },
          { height:2, block_hash: randHex(64), prev_hash: randHex(64),
            merkle_root: randHex(64), validator:'node-3', timestamp:'2026-09-28T22:41:05Z', tx_count:1 },
        ];
      }
    }

    // Render node cards
    nodes.forEach(n => {
      const h = document.getElementById(`n${n.id}-height`);
      const s = document.getElementById(`n${n.id}-status`);
      if (h) h.textContent = '#' + (n.height ?? '–');
      if (s) { s.textContent = n.online ? 'Online ●' : 'Offline ✗'; s.style.color = n.online ? 'var(--primary)' : 'var(--danger)'; }
    });

    // Render blocks table
    const tbody = document.getElementById('ledger-tbody');
    tbody.innerHTML = [...ledgerBlocks].reverse().map(b => `
      <tr>
        <td>${b.height === 0
          ? '<span class="badge badge-amber">#0 Genesis</span>'
          : `<span class="badge badge-neutral">#${b.height}</span>`}
        </td>
        <td><code>${b.block_hash.slice(0,10)}…${b.block_hash.slice(-6)}</code></td>
        <td><code>${b.prev_hash.slice(0,10)}…${b.prev_hash.slice(-6)}</code></td>
        <td><code>${b.merkle_root.slice(0,10)}…${b.merkle_root.slice(-6)}</code></td>
        <td>${b.validator}</td>
        <td>${b.timestamp}</td>
        <td style="text-align:center;font-family:var(--font-mono);color:var(--primary)">${b.tx_count ?? 1}</td>
      </tr>`).join('');
  } catch (e) {
    console.error('Ledger refresh error:', e);
  }
}

// ── Startup ───────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  // Restore theme
  const savedTheme = localStorage.getItem('theme') || 'dark';
  document.documentElement.setAttribute('data-theme', savedTheme);
  document.getElementById('theme-icon').textContent  = savedTheme === 'dark' ? '☀️' : '🌙';
  document.getElementById('theme-label').textContent = savedTheme === 'dark' ? 'Light Mode' : 'Dark Mode';

  initNav();
  initDropZones();
  await checkApiHealth();
  await refreshLedger();

  // Recheck API health every 15 seconds
  setInterval(checkApiHealth, 15000);
});
