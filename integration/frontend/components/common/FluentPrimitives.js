/**
 * Fluent UI Base Primitives & Shared Component Helpers
 * Adheres strictly to central theme tokens in styles/theme.css
 */

export class FluentCard {
  static create({ title, subtitle, statusText = 'Ready', statusType = 'success', contentHtml = '' }) {
    const card = document.createElement('article');
    card.className = 'fluent-card';
    card.innerHTML = `
      <div class="card-header">
        <div>
          <h3 class="card-title">${title}</h3>
          ${subtitle ? `<p style="font-size: var(--font-size-xs); color: var(--text-tertiary);">${subtitle}</p>` : ''}
        </div>
        <span class="badge badge-${statusType}">
          <span class="badge-dot"></span> ${statusText}
        </span>
      </div>
      <div class="card-body">
        ${contentHtml}
      </div>
    `;
    return card;
  }
}

export class FluentButton {
  static create({ label, icon = '', variant = 'primary', onClick }) {
    const btn = document.createElement('button');
    btn.className = `btn btn-${variant}`;
    btn.innerHTML = `${icon ? `<span>${icon}</span>` : ''} ${label}`;
    if (onClick) btn.addEventListener('click', onClick);
    return btn;
  }
}

export class CryptoBadge {
  static create(label, type = 'crypto') {
    const badge = document.createElement('span');
    badge.className = `badge badge-${type}`;
    badge.textContent = label;
    return badge;
  }
}
