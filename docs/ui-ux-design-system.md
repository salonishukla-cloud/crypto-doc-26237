# UI/UX Design System & Central Aesthetic Guidelines

## 1. Design Philosophy: Fluent UI & High-Assurance Minimalism

The user interface for the Cryptographic Attribution & Provenance platform is designed to convey **absolute cryptographic trust, precision, and state-of-the-art elegance**.

All frontend views, forensic tools, and administrative panels across the repository must strictly follow these rules:

1. **Framework**: Microsoft Fluent UI 2.0 aesthetic (Acrylic materials, Mica depth, subtle borders, elevated shadows).
2. **Typography**: **Nexa** bold/book font family with clean modern sans-serif fallbacks (`-apple-system`, `BlinkMacSystemFont`, `Segoe UI Variable`, `Segoe UI`, `Roboto`).
3. **Aesthetic Direction**: Minimal, clean, distraction-free, smooth micro-interactions, zero clutter.
4. **Theme Support**: First-class **Dark Mode** and **Light Mode** as a neutral, mandatory rule for all systems and components.
5. **Motion**: Fluid, natural transitions using cubic-bezier easing (`cubic-bezier(0.1, 0.9, 0.2, 1.0)`).

---

## 2. Color Palette & Neutral Theme Tokens

All color references must be made via CSS custom properties defined in [`integration/frontend/styles/theme.css`](../integration/frontend/styles/theme.css). Never hardcode hex codes in component styles.

### 2.1 Canvas & Surface Tokens

| Token Name | Light Mode Value | Dark Mode Value | Usage |
| :--- | :--- | :--- | :--- |
| `--bg-canvas` | `#f3f3f3` | `#0f1115` | App root window / workspace background |
| `--bg-surface` | `#ffffff` | `#181b22` | Primary content panels, modal dialogs |
| `--bg-surface-secondary` | `#f9f9f9` | `#21252f` | Secondary containers, input backgrounds |
| `--bg-card` | `rgba(255, 255, 255, 0.85)` | `rgba(24, 27, 34, 0.85)` | Glassmorphic cards with elevation |
| `--bg-acrylic` | `rgba(255, 255, 255, 0.75)` | `rgba(24, 27, 34, 0.72)` | Navigation sidebar, blur backdrop filter |

### 2.2 Text & Border Tokens

| Token Name | Light Mode Value | Dark Mode Value | Usage |
| :--- | :--- | :--- | :--- |
| `--text-primary` | `#1a1a1a` | `#f5f6f8` | Headers, primary titles, critical labels |
| `--text-secondary` | `#5c5c5c` | `#9aa0a6` | Subtitles, body descriptions, hints |
| `--text-tertiary` | `#8a8a8a` | `#6b7280` | Timestamps, micro-captions, metadata |
| `--border-subtle` | `rgba(0, 0, 0, 0.06)` | `rgba(255, 255, 255, 0.06)` | Dividers, subtle container borders |
| `--border-default` | `rgba(0, 0, 0, 0.12)` | `rgba(255, 255, 255, 0.12)` | Input outlines, button strokes |

### 2.3 Cryptographic Security Accent & Status

| Token Name | Light Mode Value | Dark Mode Value | Usage |
| :--- | :--- | :--- | :--- |
| `--accent-default` | `#0066cc` | `#4cc2ff` | Primary action buttons, active navigation states |
| `--status-success` | `#107c10` | `#6ccb5f` | Cryptographic signature verified, valid DLT block |
| `--status-warning` | `#b7791f` | `#fce100` | Partial watermark match, warning notices |
| `--status-danger` | `#c42b1c` | `#ff99a4` | Signature forgery detected, chain broken, leak alert |

---

## 3. Typography Standards

```css
font-family: 'Nexa', -apple-system, BlinkMacSystemFont, 'Segoe UI Variable', 'Segoe UI', Roboto, sans-serif;
```

* **Display Headings (`h1`, `h2`)**: Nexa Bold, $-0.02\text{em}$ letter spacing, crisp contrast.
* **Body Text (`p`, `span`)**: Regular weight, $1.5$ line-height for effortless readability.
* **Cryptographic Hashes & IDs**: Fixed-width Cascadia Code / Fira Code monospace font (`var(--font-family-mono)`).

---

## 4. Motion, Elevation & Transitions

Fluent UI emphasizes realistic physics and responsiveness:

* **Transitions**: Every interactive element must transition background, borders, and transforms smoothly:
  ```css
  transition: all 150ms cubic-bezier(0.1, 0.9, 0.2, 1.0);
  ```
* **Cards & Panels**:
  * Default elevation: Subtle 1px boundary + soft ambient drop shadow.
  * Hover state: Elevates by `translateY(-2px)` with expanded shadow (`--shadow-flyout`).
* **Acrylic Blur**:
  * Backdrops use `backdrop-filter: blur(24px) saturate(180%)`.

---

## 5. Dark / Light Mode Neutral Standard

All system views must respect the user's manual selection stored in `localStorage` or fallback dynamically to their OS `prefers-color-scheme`.

The mode is switched by toggling the `data-theme` attribute on the root `<html>` element:
```html
<html lang="en" data-theme="dark">
<!-- or data-theme="light" -->
```

No hardcoded colors are permitted in inline styles or separate stylesheets.
