# Color Palette

## Primary Colors

| Token | Hex | RGBA | Usage |
|-------|-----|------|-------|
| `--bg-primary` | `#0A0A0F` | `rgb(10, 10, 15)` | Main background |
| `--bg-secondary` | `#12121F` | `rgb(18, 18, 31)` | Panels, cards |
| `--bg-tertiary` | `#1A1A2E` | `rgb(26, 26, 46)` | Interactive elements |
| `--bg-hover` | `#252540` | `rgb(37, 37, 64)` | Hover states |

## Accent Colors

| Token | Hex | RGBA | Usage |
|-------|-----|------|-------|
| `--accent-cyan` | `#05D9E8` | `rgb(5, 217, 232)` | OK, links, highlights |
| `--accent-pink` | `#FF2A6D` | `rgb(255, 42, 109)` | Critical, alerts |
| `--accent-yellow` | `#F7E018` | `rgb(247, 224, 24)` | Warning, attention |

## Glow Colors

| Token | Value | Usage |
|-------|-------|-------|
| `--glow-cyan` | `rgba(5, 217, 232, 0.3)` | Cyan glow effects |
| `--glow-pink` | `rgba(255, 42, 109, 0.3)` | Pink glow effects |
| `--glow-yellow` | `rgba(247, 224, 24, 0.3)` | Yellow glow effects |

## Text Colors

| Token | Hex | Usage |
|-------|-----|-------|
| `--text-primary` | `#E0E0E0` | Main text |
| `--text-secondary` | `#8A8AA3` | Secondary text, labels |
| `--text-muted` | `#5A5A73` | Disabled, hints |

## Border Colors

| Token | Hex | Usage |
|-------|-----|-------|
| `--border-default` | `#1A1A2E` | Default borders |
| `--border-hover` | `#05D9E8` | Hover borders |
| `--border-critical` | `#FF2A6D` | Critical borders |

## Usage Guidelines

### Contrast Ratios

- Primary text on bg-primary: 15.2:1 ✅
- Secondary text on bg-primary: 7.8:1 ✅
- Cyan on bg-primary: 11.4:1 ✅
- Pink on bg-primary: 7.2:1 ✅
- Yellow on bg-primary: 14.1:1 ✅

All ratios exceed WCAG AA standards.

### Gradient Usage

```css
.gradient-risk {
  background: linear-gradient(135deg, #05D9E8 0%, #FF2A6D 100%);
}

.gradient-dark {
  background: linear-gradient(180deg, #12121F 0%, #0A0A0F 100%);
}
```

### Glow Effects

```css
.glow-cyan {
  box-shadow: 0 0 20px rgba(5, 217, 232, 0.3),
              0 0 40px rgba(5, 217, 232, 0.1);
}

.glow-pink {
  box-shadow: 0 0 20px rgba(255, 42, 109, 0.3),
              0 0 40px rgba(255, 42, 109, 0.1);
}
```
