# Typography

## Font Families

| Usage | Font | Weights | Fallback |
|-------|------|---------|----------|
| Titles / Logo | Space Grotesk | 400, 600, 700 | sans-serif |
| Code / CLI | JetBrains Mono | 400, 600 | monospace |
| Body / UI | Inter | 400, 500, 600 | sans-serif |

## Loading

```html
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@400;600;700&family=JetBrains+Mono:wght@400;600&family=Inter:wght@400;500;600&display=swap" rel="stylesheet">
```

## Type Scale

| Element | Size | Weight | Line Height | Letter Spacing |
|---------|------|--------|-------------|----------------|
| H1 (Hero) | 56px | 700 | 1.1 | -1px |
| H2 (Section) | 32px | 600 | 1.2 | -0.5px |
| H3 (Card Title) | 20px | 600 | 1.3 | 0 |
| Body | 14px | 400 | 1.6 | 0 |
| Small | 12px | 400 | 1.5 | 0 |
| Code | 13px | 400 | 1.5 | 0 |
| Mono Label | 11px | 600 | 1.4 | 1px |

## Usage Rules

### CLI Output

- All CLI text uses JetBrains Mono
- Risk scores: bold, colored
- Package names: cyan
- Version numbers: secondary color

### Web UI

- Logo: Space Grotesk 700
- Page titles: Space Grotesk 600
- Body text: Inter 400
- Code blocks: JetBrains Mono 400
- Stats/numbers: JetBrains Mono 600

### Accessibility

- Minimum body text: 14px
- Minimum contrast: 7:1
- Line length max: 75ch
- Line height min: 1.5

## Examples

```css
/* Title */
.title {
  font-family: 'Space Grotesk', sans-serif;
  font-size: 56px;
  font-weight: 700;
  line-height: 1.1;
  letter-spacing: -1px;
}

/* Code block */
.code {
  font-family: 'JetBrains Mono', monospace;
  font-size: 13px;
  line-height: 1.5;
}

/* Body text */
.body {
  font-family: 'Inter', sans-serif;
  font-size: 14px;
  line-height: 1.6;
}
```
