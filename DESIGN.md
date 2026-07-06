# LayerTrace EDR/SIEM Design System

## 1. Atmosphere & Identity

A security operations command center: dense, scan-first, and evidence-led. The signature is a three-layer egress map that separates endpoint activity, protected tenant boundary, and external destinations.

## 2. Color

| Role | Token | Dark | Usage |
|---|---|---|---|
| Background | --bg | #101215 | Page background |
| Shell | --shell | #15191f | Navigation shell |
| Panel | --panel | #1b2027 | Dashboard panels |
| Panel raised | --panel-2 | #202733 | Selected rows and inspector blocks |
| Border | --line | #323a46 | Structural borders |
| Border subtle | --line-soft | #272e38 | Row separators |
| Text primary | --text | #eef2f7 | Main labels |
| Text muted | --muted | #9aa8ba | Secondary labels |
| Text tertiary | --muted-2 | #748296 | Tertiary metadata |
| Critical | --red | #f2495c | RED EDR state, critical alerts |
| Warning | --amber | #ffb357 | YELLOW state, warnings |
| Success | --green | #73bf69 | GREEN state, not detected |
| Info | --blue | #5794f2 | Suspicious/info signal |
| Network | --cyan | #56d0e6 | Topology links and external destinations |

## 3. Typography

| Level | Size | Weight | Line Height | Tracking | Usage |
|---|---:|---:|---:|---:|---|
| Page title | 23px | 800 | 1.18 | 0 | Console title |
| Panel title | 14px | 800 | 1.3 | 0 | Panel headers |
| Body | 13px | 400 | 1.45 | 0 | Console text |
| Secondary | 12px | 400 | 1.45 | 0 | Metadata |
| Label | 11px | 800 | 1.3 | 0 | Eyebrows and chips |
| Mono | 12px | 400 | 1.45 | 0 | IDs, paths, times |

Primary font is Inter, Segoe UI, system-ui, sans-serif. Mono font is Cascadia Code, Consolas, SFMono-Regular, monospace.

## 4. Spacing & Layout

Base unit is 4px. Dashboard layout uses a 12-column grid with 12px gutters, 14px page padding, and compact 10-14px panel padding. Fixed-format controls keep stable heights: filters 32px, action buttons 31px, chips 23-28px.

## 5. Components

### Panel
- **Structure**: section with `.panel`, `.panel-heading`, and content region.
- **Variants**: span-4, span-5, span-7, span-8, span-12.
- **States**: normal, empty, selected child row.
- **Accessibility**: semantic section headings and readable contrast.

### Alert row
- **Structure**: clickable article with title, severity chip, metadata, evidence list.
- **States**: default, hover, selected, filtered empty.
- **Accessibility**: button cursor, focus-visible outline, inspector mirror for selected context.

### Egress topology
- **Structure**: first-viewport SVG graph with three lanes: Endpoint fleet, Protected tenant boundary, External destinations. Secondary details may use compact node cards below the graph.
- **Variants**: RED, YELLOW/alert, GREEN/not detected.
- **States**: alert, observed, not detected.
- **Accessibility**: text labels and state chips, no color-only encoding.

### Detection chart panel
- **Structure**: compact chart region with severity donut, event/alert volume bars, and MITRE/timeline distribution.
- **Variants**: first-viewport summary, detailed section chart.
- **States**: empty, filtered, active severity.
- **Accessibility**: visible numeric labels next to every chart; color is paired with text.

### Data source switcher
- **Structure**: sidebar status block showing current source plus the exact CLI commands that regenerate `dashboard/data/latest-result.js`.
- **Variants**: sample file, local collect, DNS cache, L7 file, PCAP file.
- **States**: current, available, unavailable.
- **Accessibility**: commands are plain text, not hidden behind hover.

### Report modal
- **Structure**: modal overlay, report summary, close, print-to-PDF action.
- **States**: hidden, open, print mode.
- **Accessibility**: dialog role, focusable buttons, keyboard close.

## 6. Motion & Interaction

Use 150-200ms ease-out transitions for hover and selected state changes. Respect reduced motion by keeping animations non-essential and transform/opacity-only.

## 7. Depth & Surface

Depth strategy is borders plus tonal shift. Panels use #1b2027; selected rows and raised blocks use #202733; modal overlays use a transparent dark scrim.
