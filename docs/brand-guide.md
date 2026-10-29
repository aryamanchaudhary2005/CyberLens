# CyberLens brand guide

## Logo idea

The mark is an open geometric lens shaped like a **C**. The gap stays open at small sizes, where the short connection and single focal node suggest one piece of evidence entering review. The mark is original CyberLens artwork and is kept as editable SVG; it does not use a stock symbol, an external image, or an embedded font.

## Source artwork

- [`cyberlens-master.svg`](../frontend/public/brand/cyberlens-master.svg) is the editable horizontal master with named SVG groups for the lens, evidence link, node, and wordmark.
- [`cyberlens-icon.svg`](../frontend/public/brand/cyberlens-icon.svg) is the transparent color icon. [`cyberlens-icon-monochrome.svg`](../frontend/public/brand/cyberlens-icon-monochrome.svg) is the single-color alternative.
- [`cyberlens-wordmark-dark.svg`](../frontend/public/brand/cyberlens-wordmark-dark.svg) is for dark surfaces; [`cyberlens-wordmark-light.svg`](../frontend/public/brand/cyberlens-wordmark-light.svg) is for light surfaces; [`cyberlens-wordmark-monochrome.svg`](../frontend/public/brand/cyberlens-wordmark-monochrome.svg) works in one-color contexts.
- [`favicon.svg`](../frontend/public/favicon.svg) uses the same icon artwork. PNG fallbacks at 16, 24, 32, and 180 pixels are rasterized directly from that SVG.

The vector wordmark uses Arial/Helvetica with platform sans-serif fallback. The application uses the installed UI system font. Neither path downloads fonts. The React `BrandLockup` and `BrandMark` components reference only local SVG assets.

## Color

| Role | Color |
| --- | --- |
| Lens blue | `#64A5FF` |
| Lens indigo | `#7968F1` |
| Connection blue | `#90AEFF` |
| Focal point | `#C6D2FF` |
| Main interface accent | `#8BAAFF` |
| Dark-background wordmark | `#EEF3FF` |
| Light-background wordmark | `#222A43` |

Use the blue-to-indigo mark on the existing charcoal/navy surfaces. Use the light wordmark for white report pages and light surfaces. Use the monochrome artwork when color reproduction is unavailable. Green remains reserved for semantic success states and is not part of the logo.

## Spacing and size

Keep clear space around the mark at least the width of its focal node. In the application lockup, use an 8–10 CSS pixel mark-to-wordmark gap; do not squeeze the lettering to fit a narrow layout. Prefer the icon alone below 32 pixels and the horizontal lockup at larger sizes. Keep the C opening and its node visible; do not crop, stretch, rotate, add a shield, or place a competing shape inside the opening.

The brand PNGs are transparent. For a background tile, use a flat surface with adequate contrast rather than baking an unapproved color into the logo image. At 16 pixels, keep the mark at native size and do not add shadows or small text.

## Motion and accessibility

The application wordmark rolls in once when its brand area appears. Hovering the login brand or entering the sidebar home control with keyboard focus intentionally replays it. Routine updates and navigation do not replay the roll. The complete text remains readable beneath the moving ink layer, and the lockup exposes one accessible name: “CyberLens.” The system reduced-motion setting and the application preference both show the static full title immediately.

Brand SVGs are decorative inside the accessible lockup, so assistive technology does not announce the mark and wordmark twice. Standalone icon use must have a suitable accessible name when it conveys meaning.

## Reports

Newly generated PDFs use a small vector lockup in dark text and blue-indigo mark colors on the standard light PDF page. Saved report bytes and snapshots are point-in-time records and are not regenerated when brand artwork changes.

## Visual checks

These screenshots use synthetic Demo UI data and a synthetic PDF example. The full-size raster output is at native resolution in the first three icon assets; the browser checks also loaded each image and confirmed its dimensions.

- [Login, desktop](brand/screenshots/brand-login-desktop.png)
- [Expanded sidebar, desktop](brand/screenshots/brand-app-expanded-desktop.png)
- [Collapsed sidebar](brand/screenshots/brand-sidebar-collapsed.png)
- [Mobile header at 390px](brand/screenshots/brand-app-mobile-390.png)
- [New report header on a light PDF page](brand/screenshots/brand-report-light-page.png)
