# Daly Alpha

Smart battle calculator for strategy-game scout reports. Upload a scout report screenshot and the app auto-reads troop totals (OCR), then suggests an optimal attack composition.

## Features

- OCR image reading (Tesseract.js in-browser)
- Auto-parsing + normalization for values like `360k`, `1.1m`
- Smart analysis + recommended troop ratio
- PWA support (manifest + service worker caching)
- Multi-language UI (AR / EN / PT)

## Tech Stack

- Vanilla HTML/CSS/JS
- Tesseract.js (loaded on-demand from CDN)
- Service Worker + Web App Manifest (PWA)

## How To Use

1. Open `index.html` via a local static server (recommended).
2. Upload a scout report screenshot from your device.
3. The troop fields (Snipers / Fighters / Cavalry) auto-fill.
4. Press `Smart Analysis` (or `Calculate Best Composition`) to get a recommendation.

Tip: For best OCR results, use a clear screenshot with the troop totals visible.

## Local Run

Any static server works. Example:

```bash
python -m http.server 3000
```

Then open:

- http://127.0.0.1:3000/

## GitHub Pages Deployment

1. Push this repository to GitHub.
2. In GitHub: Settings → Pages → Deploy from a branch.
3. Select your branch (usually `main`) and `/ (root)`.

Live demo:

- https://<your-user>.github.io/<your-repo>/

## Notes

- The OCR runs fully in the browser.
