# bsky-low-data

A minimal, static, installable Progressive Web App (PWA) for posting to Bluesky that loads fast and works well on low-bandwidth connections. It supports:

- App Password login (fully working)
- OAuth login (experimental: PKCE + PAR + DPoP)
- Link and hashtag facets
- Image uploads with on-device compression (quality + max dimension controls) and per-image alt text
- Thread replies (provide parent/root URIs and CIDs)
- PWA installability and offline asset caching (service worker)

## Quick start (local)

1. Add icons:
   - Place `icons/icon-192.png` and `icons/icon-512.png` in `icons/`.
2. Serve locally (any static server works). Examples:
   - Python: `python3 -m http.server 8080`
   - Node: `npx serve -p 8080 --no-clipboard`
3. Open `http://localhost:8080`.

## Login options

- App Password: enter your handle (or DID) and your Bluesky App Password. Do not use your main account password.
- OAuth (experimental): enter your handle and use the default redirect (`oauth-callback.html`). Flow uses PKCE + PAR and DPoP.

## Posting

- Type your text (byte counter enforces 300 bytes). Links and `#hashtags` are auto-faceted.
- Add up to 4 images. Toggle compression, and tweak max dimension and JPEG quality. Provide optional alt text per image.
- To reply in a thread, provide the parent post `uri` and `cid`. Optionally provide root `uri`/`cid` if different.

## Deploy to GitHub Pages

1. Push this repo to GitHub.
2. In repo settings → Pages → Build from branch → `main` and `/ (root)`.
3. Ensure `.nojekyll` exists (included) and manifest uses relative paths.
4. Visit your Pages URL. The service worker will cache core assets for quicker loads.

Notes:
- GitHub Pages applies ~10-minute cache headers; updates may take a short while to propagate.
- Service worker uses cache-first for `index.html`, `styles.css`, `app.js`, and manifest.

## Privacy

- No analytics. Credentials are stored locally in `localStorage` for session continuity.

## Limitations

- No video uploads (to save bandwidth).
- OAuth in browsers is evolving; DPoP/PAR support may vary by PDS and environment.

## License

MIT
