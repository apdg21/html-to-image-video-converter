# Improvements applied

- Added a visible reminder that browser rendering is approximate and output should be inspected.
- Added a pre-render pixel/frame budget to prevent high-resolution, long animations from allocating excessive memory.
- Sanitized imported HTML before it enters the preview frame: removes scripts, nested frames/embeds, inline event handlers, JavaScript URLs, and meta refresh. CSS animation and ordinary markup remain available; script-driven creative behavior is intentionally disabled.
- Added a clear note when imported content contains JavaScript.
- Enforced the 25 MB proxy limit against the actual response stream, not only Content-Length.

## Validation

- `node --check` passed for the inline application JavaScript and the Cloudflare Pages Function.
- Please deploy to a staging Pages project and test representative HTML uploads, CSS animations, remote URLs, and all export types before replacing the live version.
