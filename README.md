# MrBrands Readiness Tool V4

Cloudflare Worker name:

`mrbrands-readiness-tool-v4`

Expected URLs after deployment:

- `https://mrbrands-readiness-tool-v4.v4vz68wt5j.workers.dev`
- `https://mrbrands-readiness-tool-v4.v4vz68wt5j.workers.dev/tool`

Cloudflare build settings:

- Root directory: `/`
- Build command: leave blank
- Deploy command: `npx wrangler deploy`

The Worker root should return JSON containing `"version":"4.0.0"`.
The `/tool` route should display the full interactive audit interface.
