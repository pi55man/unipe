# unipe-ui

Desktop ops console for unipe alerts. Next.js + Tailwind in the webview, Tauri
for the native window. Talks to the live Python engine by polling files under
`/tmp/unipe/`.

```shell
# terminal 1 — rust exporter (needs root for XDP)
sudo ./target/release/unipe --iface wlan0 --skb

# terminal 2 — python engine (writes alerts + status for the ui)
cd unipe-ai && python3 run.py

# terminal 3 — desktop shell
cd unipe-ui && npm run tauri:dev
```

Defaults the engine uses (override with flags):

- alerts: `/tmp/unipe/alerts.jsonl`
- status: `/tmp/unipe/status.json`
- socket: `/tmp/unipe.sock`

In the browser (`npm run dev`) you get mocks / `public/alerts.jsonl` and file
load. Live pipeline dots need the Tauri app.

Dark mode: toggle in the top bar (persisted in `localStorage`).
