# Demo replay

## UI file replay (recommended for tomorrow)

1. Start the console (`cd unipe-ui && npm run tauri:dev`).
2. In the status bar, use **load file** / replay and open:

   `demos/demo_alerts.jsonl`

3. Play / scrub — ~42 alerts over ~11 minutes of capture time (replay maps into a short play window).

Narrative beats:

1. Recon scan against `198.51.100.10` / LAN
2. Spoofed volumetric flood on the same victim
3. Host `192.168.1.50`: DGA → encrypted anomalies → C2 beacon → exfil
4. Host `192.168.1.9`: DNS tunnel → beacon → exfil

Incidents are tagged with `incident_id` so the Incidents tab and entity dossier have something to show.
