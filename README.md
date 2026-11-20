# Saoirse's Tool

A JSON-only, POST-only Node.js device whitelist server with an administrator dashboard.

## Run

```bash
ADMIN_TOKEN="replace-with-a-long-secret" WHITELISTED_DEVICES="device-001,device-002" npm start
```

The admin dashboard is available at `POST /rpo`.

## API

- `POST /check.json` — check a device: `{"deviceId":"device-001"}`
- `POST /admin/data.json` — view device data (requires admin bearer token)
- `POST /admin/action.json` — add, remove, blacklist, or unblacklist a device

Whitelist and attempt data is currently stored in memory and resets when the server restarts.
