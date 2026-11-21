# Saoirse's Tool

Express-based whitelist checker and browser-side `.SAO` packager.

## Start

```sh
npm install
ADMIN_KEY='set-a-long-admin-secret' ENC_PASSWORD='set-a-separate-long-page-password' npm start
```

Open `http://localhost:3000/enc`; the browser requests the `ENC_PASSWORD` via HTTP Basic Auth. Use HTTPS when exposed beyond localhost. Do not hard-code the password into source or commit it.

The encryptor processes files locally in the browser. It requires Web Crypto and Compression Streams (modern browsers over HTTPS or localhost).

## Device check

`POST /check` with `Content-Type: application/json` and body:

```json
{"deviceId":"your-device-id"}
```

## Admin API

Admin endpoints require `Authorization: Bearer <ADMIN_KEY>`:

- `POST /admin/data.json`
- `POST /admin/action.json` with `{"action":"add|remove|blacklist|unblacklist","deviceId":"..."}`

Whitelist data is stored in `whitelist.json`; blacklist and attempt history are currently in memory.
