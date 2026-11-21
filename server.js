const express = require("express");
const fs = require("node:fs");
const path = require("node:path");
const { timingSafeEqual } = require("node:crypto");

const app = express();
const port = Number(process.env.PORT) || 3000;
const adminKey = process.env.ADMIN_KEY;
const encPassword = process.env.ENC_PASSWORD;
const whitelistFile = path.join(__dirname, "whitelist.json");
const encryptorFile = path.join(__dirname, "Resilient_Crypto_Engine___Status_Indicator.html");

app.set("trust proxy", 1);
app.use(express.json({ limit: "10kb" }));

const blacklist = new Set();
const attempts = new Map();
const recentAttempts = [];
const MAX_RECENT_ATTEMPTS = 100;

function loadWhitelist() {
  try {
    const data = JSON.parse(fs.readFileSync(whitelistFile, "utf8"));
    if (!Array.isArray(data)) throw new Error("whitelist.json must contain an array");
    return new Set(data.map((id) => String(id).trim()).filter(Boolean));
  } catch (error) {
    console.error(`Unable to load whitelist.json: ${error.message}`);
    return new Set();
  }
}

const whitelist = loadWhitelist();

function saveWhitelist() {
  fs.writeFileSync(whitelistFile, `${JSON.stringify([...whitelist], null, 2)}\n`, "utf8");
}

function safeStringEqual(a, b) {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

function requireEncPassword(req, res, next) {
  if (!encPassword) {
    return res.status(503).send("ENC_PASSWORD is not configured on the server.");
  }

  const header = req.get("authorization") || "";
  if (header.startsWith("Basic ")) {
    let decoded = "";
    try {
      decoded = Buffer.from(header.slice(6), "base64").toString("utf8");
    } catch {
      decoded = "";
    }
    const separator = decoded.indexOf(":");
    const password = separator >= 0 ? decoded.slice(separator + 1) : "";
    if (safeStringEqual(password, encPassword)) return next();
  }

  res.set("WWW-Authenticate", 'Basic realm="Saoirse Encryptor", charset="UTF-8"');
  return res.status(401).type("text").send("Password required to access the encryptor.");
}

function requireAdmin(req, res, next) {
  if (!adminKey) return res.status(503).json({ error: "ADMIN_KEY is not configured" });
  if (req.get("authorization") !== `Bearer ${adminKey}`) {
    return res.status(401).json({ error: "Unauthorized" });
  }
  next();
}

function recordAttempt(deviceId, allowed, req) {
  const count = (attempts.get(deviceId) || 0) + 1;
  attempts.set(deviceId, count);
  recentAttempts.unshift({ deviceId, count, allowed, ip: req.ip, time: new Date().toISOString() });
  if (recentAttempts.length > MAX_RECENT_ATTEMPTS) recentAttempts.pop();
  return count;
}

// GET /enc is password-protected with HTTP Basic Auth. The HTML is not exposed as a static file.
app.get("/enc", requireEncPassword, (_req, res) => {
  res.set("Cache-Control", "no-store").sendFile(encryptorFile);
});

// Device check API: POST /check with JSON {"deviceId":"..."}.
app.post("/check", (req, res) => {
  const deviceId = typeof req.body?.deviceId === "string" ? req.body.deviceId.trim() : "";
  if (!deviceId) return res.status(400).json({ error: "deviceId is required" });
  const allowed = whitelist.has(deviceId) && !blacklist.has(deviceId);
  return res.json({ deviceId, allowed, attemptCount: recordAttempt(deviceId, allowed, req) });
});

// Admin APIs remain POST-only.
app.post("/admin/data.json", requireAdmin, (_req, res) => {
  res.json({ whitelist: [...whitelist], blacklist: [...blacklist], deviceCount: attempts.size, recentAttempts });
});

app.post("/admin/action.json", requireAdmin, (req, res) => {
  const deviceId = typeof req.body?.deviceId === "string" ? req.body.deviceId.trim() : "";
  const { action } = req.body || {};
  if (!deviceId) return res.status(400).json({ error: "deviceId is required" });

  if (action === "add") {
    whitelist.add(deviceId);
    blacklist.delete(deviceId);
    saveWhitelist();
  } else if (action === "remove") {
    whitelist.delete(deviceId);
    saveWhitelist();
  } else if (action === "blacklist") {
    blacklist.add(deviceId);
    whitelist.delete(deviceId);
    saveWhitelist();
  } else if (action === "unblacklist") {
    blacklist.delete(deviceId);
  } else {
    return res.status(400).json({ error: "Unknown action" });
  }
  return res.json({ ok: true });
});

app.use((error, _req, res, _next) => {
  if (error instanceof SyntaxError && "body" in error) return res.status(400).json({ error: "Invalid JSON" });
  if (error.type === "entity.too.large") return res.status(413).json({ error: "Request body too large" });
  console.error(error);
  return res.status(500).json({ error: "Internal server error" });
});

app.listen(port, () => console.log(`Listening on port ${port}`));
