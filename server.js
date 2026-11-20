const http = require("node:http");
const fs = require("node:fs");
const path = require("node:path");

const port = Number(process.env.PORT) || 3000;
const adminKey = process.env.ADMIN_KEY;
const whitelistFile = path.join(__dirname, "whitelist.json");

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

let whitelist = loadWhitelist();

function saveWhitelist() {
  fs.writeFileSync(whitelistFile, JSON.stringify([...whitelist], null, 2) + "\n", "utf8");
}

function sendJson(res, status, data) {
  res.writeHead(status, {
    "Content-Type": "application/json; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(JSON.stringify(data));
}

function sendHtml(res, status, html) {
  res.writeHead(status, {
    "Content-Type": "text/html; charset=utf-8",
    "Cache-Control": "no-store",
  });
  res.end(html);
}

async function readJson(req, res) {
  if (!req.headers["content-type"]?.includes("application/json")) {
    sendJson(res, 415, { error: "Content-Type must be application/json" });
    req.resume();
    return null;
  }

  let body = "";
  for await (const chunk of req) {
    body += chunk;
    if (Buffer.byteLength(body) > 10_000) {
      sendJson(res, 413, { error: "Request body too large" });
      return null;
    }
  }

  try {
    return JSON.parse(body);
  } catch {
    sendJson(res, 400, { error: "Invalid JSON" });
    return null;
  }
}

function isAdmin(req) {
  const authorization = req.headers.authorization || "";
  return authorization === `Bearer ${adminKey}`;
}

function recordAttempt(deviceId, allowed, req) {
  const count = (attempts.get(deviceId)?.count || 0) + 1;
  attempts.set(deviceId, { deviceId, count });

  recentAttempts.unshift({
    deviceId,
    count,
    allowed,
    ip: req.socket.remoteAddress || "unknown",
    time: new Date().toISOString(),
  });

  if (recentAttempts.length > MAX_RECENT_ATTEMPTS) recentAttempts.pop();
  return count;
}

function dashboardHtml() {
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Device Access Admin</title>
  <style>
    :root { color-scheme:light; --ink:#172033; --muted:#64748b; --line:#e2e8f0; --page:#f4f7fb; --blue:#3157d5; --red:#b42318; --green:#067647 }
    * { box-sizing:border-box }
    body { margin:0; background:var(--page); color:var(--ink); font:15px/1.5 system-ui,sans-serif }
    header { background:#172554; color:white; padding:24px max(20px,calc((100% - 1100px)/2)) }
    header h1 { margin:0; font-size:1.4rem } header p { margin:4px 0 0; color:#cbd5e1 }
    main { max-width:1100px; margin:24px auto; padding:0 20px }
    .card { background:white; border:1px solid var(--line); border-radius:12px; padding:20px; margin-bottom:18px }
    h2 { margin:0 0 14px; font-size:1.1rem }
    input { min-width:220px; padding:10px 12px; border:1px solid #cbd5e1; border-radius:7px; font:inherit }
    button { border:0; border-radius:7px; padding:9px 12px; background:var(--blue); color:white; font:inherit; cursor:pointer }
    button.danger { background:var(--red) }
    form.inline { display:flex; gap:8px; flex-wrap:wrap }
    .hint,#message { color:var(--muted) }
    .stats { display:flex; gap:12px; flex-wrap:wrap }
    .stat { flex:1; min-width:150px; background:#f8fafc; border:1px solid var(--line); border-radius:9px; padding:14px }
    .stat strong { display:block; font-size:1.35rem }
    .table-wrap { overflow-x:auto } table { width:100%; border-collapse:collapse; min-width:620px }
    th,td { padding:10px; text-align:left; border-bottom:1px solid var(--line) } th { color:var(--muted) }
    .allowed { color:var(--green); font-weight:600 } .denied { color:var(--red); font-weight:600 }
    .actions { display:flex; gap:6px }
  </style>
</head>
<body>
  <header><h1>Device Access Admin</h1><p>Manage whitelist, blacklist, and access attempts.</p></header>
  <main>
    <section class="card">
      <h2>Administrator sign-in</h2>
      <form id="login" class="inline">
        <input id="key" type="password" placeholder="Admin key" required>
        <button type="submit">Sign in</button>
      </form>
      <p class="hint">The key is kept in this browser tab only.</p>
      <p id="message" role="status"></p>
    </section>

    <section id="dashboard" hidden>
      <section class="card"><h2>Overview</h2><div class="stats">
        <div class="stat">Whitelisted<strong id="whitelist-count">0</strong></div>
        <div class="stat">Blacklisted<strong id="blacklist-count">0</strong></div>
        <div class="stat">Tracked devices<strong id="device-count">0</strong></div>
      </div></section>

      <section class="card"><h2>Whitelist</h2>
        <form id="add-device" class="inline"><input id="device-id" placeholder="Device ID" required><button>Add to whitelist</button></form>
        <div class="table-wrap"><table><thead><tr><th>Device ID</th><th>Actions</th></tr></thead><tbody id="whitelist"></tbody></table></div>
      </section>

      <section class="card"><h2>Blacklist</h2>
        <div class="table-wrap"><table><thead><tr><th>Device ID</th><th>Actions</th></tr></thead><tbody id="blacklist"></tbody></table></div>
      </section>

      <section class="card"><h2>Recent access attempts</h2>
        <div class="table-wrap"><table><thead><tr><th>Device ID</th><th>Total attempts</th><th>Result</th><th>IP</th><th>Time</th><th>Actions</th></tr></thead><tbody id="attempts"></tbody></table></div>
      </section>
    </section>
  </main>

  <script>
    const message=document.getElementById("message");
    function cell(row,value){const td=document.createElement("td");td.textContent=String(value ?? "");row.append(td);return td}
    function actionButton(label,action,id,danger=false){const button=document.createElement("button");button.type="button";button.textContent=label;if(danger)button.className="danger";button.onclick=()=>runAction(action,id);return button}
    async function api(path,data={}){const response=await fetch(path,{method:"POST",headers:{"Content-Type":"application/json","Authorization":"Bearer "+sessionStorage.getItem("adminKey")},body:JSON.stringify(data)});const result=await response.json();if(!response.ok)throw new Error(result.error||"Request failed");return result}
    async function loadData(){const data=await api("/admin/data.json");document.getElementById("whitelist-count").textContent=data.whitelist.length;document.getElementById("blacklist-count").textContent=data.blacklist.length;document.getElementById("device-count").textContent=data.deviceCount;
      const white=document.getElementById("whitelist");white.replaceChildren();for(const id of data.whitelist){const row=document.createElement("tr");cell(row,id);const actions=cell(row,"");actions.className="actions";actions.append(actionButton("Remove","remove",id,true),actionButton("Blacklist","blacklist",id,true));white.append(row)}
      const black=document.getElementById("blacklist");black.replaceChildren();for(const id of data.blacklist){const row=document.createElement("tr");cell(row,id);const actions=cell(row,"");actions.className="actions";actions.append(actionButton("Unblacklist","unblacklist",id));black.append(row)}
      const attempts=document.getElementById("attempts");attempts.replaceChildren();for(const attempt of data.recentAttempts){const row=document.createElement("tr");cell(row,attempt.deviceId);cell(row,attempt.count);const status=cell(row,attempt.allowed?"Allowed":"Denied");status.className=attempt.allowed?"allowed":"denied";cell(row,attempt.ip);cell(row,attempt.time);const actions=cell(row,"");actions.className="actions";actions.append(actionButton("Blacklist","blacklist",attempt.deviceId,true));attempts.append(row)}}
    async function runAction(action,deviceId){try{await api("/admin/action.json",{action,deviceId});message.textContent="Changes saved.";await loadData()}catch(error){message.textContent=error.message}}
    document.getElementById("login").onsubmit=async event=>{event.preventEvent?.();event.preventDefault();sessionStorage.setItem("adminKey",document.getElementById("key").value);try{await loadData();document.getElementById("dashboard").hidden=false;message.textContent="Signed in."}catch(error){sessionStorage.removeItem("adminKey");message.textContent=error.message}};
    document.getElementById("add-device").onsubmit=async event=>{event.preventEvent?.();event.preventDefault();const input=document.getElementById("device-id");const id=input.value.trim();if(id){await runAction("add",id);input.value=""}};
  </script>
</body>
</html>`;
}

const server=http.createServer(async(req,res)=>{
  if(req.url==="/rpo") return sendHtml(res,200,dashboardHtml());
  
  if(req.method!=="POST"){
    res.setHeader("Allow","POST");
    return sendJson(res,405,{error:"Only POST requests are supported"});
  }

  

  if(req.url==="/check.json"){
    const body=await readJson(req,res);
    if(!body)return;
    const deviceId=typeof body.deviceId==="string"?body.deviceId.trim():"";
    if(!deviceId)return sendJson(res,400,{error:"deviceId is required"});
    const allowed=whitelist.has(deviceId)&&!blacklist.has(deviceId);
    const count=recordAttempt(deviceId,allowed,req);
    return sendJson(res,200,{deviceId,allowed,attemptCount:count});
  }

  if(req.url==="/admin/data.json"||req.url==="/admin/action.json"){
    if(!isAdmin(req))return sendJson(res,401,{error:"Unauthorized"});

    if(req.url==="/admin/data.json"){
      return sendJson(res,200,{whitelist:[...whitelist],blacklist:[...blacklist],deviceCount:attempts.size,recentAttempts});
    }

    const body=await readJson(req,res);
    if(!body)return;
    const deviceId=typeof body.deviceId==="string"?body.deviceId.trim():"";
    if(!deviceId)return sendJson(res,400,{error:"deviceId is required"});

    if(body.action=== "add") {whitelist.add(deviceId);blacklist.delete(deviceId);saveWhitelist();}
    else if(body.action=== "remove") {whitelist.delete(deviceId);saveWhitelist();}
    else if(body.action=== "blacklist") {blacklist.add(deviceId);whitelist.delete(deviceId);saveWhitelist();}
    else if(body.action=== "unblacklist") blacklist.delete(deviceId);
    else return sendJson(res,400,{error:"Unknown action"});

    return sendJson(res,200,{ok:true});
  }

  return sendJson(res,404,{error:"Not found"});
});

server.listen(port,()=>console.log(`Listening on port ${port}`));
