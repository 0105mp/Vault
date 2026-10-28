const PORT = 8743;
const BASE = `http://127.0.0.1:${PORT}`;
const CLIPBOARD_CLEAR_MS = 20 * 1000;

const listEl = document.getElementById("list");
const statusEl = document.getElementById("status");
const searchEl = document.getElementById("search");

let allEntries = [];
let clearTimer = null;

function setStatus(text, kind) {
  statusEl.textContent = text || "";
  statusEl.className = kind || "";
}

function render(entries) {
  listEl.innerHTML = "";
  if (entries.length === 0) {
    const empty = document.createElement("div");
    empty.id = "status";
    empty.textContent = "No matching entries.";
    listEl.appendChild(empty);
    return;
  }
  for (const e of entries) {
    const row = document.createElement("div");
    row.className = "row";
    const t = document.createElement("div");
    t.className = "t";
    t.textContent = e.title;
    const u = document.createElement("div");
    u.className = "u";
    u.textContent = e.username || e.url || "";
    row.appendChild(t);
    row.appendChild(u);
    row.addEventListener("click", () => copyPassword(e));
    listEl.appendChild(row);
  }
}

async function copyPassword(entry) {
  const token = await getToken();
  if (!token) return;
  try {
    const res = await fetch(`${BASE}/entries/${entry.id}/password`, {
      method: "POST",
      headers: { "X-Vault-Token": token },
    });
    if (!res.ok) {
      setStatus("Couldn't fetch password (is Vault unlocked?)", "error");
      return;
    }
    const data = await res.json();
    await navigator.clipboard.writeText(data.password);
    setStatus(`Copied password for "${entry.title}" - clears in 20s`, "ok");
    if (clearTimer) clearTimeout(clearTimer);
    clearTimer = setTimeout(() => {
      navigator.clipboard.writeText("").catch(() => {});
    }, CLIPBOARD_CLEAR_MS);
  } catch (err) {
    setStatus("Can't reach the Vault app. Is it running?", "error");
  }
}

function getToken() {
  return new Promise((resolve) => {
    chrome.storage.local.get(["vaultToken"], (result) => resolve(result.vaultToken || null));
  });
}

async function load() {
  const token = await getToken();
  if (!token) {
    setStatus("Not set up yet. Open the extension options and paste your pairing token.", "error");
    return;
  }
  try {
    const res = await fetch(`${BASE}/entries`, { headers: { "X-Vault-Token": token } });
    if (res.status === 401) {
      setStatus("Pairing token is wrong. Re-check it in the extension options.", "error");
      return;
    }
    if (res.status === 423) {
      setStatus("Vault is locked. Unlock it in the desktop app first.", "error");
      return;
    }
    if (!res.ok) {
      setStatus("Vault app returned an error.", "error");
      return;
    }
    const data = await res.json();
    allEntries = data.entries || [];
    render(allEntries);
  } catch (err) {
    setStatus("Can't reach the Vault app. Make sure it's running.", "error");
  }
}

searchEl.addEventListener("input", () => {
  const q = searchEl.value.toLowerCase().trim();
  if (!q) {
    render(allEntries);
    return;
  }
  render(allEntries.filter(
    (e) => e.title.toLowerCase().includes(q) || (e.username || "").toLowerCase().includes(q)
  ));
});

load();
