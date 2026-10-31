"use strict";
// Tutto il contenuto proveniente dal web viene inserito con textContent: niente XSS.

const $ = (id) => document.getElementById(id);
let state = {}, findings = [], filter = "all", pollTimer = null;

async function api(path, method = "GET", body) {
  const opt = { method, headers: { "X-LeakWatch": "1" } };
  if (body !== undefined) { opt.headers["Content-Type"] = "application/json"; opt.body = JSON.stringify(body); }
  const r = await fetch(path, opt);
  const data = await r.json().catch(() => ({}));
  if (r.status === 423) { await refresh(); throw new Error("Vault bloccato"); }
  if (!r.ok) throw new Error(data.detail?.[0]?.msg || data.detail || "Errore " + r.status);
  return data;
}

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;
  return e;
}

// ---------------------------------------------------------------- stato
async function refresh() {
  state = await api("/api/state");
  const unlocked = state.unlocked;
  $("view-lock").hidden = unlocked;
  $("view-app").hidden = !unlocked;
  $("btn-lock").hidden = !unlocked;
  $("dot").classList.toggle("ok", unlocked);
  const parts = [`kill switch Tor: ${state.require_tor ? "attivo" : "DISATTIVO"}`, `auto-cancellazione ${state.retention_hours}h`];
  if (state.scheduler) parts.push(state.vault_unlocked && state.next_scan_at
    ? `prossima scansione ${new Date(state.next_scan_at * 1000).toLocaleString("it-IT", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" })}`
    : "scansioni automatiche in pausa (vault bloccato)");
  if (state.telegram) parts.push("Telegram attivo");
  $("meta").textContent = parts.join(" · ");
  $("btn-tg").hidden = !state.telegram;
  $("btn-stop").hidden = !state.scheduler;
  $("retention").textContent = `Si cancellano da soli dopo ${state.retention_hours} ore`;

  const first = !state.initialized;
  $("lock-title").textContent = first ? "Crea il vault" : "Sblocca";
  $("lock-hint").textContent = first
    ? "Scegli una passphrase di almeno 12 caratteri. Non è recuperabile: se la perdi, i dati sono persi."
    : state.vault_unlocked
      ? "Le scansioni automatiche sono attive. Inserisci la passphrase per aprire la dashboard."
      : "La chiave resta solo in memoria e si cancella al blocco.";
  $("pass2").hidden = !first;
  $("pass2").required = first;
  $("btn-unlock").textContent = first ? "Crea" : "Sblocca";

  if (unlocked) {
    renderScan(state.scan);
    if (state.scan.running) startPolling();
  } else {
    clearSensitiveView();
  }
}

// Sessione scaduta o vault bloccato: nessun dato resta nella pagina, nemmeno nascosto
function clearSensitiveView() {
  $("form-profile").reset();
  $("passwords").value = "";
  $("results").replaceChildren();
  findings = [];
  clearInterval(pollTimer);
}

// ---------------------------------------------------------------- blocco
$("form-lock").addEventListener("submit", async (e) => {
  e.preventDefault();
  $("lock-error").textContent = "";
  const p = $("pass").value;
  try {
    if (!state.initialized) {
      if (p !== $("pass2").value) throw new Error("Le passphrase non coincidono");
      await api("/api/init", "POST", { passphrase: p });
    } else {
      await api("/api/unlock", "POST", { passphrase: p });
    }
    $("pass").value = $("pass2").value = "";
    await refresh();
    await loadProfile();
    await loadResults();
  } catch (err) { $("lock-error").textContent = err.message; }
});

$("btn-lock").addEventListener("click", async () => {
  await api("/api/lock", "POST", { full: false });
  await refresh();
});

// ---------------------------------------------------------------- profilo
async function loadProfile() {
  const p = await api("/api/profile");
  const f = $("form-profile");
  for (const k of ["first_name", "last_name", "birth_date", "cf"]) f.elements[k].value = p[k] || "";
  for (const k of ["emails", "phones", "documents", "usernames"]) f.elements[k].value = (p[k] || []).join("\n");
}

$("form-profile").addEventListener("submit", async (e) => {
  e.preventDefault();
  const f = e.target, body = {};
  for (const k of ["first_name", "last_name", "birth_date", "cf"]) body[k] = f.elements[k].value;
  for (const k of ["emails", "phones", "documents", "usernames"]) body[k] = f.elements[k].value.split("\n");
  try {
    const r = await api("/api/profile", "PUT", body);
    $("profile-msg").textContent = r.warnings.length ? "⚠ " + r.warnings.join(" ") : "Salvato.";
  } catch (err) { $("profile-msg").textContent = err.message; }
});

// ---------------------------------------------------------------- scansione
$("btn-scan").addEventListener("click", async () => {
  $("scan-error").textContent = "";
  const passwords = $("passwords").value.split("\n").filter(Boolean);
  try {
    await api("/api/scan", "POST", { passwords });
    $("passwords").value = "";
    startPolling();
  } catch (err) { $("scan-error").textContent = err.message; }
});

function renderScan(s) {
  $("btn-scan").disabled = s.running;
  $("bar").style.width = (s.running || s.progress === 100 ? s.progress : 0) + "%";
  $("scan-step").textContent = s.step || "";
  $("scan-error").textContent = s.last_error || "";
}

function startPolling() {
  clearInterval(pollTimer);
  pollTimer = setInterval(async () => {
    try {
      const st = await api("/api/state");
      renderScan(st.scan);
      if (!st.scan.running) { clearInterval(pollTimer); await loadResults(); }
    } catch { clearInterval(pollTimer); }
  }, 1500);
}

// ---------------------------------------------------------------- risultati
async function loadResults() {
  const r = await api("/api/results");
  findings = r.findings;
  const last = r.scans[0];
  if (last?.errors?.length) $("scan-error").textContent = last.errors.join(" · ");
  renderResults();
}

function fmtLeft(sec) {
  const h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60);
  return `si cancella tra ${h}h ${m}m`;
}

function renderResults() {
  const box = $("results");
  const list = findings.filter((f) =>
    filter === "all" ? true : filter === "new" ? f.new : f.severity === filter);
  if (!list.length) {
    box.replaceChildren(el("div", "empty", findings.length ? "Nessun risultato con questo filtro." : "Nessun risultato. Avvia una scansione."));
    return;
  }
  const order = { alta: 0, media: 1, bassa: 2 };
  list.sort((a, b) => order[a.severity] - order[b.severity] || b.created_at - a.created_at);
  box.replaceChildren(...list.map(card));
}

function card(f) {
  const c = el("div", "finding " + f.severity);
  const head = el("div", "f-head");
  head.append(el("span", "tag " + f.severity, f.severity), el("span", "f-title", f.title), el("span", "tag", f.source));
  if (f.new) head.append(el("span", "tag new", "nuovo"));
  head.append(el("span", "muted small", fmtLeft(f.expires_in)));
  c.append(head);
  if (f.url) {
    const u = el("div", "f-url");
    const b = el("button", "", "copia");
    b.addEventListener("click", () => navigator.clipboard.writeText(f.url).then(() => (b.textContent = "copiato")));
    u.append(el("span", "", f.url), b);
    c.append(u);
  }
  for (const it of f.items || []) {
    const row = el("div", "item");
    row.append(el("b", "", it.label));
    if (it.context) row.append(el("span", "ctx", it.context));
    c.append(row);
  }
  return c;
}

$("filters").addEventListener("click", (e) => {
  const b = e.target.closest(".chip");
  if (!b) return;
  filter = b.dataset.f;
  document.querySelectorAll(".chip").forEach((x) => x.classList.toggle("active", x === b));
  renderResults();
});

// ---------------------------------------------------------------- controlli
$("btn-tg").addEventListener("click", async () => {
  try { await api("/api/telegram/test", "POST"); alert("Messaggio inviato."); }
  catch (err) { alert(err.message); }
});

$("btn-stop").addEventListener("click", async () => {
  if (!confirm("Bloccare il vault e fermare le scansioni automatiche finché non lo sblocchi di nuovo?")) return;
  await api("/api/lock", "POST", { full: true });
  await refresh();
});
$("btn-purge").addEventListener("click", async () => {
  if (!confirm("Cancellare subito tutti i risultati e lo storico delle ricerche?")) return;
  await api("/api/purge", "POST");
  await loadResults();
});

$("btn-wipe").addEventListener("click", async () => {
  const v = prompt('Distrugge vault, profilo e risultati in modo irreversibile.\nScrivi "CANCELLA TUTTO" per confermare:');
  if (v !== "CANCELLA TUTTO") return;
  await api("/api/wipe", "POST", { confirm: v });
  await refresh();
});

refresh().then(async () => {
  if (state.unlocked) { await loadProfile(); await loadResults(); }
});

// Ogni minuto controlla se la sessione è scaduta (il controllo non la rinnova)
setInterval(() => { refresh().catch(() => {}); }, 60000);
