const API = "/api";
const ITERATIONS = 310000;
const CHECK_TEXT = "vaultdb-browser-key-check-v1";
const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const state = { key: null, items: [], view: "vault", filter: "all", search: "" };

function toBase64(value) {
  const bytes = value instanceof Uint8Array ? value : new Uint8Array(value);
  let binary = "";
  for (let i = 0; i < bytes.length; i += 0x8000) binary += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(binary);
}
function fromBase64(value) { return Uint8Array.from(atob(value), (char) => char.charCodeAt(0)); }
function randomBytes(length) { return crypto.getRandomValues(new Uint8Array(length)); }
async function deriveKey(password, salt) {
  const material = await crypto.subtle.importKey("raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITERATIONS, hash: "SHA-256" }, material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function encryptText(text, key = state.key) {
  const iv = randomBytes(12);
  const data = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, new TextEncoder().encode(text));
  return { iv: toBase64(iv), ciphertext: toBase64(data) };
}
async function decryptText(iv, ciphertext, key = state.key) {
  const data = await crypto.subtle.decrypt({ name: "AES-GCM", iv: fromBase64(iv) }, key, fromBase64(ciphertext));
  return new TextDecoder().decode(data);
}
async function api(path, options = {}) {
  const response = await fetch(`${API}${path}`, { ...options, headers: { ...(options.body ? { "Content-Type": "application/json" } : {}), ...options.headers } });
  if (response.status === 204) return null;
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw new Error(data.error || `Request failed (${response.status})`);
  return data;
}

async function initialize() {
  try {
    const vault = await api("/vault");
    const form = $("#gate-form");
    const confirmWrap = $("#confirm-wrap");
    if (vault.exists) {
      $("#gate-title").textContent = "Welcome back.";
      $("#gate-copy").textContent = "Unlock this vault with your master password. It never leaves your browser.";
      $("#gate-submit").textContent = "Unlock vault";
      $("#master-password").autocomplete = "current-password";
      confirmWrap.classList.add("hidden-field");
      $("#master-password").focus();
    } else {
      $("#gate-title").textContent = "Your vault starts here.";
      $("#gate-copy").textContent = "Create a master password to encrypt your vault on this device.";
      $("#gate-submit").textContent = "Create my vault";
      confirmWrap.classList.remove("hidden-field");
      $("#master-password").autocomplete = "new-password";
      $("#master-password").focus();
    }
    form.addEventListener("submit", (event) => handleGate(event, vault));
  } catch (error) {
    $("#gate-title").textContent = "Can't reach the local database.";
    $("#gate-copy").textContent = "Start VaultDB from VS Code, then refresh this page.";
    $("#gate-submit").disabled = true;
    showGateError(error.message);
  }
}
async function handleGate(event, vault) {
  event.preventDefault();
  const password = $("#master-password").value;
  const errorBox = $("#gate-error");
  errorBox.textContent = "";
  if (password.length < 8) return showGateError("Use at least 8 characters for your master password.");
  const button = $("#gate-submit");
  button.disabled = true;
  button.textContent = vault.exists ? "Unlocking…" : "Creating vault…";
  try {
    if (!vault.exists) {
      if (password !== $("#confirm-password").value) throw new Error("The master passwords do not match.");
      const salt = randomBytes(16);
      const key = await deriveKey(password, salt);
      const verifier = await encryptText(CHECK_TEXT, key);
      await api("/vault/setup", { method: "POST", body: JSON.stringify({ salt: toBase64(salt), verifierIv: verifier.iv, verifierCiphertext: verifier.ciphertext }) });
      state.key = key;
    } else {
      const key = await deriveKey(password, fromBase64(vault.salt));
      const result = await decryptText(vault.verifierIv, vault.verifierCiphertext, key);
      if (result !== CHECK_TEXT) throw new Error("That master password doesn't match this vault.");
      state.key = key;
    }
    $("#gate").classList.add("hidden");
    $("#app").classList.remove("hidden");
    $("#master-password").value = "";
    $("#confirm-password").value = "";
    await loadItems();
    updateStats();
    renderEntries();
  } catch (error) {
    showGateError(error.message.includes("OperationError") ? "That master password doesn't match this vault." : error.message);
    button.disabled = false;
    button.textContent = vault.exists ? "Unlock vault" : "Create my vault";
  }
}
function showGateError(message) { $("#gate-error").textContent = message; }
async function loadItems() {
  const encryptedItems = await api("/items");
  state.items = await Promise.all(encryptedItems.map(async (row) => {
    const data = JSON.parse(await decryptText(row.iv, row.ciphertext));
    return { ...row, data };
  }));
}
function scorePassword(password = "") {
  if (!password) return { score: 0, label: "No password", tone: "weak" };
  let score = 0;
  if (password.length >= 12) score++;
  if (password.length >= 16) score++;
  if (/[a-z]/.test(password) && /[A-Z]/.test(password)) score++;
  if (/\d/.test(password)) score++;
  if (/[^A-Za-z0-9]/.test(password)) score++;
  if (new Set(password).size / password.length > 0.65) score++;
  const tier = score >= 5 ? { label: "Strong", tone: "strong" } : score >= 3 ? { label: "Fair", tone: "medium" } : { label: "Needs work", tone: "weak" };
  return { score, ...tier };
}
function updateStats() {
  const strong = state.items.filter((item) => scorePassword(item.data.password).tone === "strong").length;
  $("#stat-total").textContent = state.items.length;
  $("#stat-strong").innerHTML = `${strong}<span class="stat-of"> / ${state.items.length}</span>`;
  $("#nav-count").textContent = state.items.length;
  $("#result-count").textContent = `${state.items.length} ${state.items.length === 1 ? "entry" : "entries"}`;
  $("#last-updated").textContent = state.items.length ? `Last saved ${new Date(Math.max(...state.items.map((item) => Date.parse(item.updatedAt)))).toLocaleString()}` : "Ready to protect your first password";
}
function escapeHtml(value = "") { return String(value).replace(/[&<>"']/g, (char) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#039;" })[char]); }
function initials(label = "?") { return label.trim().split(/\s+/).slice(0, 2).map((part) => part[0] || "").join("").toUpperCase() || "?"; }
function renderEntries() {
  const root = $("#entries-list");
  const search = state.search.trim().toLowerCase();
  const list = state.items.filter(({ data }) => (state.filter === "all" || data.category === state.filter) && (!search || [data.site, data.username, data.url, data.category].some((part) => String(part || "").toLowerCase().includes(search)))).sort((a, b) => Date.parse(b.updatedAt) - Date.parse(a.updatedAt));
  if (!list.length) {
    root.innerHTML = `<div class="empty-state"><div class="empty-graphic">⌑</div><h3>${state.items.length ? "No matches just yet." : "Your vault is ready."}</h3><p>${state.items.length ? "Try a different search or category filter." : "Add your first login. It will be encrypted in your browser before it is saved."}</p>${state.items.length ? "" : '<button class="button button-primary" data-action="add">＋ Add your first password</button>'}</div>`;
    return;
  }
  root.innerHTML = list.map(({ id, data }) => {
    const strength = scorePassword(data.password);
    return `<article class="credential-row" data-id="${escapeHtml(id)}"><div class="site-mark">${escapeHtml(initials(data.site))}</div><div class="entry-main"><div class="entry-title">${escapeHtml(data.site)}</div><div class="entry-sub">${escapeHtml(data.username || data.url || "Saved login")}</div></div><span class="entry-category">${escapeHtml(data.category || "Other")}</span><span class="entry-strength"><i class="strength-dot ${strength.tone}"></i>${strength.label}</span><div class="row-actions"><button class="small-icon-button" data-action="view" title="View details" aria-label="View ${escapeHtml(data.site)}">View</button><button class="small-icon-button" data-action="edit" title="Edit entry" aria-label="Edit ${escapeHtml(data.site)}">Edit</button></div></article>`;
  }).join("");
}
function toast(message, type = "") {
  const node = document.createElement("div");
  node.className = `toast ${type}`;
  node.textContent = message;
  $("#toast-region").append(node);
  setTimeout(() => node.remove(), 2700);
}
function showVault() {
  state.key = null;
  state.items = [];
  $("#app").classList.add("hidden");
  $("#gate").classList.remove("hidden");
  $("#gate-title").textContent = "Welcome back.";
  $("#gate-copy").textContent = "Unlock this vault with your master password. It never leaves your browser.";
  $("#gate-submit").textContent = "Unlock vault";
  $("#master-password").value = "";
  $("#master-password").autocomplete = "current-password";
  $("#confirm-wrap").classList.add("hidden-field");
  setTimeout(() => $("#master-password").focus(), 0);
}
function setView(view) {
  state.view = view;
  $("#vault-view").classList.toggle("hidden", view !== "vault");
  $("#project-view").classList.toggle("hidden", view !== "project");
  $$(".nav-link[data-view]").forEach((button) => button.classList.toggle("active", button.dataset.view === view));
  $("#breadcrumb-current").textContent = view === "vault" ? "My vault" : "Project overview";
  location.hash = view === "vault" ? "vault" : "project";
}
function generatePassword(length = 20) {
  const alphabet = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789!@#$%&*+-=?";
  let result = "";
  const ceiling = Math.floor(256 / alphabet.length) * alphabet.length;
  while (result.length < length) {
    for (const value of randomBytes(length * 2)) if (value < ceiling && result.length < length) result += alphabet[value % alphabet.length];
  }
  return result;
}
function openEntryForm(existing = null) {
  const edit = Boolean(existing);
  $("#modal-root").innerHTML = `<div class="modal-backdrop" data-backdrop><section class="modal-card" role="dialog" aria-modal="true" aria-labelledby="modal-title"><div class="modal-head"><div><h2 id="modal-title">${edit ? "Edit password" : "New password"}</h2><p>${edit ? "Your updated details will be re-encrypted." : "Details are encrypted before they are saved."}</p></div><button class="close-button" data-action="close" aria-label="Close">×</button></div><form id="entry-form" class="modal-form"><label class="field-span">Website or service *<input name="site" required maxlength="100" placeholder="e.g. Study Portal" value="${escapeHtml(existing?.data.site || "")}" /></label><label>Username or email<input name="username" maxlength="160" placeholder="you@example.com" value="${escapeHtml(existing?.data.username || "")}" /></label><label>Category<select name="category">${["Social", "Work", "Finance", "Shopping", "Entertainment", "Other"].map((x) => `<option${(existing?.data.category || "Other") === x ? " selected" : ""}>${x}</option>`).join("")}</select></label><label class="field-span">Password *<div class="input-with-action"><input id="entry-password" name="password" required maxlength="500" autocomplete="new-password" placeholder="Choose or generate one" value="${escapeHtml(existing?.data.password || "")}" /><button type="button" data-action="generate">Generate</button></div></label><div class="strength-check"><div class="strength-track"><span id="strength-fill"></span></div><div id="strength-caption" class="strength-caption">Password strength</div></div><label class="field-span">Website URL<input name="url" type="url" maxlength="500" placeholder="https://example.com" value="${escapeHtml(existing?.data.url || "")}" /></label><label class="field-span">Notes <span class="muted">(optional)</span><textarea name="notes" maxlength="1000" placeholder="Helpful details, encrypted with this entry">${escapeHtml(existing?.data.notes || "")}</textarea></label><div class="field-span form-actions"><button class="button button-secondary" type="button" data-action="close">Cancel</button><button class="button button-primary" type="submit">${edit ? "Save changes" : "Save to vault"}</button></div></form></section></div>`;
  const form = $("#entry-form");
  const passField = $("#entry-password");
  const updateStrength = () => {
    const result = scorePassword(passField.value);
    $("#strength-caption").textContent = result.label;
    $("#strength-fill").style.width = `${Math.max(0, result.score / 6 * 100)}%`;
    $("#strength-fill").style.background = result.tone === "strong" ? "#58b58b" : result.tone === "medium" ? "#e9b95f" : "#dc816d";
  };
  passField.addEventListener("input", updateStrength);
  updateStrength();
  passField.focus();
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const button = $("button[type=submit]", form);
    button.disabled = true;
    try {
      const formData = new FormData(form);
      const data = Object.fromEntries(formData.entries());
      const encrypted = await encryptText(JSON.stringify(data));
      if (edit) {
        await api(`/items/${encodeURIComponent(existing.id)}`, { method: "PUT", body: JSON.stringify(encrypted) });
        toast("Password updated.");
      } else {
        await api("/items", { method: "POST", body: JSON.stringify(encrypted) });
        toast("Password encrypted and saved.");
      }
      closeModal();
      await loadItems(); updateStats(); renderEntries();
    } catch (error) { toast(error.message, "error"); button.disabled = false; }
  });
}
function closeModal() { $("#modal-root").innerHTML = ""; }
function openDetails(item) {
  const data = item.data;
  let revealed = false;
  $("#modal-root").innerHTML = `<div class="modal-backdrop" data-backdrop><section class="modal-card modal-small" role="dialog" aria-modal="true" aria-labelledby="detail-title"><div class="modal-head"><div><h2 id="detail-title">${escapeHtml(data.site)}</h2><p>${escapeHtml(data.category || "Other")}${data.url ? ` · ${escapeHtml(data.url)}` : ""}</p></div><button class="close-button" data-action="close" aria-label="Close">×</button></div><div class="detail-fields"><div class="detail-field"><label>USERNAME / EMAIL</label><div class="detail-value"><span>${escapeHtml(data.username || "Not set")}</span><button data-action="copy-user">Copy</button></div></div><div class="detail-field"><label>PASSWORD</label><div class="detail-value"><span id="detail-password" class="password-dots">••••••••••••</span><button data-action="reveal">Reveal</button><button data-action="copy-password">Copy</button></div></div>${data.notes ? `<div class="detail-field"><label>NOTES</label><div class="detail-value"><span>${escapeHtml(data.notes)}</span></div></div>` : ""}<div class="form-actions"><button class="button button-danger" data-action="delete">Delete</button><button class="button button-secondary" data-action="edit">Edit entry</button><button class="button button-primary" data-action="close">Done</button></div></div></section></div>`;
  $("[data-action=reveal]").addEventListener("click", (event) => {
    revealed = !revealed;
    $("#detail-password").textContent = revealed ? data.password : "••••••••••••";
    event.currentTarget.textContent = revealed ? "Hide" : "Reveal";
    $("#detail-password").classList.toggle("password-dots", !revealed);
  });
  $("[data-action=copy-user]").addEventListener("click", () => copyText(data.username || "", "Username copied."));
  $("[data-action=copy-password]").addEventListener("click", () => copyText(data.password, "Password copied."));
  $("#modal-root [data-action=edit]").addEventListener("click", () => { closeModal(); openEntryForm(item); });
  $("[data-action=delete]").addEventListener("click", async () => {
    if (!confirm(`Delete the saved login for ${data.site}? This cannot be undone.`)) return;
    try { await api(`/items/${encodeURIComponent(item.id)}`, { method: "DELETE" }); closeModal(); await loadItems(); updateStats(); renderEntries(); toast("Entry deleted."); }
    catch (error) { toast(error.message, "error"); }
  });
}
async function copyText(value, message) {
  if (!value) return toast("Nothing to copy.", "error");
  try { await navigator.clipboard.writeText(value); toast(message); }
  catch { toast("Clipboard unavailable. Select and copy manually.", "error"); }
}
function bindEvents() {
  $("#add-entry").addEventListener("click", () => openEntryForm());
  $("#add-first").addEventListener("click", () => openEntryForm());
  $("#entries-list").addEventListener("click", (event) => {
    const action = event.target.closest("[data-action]")?.dataset.action;
    if (action === "add") return openEntryForm();
    const row = event.target.closest("[data-id]");
    if (!row) return;
    const item = state.items.find((entry) => entry.id === row.dataset.id);
    if (!item) return;
    if (action === "edit") openEntryForm(item); else openDetails(item);
  });
  $("#search-input").addEventListener("input", (event) => { state.search = event.target.value; renderEntries(); });
  $("#category-filter").addEventListener("change", (event) => { state.filter = event.target.value; renderEntries(); });
  $("#lock-button").addEventListener("click", showVault);
  $("#top-lock").addEventListener("click", showVault);
  $$(".nav-link[data-view]").forEach((button) => button.addEventListener("click", () => setView(button.dataset.view)));
  $(".notice-close").addEventListener("click", (event) => event.currentTarget.closest(".notice").remove());
  $("#modal-root").addEventListener("click", (event) => {
    if (event.target.matches("[data-backdrop]") || event.target.closest('[data-action="close"]')) return closeModal();
    if (event.target.closest('[data-action="generate"]')) {
      const input = $("#entry-password");
      input.value = generatePassword();
      input.dispatchEvent(new Event("input", { bubbles: true }));
    }
  });
  document.addEventListener("keydown", (event) => {
    if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k") { event.preventDefault(); $("#search-input").focus(); }
    if (event.key === "Escape") closeModal();
  });
  if (location.hash === "#project") setView("project");
}

bindEvents();
initialize();
