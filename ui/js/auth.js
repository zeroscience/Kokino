// Sign-in, first-admin setup and password change screens.
//
// They render into the #auth overlay above the app shell, so an expired
// session can be renewed in place without losing the examiner's route.

import { api, h, icon, spring } from "./lib.js";

const root = () => document.getElementById("auth");

export const authOpen = () => root().classList.contains("open");

function card(info, ...body) {
  const c = h("form.card.auth-card", { autocomplete: "on", onsubmit: (e) => e.preventDefault() },
    h("div.auth-brand", h("span.eyes", { role: "img", "aria-label": "Kokino logo: detail of a painting by Siebe Boersma", style: { width: "56px", height: "56px" } }),
      h("div", h("span.wordmark", { role: "img", "aria-label": "Kokino Forensic Toolkit", style: { width: "170px" } }, h("i.wm-main"), h("i.wm-sub"), h("i.wm-acc")), h("small.auth-tag", "Every finding, traceable to the byte."))),
    ...body,
    h("div.auth-foot", transport(info), h("span.sp"), h("span.muted", info ? "v" + info.version : "")),
  );
  root().replaceChildren(c);
  root().classList.add("open");
  root().setAttribute("aria-hidden", "false");
  document.body.classList.add("locked");
  const first = c.querySelector("input:not([value]), input");
  if (first) setTimeout(() => first.focus(), 60);
  return c;
}

function transport(info) {
  const local = ["127.0.0.1", "localhost", "[::1]"].includes(location.hostname);
  if (info && info.tls) return h("span.auth-tls.ok", icon("lock", 13), "Encrypted connection (TLS)");
  if (local) return h("span.auth-tls", icon("shield", 13), "Local connection, this machine only");
  return h("span.auth-tls.bad", icon("alert", 13), "Unencrypted connection");
}

export function closeAuth() {
  const r = root();
  r.classList.remove("open");
  r.setAttribute("aria-hidden", "true");
  document.body.classList.remove("locked");
  setTimeout(() => { if (!authOpen()) r.replaceChildren(); }, 450);
}

function fail(c, box, msg) {
  box.textContent = msg;
  box.classList.add("show");
  c.classList.remove("shake");
  void c.offsetWidth;
  c.classList.add("shake");
}

function busy(btn, on, label) {
  btn.disabled = on;
  btn.replaceChildren(on ? h("span.spin.sm") : "", label);
}

/** Rough strength: length dominates, character variety helps. 0..1 */
function strength(p) {
  if (!p) return 0;
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((r) => r.test(p)).length;
  return Math.min(1, (p.length / 20) * 0.75 + classes * 0.0625 + (p.length >= 12 ? 0.1 : 0));
}

function meter(input) {
  const bar = h("i");
  const label = h("span.muted");
  let cur = 0;
  const draw = () => {
    const s = strength(input.value);
    const words = input.value.length < 12 ? `${12 - input.value.length} more characters needed` : s < 0.7 ? "acceptable" : "strong";
    label.textContent = input.value ? words : "At least 12 characters. A passphrase works well.";
    bar.style.background = input.value.length < 12 ? "var(--bad)" : s < 0.7 ? "var(--warn)" : "var(--ok)";
    spring(cur, s, (v) => { cur = v; bar.style.width = Math.max(0, Math.min(1, v)) * 100 + "%"; }, { stiffness: 170, damping: 20 });
  };
  input.addEventListener("input", draw);
  draw();
  return h("div.meter-wrap", h("div.meter", bar), label);
}

export function loginScreen(info, onDone, notice) {
  const user = h("input", { name: "username", autocomplete: "username", autocapitalize: "off", spellcheck: "false", required: true });
  const pass = h("input", { name: "password", type: "password", autocomplete: "current-password", required: true });
  const err = h("div.auth-err", { role: "alert" });
  const btn = h("button.primary.wide", { type: "submit" }, "Sign in");
  const c = card(info,
    h("h1", "Sign in"),
    h("p.muted", notice || "Use the account your Kokino administrator gave you."),
    h("label", "Username", user),
    h("label", "Password", pass),
    err,
    btn,
  );
  c.onsubmit = async (e) => {
    e.preventDefault();
    busy(btn, true, "Signing in");
    try {
      const r = await api("/auth/login", { method: "POST", body: { username: user.value, password: pass.value }, quiet: true });
      pass.value = "";
      if (r.user.must_change_password) return passwordScreen(info, onDone, true);
      onDone(r.user);
    } catch (ex) {
      busy(btn, false, "Sign in");
      pass.value = "";
      fail(c, err, ex.message);
      pass.focus();
    }
  };
  if (notice) user.focus();
}

export function setupScreen(info, token, onDone) {
  const tok = h("input.mono", { value: token || "", autocomplete: "off", spellcheck: "false" });
  const user = h("input", { autocomplete: "username", autocapitalize: "off", spellcheck: "false", placeholder: "e.g. jdoe" });
  const disp = h("input", { autocomplete: "name", placeholder: "e.g. Jane Doe" });
  const pass = h("input", { type: "password", autocomplete: "new-password" });
  const again = h("input", { type: "password", autocomplete: "new-password" });
  const err = h("div.auth-err", { role: "alert" });
  const btn = h("button.primary.wide", { type: "submit" }, "Create admin account");
  const c = card(info,
    h("h1", "Welcome"),
    h("p.muted", "No accounts exist yet. Create the first administrator. Admins add examiners and reviewers and assign them to cases."),
    token ? null : h("label", "Setup token (printed by kokino serve)", tok),
    h("div.grid.g2", h("label", "Username", user), h("label", "Display name", disp)),
    h("label", "Password", pass),
    meter(pass),
    h("label", "Repeat password", again),
    err,
    btn,
  );
  c.onsubmit = async (e) => {
    e.preventDefault();
    if (pass.value !== again.value) return fail(c, err, "The passwords do not match.");
    busy(btn, true, "Creating account");
    try {
      const r = await api("/auth/setup", { method: "POST", body: { token: tok.value.trim(), username: user.value, display_name: disp.value, password: pass.value }, quiet: true });
      onDone(r.user);
    } catch (ex) {
      busy(btn, false, "Create admin account");
      fail(c, err, ex.message);
    }
  };
}

/** forced: shown after an admin reset; there is no way around it but signing out. */
export function passwordScreen(info, onDone, forced, onCancel) {
  const cur = h("input", { type: "password", autocomplete: "current-password" });
  const pass = h("input", { type: "password", autocomplete: "new-password" });
  const again = h("input", { type: "password", autocomplete: "new-password" });
  const err = h("div.auth-err", { role: "alert" });
  const btn = h("button.primary.wide", { type: "submit" }, "Change password");
  const cancel = forced
    ? h("button.ghost.wide", { type: "button", onclick: async () => { await api("/auth/logout", { method: "POST", quiet: true }).catch(() => {}); loginScreen(info, onDone); } }, "Sign out")
    : h("button.ghost.wide", { type: "button", onclick: () => { closeAuth(); if (onCancel) onCancel(); } }, "Cancel");
  const c = card(info,
    h("h1", forced ? "Choose your password" : "Change password"),
    h("p.muted", forced ? "Your password was set by an administrator. Choose your own before you continue." : "Other sessions of your account are signed out when the password changes."),
    h("label", forced ? "Temporary password" : "Current password", cur),
    h("label", "New password", pass),
    meter(pass),
    h("label", "Repeat new password", again),
    err,
    btn,
    cancel,
  );
  c.onsubmit = async (e) => {
    e.preventDefault();
    if (pass.value !== again.value) return fail(c, err, "The new passwords do not match.");
    busy(btn, true, "Saving");
    try {
      await api("/auth/password", { method: "POST", body: { current: cur.value, new: pass.value }, quiet: true });
      onDone();
    } catch (ex) {
      busy(btn, false, "Change password");
      fail(c, err, ex.message);
    }
  };
}
