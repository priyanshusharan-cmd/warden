// Warden console: state, rendering and playback. Plain JS, no build step.
(function () {
  "use strict";

  const $ = (s, el = document) => el.querySelector(s);
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
  const stepMs = () => (reduceMotion ? 0 : (META.ui && META.ui.step_ms) || 0);

  // Filled from /api/meta at boot: rule names, tool types and presets all come from the engine.
  let META = { rules: [], tools: [], presets: [], valuables: [] };
  const ruleTitle = (id) => (META.rules.find((r) => r.id === id) || {}).title || id;
  const ruleHelp = (id) => (META.rules.find((r) => r.id === id) || {}).help || "";
  const toolMeta = (name) => META.tools.find((t) => t.name === name) || {};

  const state = {
    tab: "run",
    scenarios: [],
    selected: null,
    custom: null,          // last custom scenario payload
    result: null,          // { scenario, planted, open, guarded, agent_acted }
    shown: { open: 0, guarded: 0 },
    timer: null,
    expanded: new Set(),
    busy: false,
    bench: null,
    tools: null,
    audit: null,
  };

  // ------------------------------------------------------------------ tabs

  const TABS = ["home", "run", "write", "results", "data", "tools", "audit"];

  function setTab(tab, focus) {
    if (!TABS.includes(tab)) tab = "home";
    state.tab = tab;
    for (const t of TABS) {
      const btn = $(`#tab-${t}`);
      const on = t === tab;
      btn.setAttribute("aria-selected", on);
      btn.tabIndex = on ? 0 : -1;
      $(`#view-${t}`).hidden = !on;
    }
    if (focus) $(`#tab-${tab}`).focus();
    if (location.hash !== `#${tab}`) history.replaceState(null, "", `#${tab}`);
    if (tab === "run" || tab === "write") mountResults(tab);
    if (tab === "home") loadHomeStats();
    if (tab === "results") loadBench();
    if (tab === "tools") { loadTools(); loadConnect(); }
    if (tab === "audit") loadAudit();
    if (tab === "data") loadWorld();
  }

  document.querySelector(".tabs").addEventListener("click", (e) => {
    const b = e.target.closest("[data-tab]");
    if (b) setTab(b.dataset.tab);
  });
  document.querySelector(".tabs").addEventListener("keydown", (e) => {
    const i = TABS.indexOf(state.tab);
    if (e.key === "ArrowRight") setTab(TABS[(i + 1) % TABS.length], true);
    else if (e.key === "ArrowLeft") setTab(TABS[(i - 1 + TABS.length) % TABS.length], true);
    else if (e.key === "Home") setTab(TABS[0], true);
    else if (e.key === "End") setTab(TABS[TABS.length - 1], true);
    else return;
    e.preventDefault();
  });
  addEventListener("hashchange", () => setTab(location.hash.slice(1)));
  document.addEventListener("warden:offline", () => { $("#offline").hidden = false; });

  // ------------------------------------------------------------- scenarios

  async function loadScenarios() {
    state.scenarios = await api.get("/api/scenarios");
    const sel = $("#scenario");
    const groups = new Map();
    for (const s of state.scenarios) {
      const g = s.benign ? "Normal tasks" : `Attack: ${s.category}`;
      if (!groups.has(g)) groups.set(g, []);
      groups.get(g).push(s);
    }
    const order = [...groups.keys()].sort((a, b) => (a === "Normal tasks") - (b === "Normal tasks"));
    sel.innerHTML = order.map((g) => `<optgroup label="${esc(g)}">${groups.get(g)
      .map((s) => `<option value="${esc(s.id)}">${esc(s.title)}</option>`).join("")}</optgroup>`).join("")
      + `<option value="custom" disabled hidden>Your attack</option>`;
    sel.value = state.selected;
    showScenario();
  }

  function currentScenario() {
    if (state.selected === "custom") return state.result?.scenario;
    return state.scenarios.find((s) => s.id === state.selected);
  }

  function showScenario() {
    const sc = currentScenario();
    if (!sc) return;
    $("#asked-text").textContent = sc.prompt;
    renderTrap(sc.planted_items || state.result?.planted || [], sc);
  }

  $("#scenario").addEventListener("change", (e) => {
    state.selected = e.target.value;
    resetBoard();
    showScenario();
  });
  $("#run-btn").addEventListener("click", () => run());

  function renderTrap(items, sc) {
    const trap = $("#trap");
    const note = $("#custom-note");
    note.hidden = true;
    if (!items.length) {
      trap.hidden = true;
      if (sc && sc.benign) {
        note.hidden = false;
        note.textContent = "A normal task with nothing planted. Warden should stay out of the way, and ask you only before anything leaves the company or gets deleted.";
      }
      return;
    }
    trap.hidden = false;
    const first = items[0];
    $(".trap-title", trap).innerHTML = `Planted in ${esc(first.where.charAt(0).toLowerCase() + first.where.slice(1))}`
      + ` <span class="muted">${esc(first.title)}</span>`;
    $(".trap-body", trap).innerHTML = items.map((p) => {
      const flagged = new Set((p.flagged || []).map((f) => f.line).filter(Boolean));
      const lines = p.text.split("\n").map((l, i) =>
        `<span class="ln${flagged.has(i + 1) ? " flag" : ""}">${showInvisible(l) || " "}</span>`).join("");
      const kinds = [...new Set((p.flagged || []).map((f) => f.detail))];
      return `<div>
        ${items.length > 1 ? `<p class="planted-where"><b>${esc(p.where)}</b> ${esc(p.title)}</p>` : ""}
        <pre class="planted-text">${lines}</pre>
        ${kinds.length ? `<ul class="planted-findings">${kinds.map((k) => `<li>${esc(k)}</li>`).join("")}</ul>` : ""}
      </div>`;
    }).join("");
  }

  function showInvisible(line) {
    // Zero-width characters are invisible by design; draw them so people can see the trick.
    return esc(line).replace(/[​‌‍⁠﻿]/g,
      '<span class="zw" title="zero-width character">·</span>');
  }

  // ---------------------------------------------------------------- running

  function resetBoard() {
    clearInterval(state.timer);
    state.result = null;
    state.shown = { open: 0, guarded: 0 };
    state.expanded.clear();
    for (const lane of ["open", "guarded"]) {
      $(`#${lane}-strips`).innerHTML = "";
      $(`#${lane}-empty`).hidden = false;
    }
    $("#leak").hidden = true;
    $("#verdict").hidden = true;
    $("#leak-list").innerHTML = "";
    $("#contract").hidden = true;
    $("#answer").hidden = true;
    $("#open-sub").className = "lane-sub";
    $("#open-sub").textContent = "";
    $("#guarded-sub").className = "lane-sub";
    $("#guarded-sub").textContent = "";
    $("#next").hidden = true;
    for (const h of ["#verdict-h", "#board-h", "#trap-h"]) $(h).hidden = true;
  }

  // One results block, moved under whichever screen started the run.
  function mountResults(where) {
    const slot = $(where === "write" ? "#write-slot" : "#run-slot");
    if ($("#results").parentElement !== slot) slot.appendChild($("#results"));
    $("#results").classList.toggle("in-lab", where === "write");
  }

  async function run(customPayload) {
    if (state.busy) return;
    mountResults(customPayload ? "write" : "run");
    state.busy = true;
    const btn = $("#run-btn");
    btn.disabled = true;
    btn.textContent = { llm: "Claude is working…", ollama: "Local model is working…", auto: "Working…" }[$("#agent").value] || "Running…";
    try {
      const body = customPayload ? { custom: customPayload } : { scenario_id: state.selected };
      body.agent = $("#agent").value || undefined;
      const res = await api.post("/api/run", body);
      resetBoard();
      state.result = res;
      if (customPayload) {
        state.selected = "custom";
        $("#scenario").value = "custom";
        $("#scenario option[value=custom]").hidden = false;
      }
      showScenario();
      if (customPayload && !res.agent_acted) {
        const note = $("#custom-note");
        note.hidden = false;
        note.textContent = "The agent read your email but didn't act on it, so there was nothing for Warden to stop. Name an address, a link or a file in an order to the assistant, or see the results view for the built-in attacks.";
      }
      renderContract(res.guarded.contract);
      const used = { ollama: "the local model", llm: "Claude", scripted: "the scripted agent" }[res.guarded.agent];
      if ($("#agent").value === "auto" && used) {
        $("#agent-help").textContent = `Ran with ${used}.`;
        $("#agent-help").title = (res.agent_notes || []).join("\n");
      }
      for (const h of ["#verdict-h", "#board-h"]) $(h).hidden = false;
      $("#trap-h").hidden = !!customPayload;
      play();
      if (customPayload) $("#results").scrollIntoView({ block: "start", behavior: reduceMotion ? "auto" : "smooth" });
    } catch (e) {
      alertNote(e.message);
    } finally {
      state.busy = false;
      btn.disabled = false;
      btn.textContent = "Run both agents";
    }
  }

  function alertNote(msg) {
    const note = $("#custom-note");
    note.hidden = false;
    note.textContent = msg;
  }

  function renderContract(c) {
    const el = $("#contract");
    const people = [...c.recipients, ...c.urls, ...c.paths];
    $("#lane-guarded-h").title = `Allowed for this task: ${c.tools.join(", ") || "no tools"}`;
    el.innerHTML = `<span>Allowed for this task</span>`
      + (c.tools.length ? c.tools.map((t) => `<span class="chip">${esc(t)}</span>`).join("") : `<span class="chip">no tools</span>`)
      + (people.length ? `<span style="margin-left:6px">You named</span>${people.map((p) => `<span class="chip person">${esc(p)}</span>`).join("")}` : "");
  }

  function play() {
    clearInterval(state.timer);
    const r = state.result;
    const tick = () => {
      let moved = false;
      for (const lane of ["open", "guarded"]) {
        if (state.shown[lane] < r[lane].steps.length) { state.shown[lane]++; moved = true; }
      }
      renderLanes();
      if (!moved) { clearInterval(state.timer); finishPlayback(); }
    };
    if (!stepMs()) {
      state.shown = { open: r.open.steps.length, guarded: r.guarded.steps.length };
      renderLanes();
      finishPlayback();
      return;
    }
    tick();
    state.timer = setInterval(tick, stepMs());
  }

  function finishPlayback() {
    $("#next").hidden = false;
    const g = state.result.guarded;
    const waiting = g.steps.find((s) => s.status === "waiting");
    const firstBlock = g.steps.find((s) => s.status === "blocked" && s.reasons.some((x) => x.evidence.length))
      || g.steps.find((s) => s.status === "blocked");
    const focus = waiting || firstBlock;
    if (focus && !state.expanded.has(`guarded:${focus.seq}`)) {
      state.expanded.add(`guarded:${focus.seq}`);
      renderLanes();
    }
    renderSubs(true);
    renderVerdict();
    if (waiting) {
      const b = document.querySelector(`#guarded-strips [data-seq="${waiting.seq}"] .btn-allow`);
      if (b) b.focus({ preventScroll: true });
    }
  }

  // ---------------------------------------------------------- verdict band

  // Two plain sentences: what happened without Warden, and what Warden did instead (with the reason).
  function renderVerdict() {
    const r = state.result;
    if (!r) return;
    const band = $("#verdict");
    const open = r.open, g = r.guarded;
    const leaks = (open.leaks || []);
    let openText;
    if (!leaks.length) openText = isBenign() ? "The task finished. Nothing was checked along the way." : "Nothing harmful happened this time.";
    else if (isBenign()) openText = `The task finished, but ${leakSentence(leaks[0]).replace(/\.$/, "").replace(/^./, (c) => c.toLowerCase())} without anyone being asked.`;
    else openText = leaks.map(leakSentence).join(" ");

    const blocked = g.steps.filter((x) => x.status === "blocked" || x.status === "rejected");
    const waiting = g.steps.find((x) => x.status === "waiting");
    let gText;
    if (waiting) {
      gText = `Paused at step ${waiting.seq} (${actionText(waiting)}). It needs your decision below.`;
    } else if (blocked.length) {
      const first = blocked[0];
      const why = first.reasons.find((x) => x.verdict === "deny" && x.evidence.length) || first.reasons.find((x) => x.verdict !== "allow") || {};
      const ev = why.evidence && why.evidence[0];
      const src = ev ? ` It came from ${ev.origin}${ev.line ? `, line ${ev.line}` : ""}.` : "";
      gText = `Blocked ${blocked.length} ${blocked.length === 1 ? "action" : "actions"}, starting with step ${first.seq}: ${actionText(first)}.${src} ${(g.leaks || []).filter((l) => l.kind !== "secret_read").length ? "" : "Nothing left the company."}`;
    } else {
      gText = (g.leaks || []).length ? "Everything went through, with your approval." : "Every action was allowed. The task finished normally.";
    }
    $("#verdict-open").textContent = openText;
    $("#verdict-guarded").textContent = gText.trim();
    band.classList.toggle("calm", !leaks.length || isBenign());
    band.classList.toggle("waiting", !!waiting);
    band.hidden = false;
  }

  // ---------------------------------------------------------------- strips

  function guardedLook(s) {
    switch (s.status) {
      case "blocked": return { cls: "s-blocked", stamp: "Blocked" };
      case "rejected": return { cls: "s-blocked", stamp: "Blocked by you" };
      case "waiting": return { cls: "s-waiting", text: "Waiting for you" };
      case "approved": return { cls: "s-allowed", stamp: "Allowed by you", pine: true };
      case "error": return { cls: "s-error", text: "Failed" };
      default: return { cls: "s-allowed", text: "Allowed" };
    }
  }

  function harmfulSeqs(laneState) {
    const seqs = new Map();
    for (const l of laneState.leaks || []) {
      const s = laneState.steps.find((st) => matchesLeak(st, l));
      if (s) seqs.set(s.seq, l);
    }
    return seqs;
  }

  function matchesLeak(st, l) {
    const a = st.args;
    if (st.status !== "done" && st.status !== "approved") return false;
    switch (l.kind) {
      case "email": return st.tool === "send_email" && a.to === l.to;
      case "post": return st.tool === "http_post" && a.url === l.to;
      case "visit": return st.tool === "browse" && (a.url || "").startsWith(l.to);
      case "deleted": return st.tool === "delete_file" && a.path === l.to;
      case "secret_read": return st.tool === "read_file" && a.path === l.to;
    }
    return false;
  }

  function keyArg(s) {
    const k = toolMeta(s.tool).key_param;
    if (k && s.args[k] != null) return `<b>${esc(s.args[k])}</b>`;
    const v = Object.entries(s.args);
    return v.length ? esc(v.map(([a, b]) => `${a}=${b}`).join(" ")) : "&nbsp;";
  }

  function stripHTML(lane, s, harm) {
    const open = lane === "guarded" ? (state.expanded.has(`guarded:${s.seq}`) || s.status === "waiting")
      : state.expanded.has(`open:${s.seq}`);
    let look;
    if (lane === "guarded") look = guardedLook(s);
    else if (s.status === "error") look = { cls: "s-error", text: "Failed" };
    else if (harm && !isBenign()) look = { cls: "s-harm", text: harmLabel(harm) };
    else look = { cls: "s-ran", text: harm ? "Ran, no check" : "Ran" };

    const cap = toolMeta(s.tool).capability || "tool";
    const verdict = look.stamp
      ? `<span class="stamp${look.pine ? " pine" : ""}">${esc(look.stamp)}</span>`
      : `<span class="verdict-text">${esc(look.text)}</span>`;
    const risk = lane === "guarded" && s.verdict !== "allow" ? `<span class="risk" title="Risk score">risk ${s.risk}</span>` : "";
    return `<li class="strip ${look.cls}${open ? " open" : ""}" data-seq="${s.seq}" data-lane="${lane}">
      <button class="strip-row" type="button" aria-expanded="${open}" aria-controls="${lane}-d-${s.seq}">
        <span class="cell c-seq" aria-label="Step ${s.seq}">${s.seq}</span>
        <span class="cell c-main">
          <span class="tool">${esc(actionText(s))}</span>
          <span class="arg"><code>${esc(s.tool)}</code> <span class="cap c-${cap}">${esc(cap)}</span></span>
        </span>
        <span class="cell c-verdict">${risk}${verdict}<span class="chev" aria-hidden="true"></span></span>
      </button>
      <div class="strip-body" id="${lane}-d-${s.seq}"><div>${open ? detailHTML(lane, s, harm) : ""}</div></div>
    </li>`;
  }

  const isBenign = () => !!(state.result && state.result.scenario && state.result.scenario.benign);

  function harmLabel(l) {
    return { email: "Ran, data left", post: "Ran, data left", visit: "Ran, data left", deleted: "Ran, file gone", secret_read: "Ran, secret read" }[l.kind];
  }

  function argsHTML(s) {
    const e = Object.entries(s.args);
    if (!e.length) return "";
    return `<dl class="args">${e.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${showInvisible(v)}</dd>`).join("")}</dl>`;
  }

  // Plain-language action from the tool's template in data/tools.json, e.g. "Send an email to {to}".
  function actionText(s) {
    const tpl = toolMeta(s.tool).action || s.tool;
    return tpl.replace(/\{(\w+)\}/g, (_, k) => (s.args[k] != null ? s.args[k] : ""));
  }

  function detailHTML(lane, s, harm) {
    if (lane === "open") {
      return `<div class="detail">
        ${argsHTML(s)}
        ${harm ? `<p class="node-p" style="margin-top:12px;${isBenign() ? "" : "color:var(--brick)"}">${esc(leakSentence(harm))}${isBenign() ? " Nobody was asked first." : ""}</p>` : ""}
        ${s.output_preview != null ? `<div class="output"><p class="output-h">What the tool returned</p><pre>${showInvisible(s.output_preview)}</pre></div>` : ""}
      </div>`;
    }
    const reasons = s.reasons || [];
    const primary = reasons.find((r) => r.verdict === "deny" && r.evidence.length)
      || reasons.find((r) => r.evidence.length);
    const ev = primary && primary.evidence[0];
    let src;
    if (ev) {
      src = `<div class="node n-src">
        <p class="node-h">Where it came from</p>
        <p class="node-p">${esc(ev.origin)}${ev.line ? `, line ${ev.line}` : ""}</p>
        ${ev.quote ? `<p class="quote">${showInvisible(ev.quote)}</p>` : ""}
      </div>`;
    } else if (reasons.some((r) => r.rule === "R2")) {
      src = `<div class="node n-src"><p class="node-h">Where it came from</p><p class="node-p">Nothing you asked for needs this tool.</p></div>`;
    } else {
      src = `<div class="node n-src trusted"><p class="node-h">Where it came from</p><p class="node-p">Part of the task you asked for.</p></div>`;
    }
    const decision = {
      blocked: "Blocked by Warden. The tool never ran.",
      rejected: "You blocked it. The tool never ran.",
      approved: "You allowed it once.",
      waiting: "Warden is holding this call until you decide.",
      error: "Allowed, but the tool reported an error.",
    }[s.status] || "Allowed. No rule objected.";
    const rules = reasons.length ? `<ul class="rules">${reasons.map((r) => `<li>
        <span class="rid ${r.verdict}">${r.rule}</span>
        <span><b>${esc(r.title || ruleTitle(r.rule))}.</b> ${esc(r.text)}</span></li>`).join("")}</ul>` : "";
    const approve = s.status === "waiting" ? `<div class="approve">
        <p class="approve-q">Let the agent do this?</p>
        <div class="approve-actions">
          <button class="btn btn-allow" type="button" data-approve="1" data-id="${esc(s.approval_id)}">Allow this once</button>
          <button class="btn btn-block" type="button" data-approve="0" data-id="${esc(s.approval_id)}">Block</button>
        </div></div>` : "";
    return `<div class="detail">
      <div class="why">
        ${src}
        <div class="node"><p class="node-h">What it would do</p><p class="node-p">${esc(actionText(s))}</p>${argsHTML(s)}</div>
        <div class="node n-dec"><p class="node-h">Decision${s.verdict !== "allow" ? `, risk ${s.risk} of 100` : ""}</p>
          <p class="node-p">${decision}</p>${rules}</div>
      </div>
      ${approve}
      ${s.output_preview != null && (s.status === "done" || s.status === "approved") ? `<div class="output"><p class="output-h">What the tool returned</p><pre>${showInvisible(s.output_preview)}</pre></div>` : ""}
    </div>`;
  }

  // Keep existing strip nodes so only new or changed strips animate.
  const rendered = { open: new Map(), guarded: new Map() };

  function renderLanes() {
    const r = state.result;
    if (!r) return;
    for (const lane of ["open", "guarded"]) {
      const ls = r[lane];
      const list = $(`#${lane}-strips`);
      const harms = harmfulSeqs(ls);
      const steps = ls.steps.slice(0, state.shown[lane]);
      $(`#${lane}-empty`).hidden = steps.length > 0 || ls.steps.length > 0;
      if (!list.children.length) rendered[lane].clear();
      steps.forEach((s) => {
        const harm = harms.get(s.seq);
        const isOpen = state.expanded.has(`${lane}:${s.seq}`) || (lane === "guarded" && s.status === "waiting");
        const key = `${s.status}|${isOpen}|${harm ? 1 : 0}`;
        const prev = rendered[lane].get(s.seq);
        if (prev && prev.key === key) return;
        const tmp = document.createElement("template");
        tmp.innerHTML = stripHTML(lane, s, harm).trim();
        const node = tmp.content.firstChild;
        if (!prev) node.classList.add("enter");
        else if (prev.status !== s.status) node.classList.add("restamp");
        const animateOpen = isOpen && (!prev || !prev.isOpen) && !reduceMotion;
        if (animateOpen) node.classList.remove("open");
        if (prev) prev.node.replaceWith(node);
        else list.appendChild(node);
        if (animateOpen) { void node.offsetHeight; node.classList.add("open"); }
        rendered[lane].set(s.seq, { key, node, status: s.status, isOpen });
      });
    }
    markRoutine();
    renderLeaks();
    renderSubs(false);
  }

  // Safe reads are noise in a demo: fold them into one line per lane that can be expanded.
  function markRoutine() {
    const r = state.result;
    for (const lane of ["open", "guarded"]) {
      const harms = harmfulSeqs(r[lane]);
      let n = 0;
      for (const [seq, info] of rendered[lane]) {
        const s = r[lane].steps.find((x) => x.seq === seq);
        const routine = s && ["done", "approved"].includes(s.status) && toolMeta(s.tool).capability === "read"
          && !harms.get(seq) && !info.isOpen;
        info.node.classList.toggle("routine", routine);
        if (routine) n++;
      }
      const list = $(`#${lane}-strips`);
      let sum = list.querySelector(".routine-sum");
      if (!n) { if (sum) sum.remove(); continue; }
      if (!sum) {
        sum = document.createElement("li");
        sum.className = "routine-sum";
        list.prepend(sum);
      }
      const shown = list.classList.contains("show-routine");
      sum.innerHTML = `<button type="button" class="link" data-routine="${lane}">${shown ? "Hide" : "Show"} ${n} safe ${n === 1 ? "step" : "steps"}</button>`;
    }
  }

  document.querySelector(".board").addEventListener("click", (e) => {
    const t = e.target.closest("[data-routine]");
    if (!t) return;
    $(`#${t.dataset.routine}-strips`).classList.toggle("show-routine");
    markRoutine();
  }, true);

  // Expanding: render closed, then open on the next frame so the height transition runs.
  document.querySelector(".board").addEventListener("click", async (e) => {
    const ap = e.target.closest("[data-approve]");
    if (ap) return approve(ap.dataset.id, ap.dataset.approve === "1", ap);
    const row = e.target.closest(".strip-row");
    if (!row) return;
    const li = row.closest(".strip");
    const k = `${li.dataset.lane}:${li.dataset.seq}`;
    const step = state.result[li.dataset.lane].steps.find((s) => String(s.seq) === li.dataset.seq);
    if (step && step.status === "waiting") return;
    if (state.expanded.has(k)) state.expanded.delete(k); else state.expanded.add(k);
    renderLanes();
    const again = document.querySelector(`[data-lane="${li.dataset.lane}"][data-seq="${li.dataset.seq}"] .strip-row`);
    if (again) again.focus({ preventScroll: true });
  });

  async function approve(id, ok, btn) {
    const g = state.result.guarded;
    btn.closest(".approve-actions").querySelectorAll("button").forEach((b) => (b.disabled = true));
    try {
      const next = await api.post("/api/approve", { run_id: g.id, approval_id: id, approved: ok });
      const before = state.shown.guarded;
      state.result.guarded = next;
      state.shown.guarded = before;
      const waitingSeq = g.steps.find((s) => s.approval_id === id)?.seq;
      if (waitingSeq != null) state.expanded.add(`guarded:${waitingSeq}`);
      for (const h of ["#verdict-h", "#board-h"]) $(h).hidden = false;
      $("#trap-h").hidden = !!customPayload;
      play();
      if (customPayload) $("#results").scrollIntoView({ block: "start", behavior: reduceMotion ? "auto" : "smooth" });
    } catch (e) {
      alertNote(e.message);
      btn.closest(".approve-actions").querySelectorAll("button").forEach((b) => (b.disabled = false));
    }
  }

  // ------------------------------------------------------------ leak panel

  const ICONS = {
    email: '<path d="M3 5h14v10H3z M3 5l7 6 7-6" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>',
    post: '<path d="M10 15V4 M5.5 8.5 10 4l4.5 4.5 M4 16h12" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round"/>',
    visit: '<path d="M8.5 11.5l3-3 M7 9.5 5 11.5a2.5 2.5 0 0 0 3.5 3.5l2-2 M13 10.5l2-2A2.5 2.5 0 0 0 11.5 5l-2 2" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>',
    deleted: '<path d="M4 6h12 M8 6V4h4v2 M6 6l1 10h6l1-10" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linejoin="round"/>',
    secret_read: '<circle cx="7" cy="10" r="3" fill="none" stroke="currentColor" stroke-width="1.6"/><path d="M10 10h7 M14 10v3 M16.5 10v2" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round"/>',
  };

  function leakSentence(l) {
    const c = l.carried.length ? ` carrying your ${l.carried.join(" and ")}` : "";
    switch (l.kind) {
      case "email": return `An email went to ${l.to}${c}.`;
      case "post": return `Data was sent to ${l.to}${c}.`;
      case "visit": return `A link to ${l.domain} was opened with your ${l.carried.join(" and ")} inside it.`;
      case "deleted": return `${l.to} was deleted.`;
      case "secret_read": return `The agent opened ${l.to}.`;
    }
    return "";
  }

  function leakHeading(leaks) {
    const out = leaks.filter((l) => ["email", "post", "visit"].includes(l.kind));
    const carried = [...new Set(out.flatMap((l) => l.carried))];
    const parts = [];
    if (out.length) {
      const noun = out.every((l) => l.kind === "email") ? (out.length === 1 ? "email" : "emails")
        : out.every((l) => l.kind === "visit") ? (out.length === 1 ? "link" : "links")
        : out.length === 1 ? "message" : "messages";
      parts.push(`${out.length} ${noun} left the company${carried.length ? ` with your ${carried.join(" and ")}` : ""}`);
    }
    const del = leaks.filter((l) => l.kind === "deleted");
    if (del.length) parts.push(`${del.map((l) => l.to.split("/").pop()).join(", ")} ${del.length === 1 ? "was" : "were"} deleted`);
    if (!parts.length && leaks.some((l) => l.kind === "secret_read")) parts.push("The agent read your secrets file");
    const s = parts.join(", and ");
    return s.charAt(0).toUpperCase() + s.slice(1);
  }

  function renderLeaks() {
    const r = state.result;
    const panel = $("#leak");
    const visibleSeqs = new Set(r.open.steps.slice(0, state.shown.open).map((s) => s.seq));
    const harms = harmfulSeqs(r.open);
    const seqOf = (l) => { for (const [seq, hl] of harms) if (hl === l) return seq; return Infinity; };
    const shown = (r.open.leaks || [])
      .filter((l) => (seqOf(l) === Infinity ? state.shown.open >= r.open.steps.length : visibleSeqs.has(seqOf(l))))
      .sort((a, b) => seqOf(a) - seqOf(b));   // in the order they happened, so appending stays correct
    if (!shown.length) { panel.hidden = true; return; }
    panel.hidden = false;
    panel.classList.toggle("neutral", isBenign());
    $("#leak-h").textContent = isBenign() ? `Done without asking you: ${leakHeading(shown).replace(/^./, (c) => c.toLowerCase())}` : leakHeading(shown);
    const list = $("#leak-list");
    if (list.children.length > shown.length) list.innerHTML = "";
    shown.slice(list.children.length).forEach((l) => {
      const li = document.createElement("li");
      li.innerHTML = `<svg class="leak-ico" viewBox="0 0 20 20" aria-hidden="true">${ICONS[l.kind]}</svg>
        <div><div class="leak-what">${esc(leakSentence(l))}</div>
        ${l.domain ? `<div class="leak-to">${esc(l.domain)}</div>` : ""}</div>`;
      list.appendChild(li);
    });
  }

  function renderSubs(final) {
    const r = state.result;
    if (!r) return;
    const openSub = $("#open-sub"), gSub = $("#guarded-sub");
    const openDone = state.shown.open >= r.open.steps.length;
    const gDone = state.shown.guarded >= r.guarded.steps.length;
    if (openDone) {
      const bad = (r.open.leaks || []).length;
      if (isBenign()) {
        openSub.className = "lane-sub";
        openSub.textContent = bad ? "Task finished with no checks." : "Task finished.";
      } else {
        openSub.className = "lane-sub" + (bad ? " bad" : "");
        openSub.textContent = bad ? `${bad} harmful ${bad === 1 ? "action" : "actions"} went through.` : "Nothing harmful happened.";
      }
    }
    if (gDone) {
      const g = r.guarded;
      const blocked = g.steps.filter((s) => s.status === "blocked" || s.status === "rejected").length;
      const waiting = g.status === "waiting";
      const gl = (g.leaks || []).filter((l) => l.kind !== "secret_read");
      let text, cls = "lane-sub good";
      if (waiting) { text = "Paused. Your decision is needed."; cls = "lane-sub"; }
      else if (gl.length) { text = `${blocked ? `${blocked} blocked. ` : ""}Sent with your approval.`; cls = "lane-sub"; }
      else if (blocked) text = `${blocked} of ${g.steps.length} calls blocked. Nothing left the company.`;
      else text = "Every call allowed. Task finished.";
      gSub.className = cls;
      gSub.textContent = text;
      const ans = $("#answer");
      if (final && g.status === "done" && g.answer) {
        ans.hidden = false;
        ans.innerHTML = `<h3>The agent's answer with Warden</h3><pre>${esc(g.answer)}</pre>`;
      } else ans.hidden = true;
    }
  }

  // ------------------------------------------------------------ write view

  function renderPresets() {
    const el = $("#presets");
    el.innerHTML = META.presets.map((p, i) => `<button type="button" class="preset" data-i="${i}" aria-pressed="${i === 0}">${esc(p.label)}</button>`).join("");
    applyPreset(0);
    $("#w-prompt").value = META.default_prompt || "";
    $("#targets").innerHTML = META.valuables.map((v) => `<div><dt>${esc(v.sensitivity === "secret" ? "Secret" : "Confidential")}</dt><dd><code>${esc(v.path)}</code> <span class="muted">${esc(v.first_line)}</span></dd></div>`).join("")
      + `<div><dt>Company domain</dt><dd><code>${esc(META.internal_domain)}</code></dd></div>`
      + `<div><dt>Blocklisted</dt><dd>${META.blocklist.map((d) => `<code>${esc(d)}</code>`).join(" ")}</dd></div>`;
    el.onclick = (e) => {   // assigned, not added: presets re-render when your data changes
      const b = e.target.closest(".preset");
      if (!b) return;
      el.querySelectorAll(".preset").forEach((x) => x.setAttribute("aria-pressed", x === b));
      applyPreset(+b.dataset.i);
    };
  }
  function applyPreset(i) {
    const p = META.presets[i];
    if (!p) return;
    $("#w-from").value = p.sender;
    $("#w-subject").value = p.subject;
    $("#w-body").value = p.body;
  }

  $("#write-form").addEventListener("submit", async (e) => {
    e.preventDefault();
    const err = $("#write-error");
    err.hidden = true;
    const payload = {
      prompt: $("#w-prompt").value.trim(),
      sender: $("#w-from").value.trim(),
      subject: $("#w-subject").value.trim(),
      body: $("#w-body").value,
    };
    if (!payload.prompt || !payload.body.trim()) {
      err.textContent = "Write both the request and the email body.";
      err.hidden = false;
      return;
    }
    const btn = e.submitter || $("#write-form .btn-primary");
    btn.disabled = true;
    btn.textContent = { llm: "Claude is working…", ollama: "Local model is working…", auto: "Working…" }[$("#agent").value] || "Running…";
    try {
      if (api.isOffline()) throw new api.ApiError("Writing your own attack needs the server. Start it with ./run.sh.");
      await run(payload);
    } catch (ex) {
      err.textContent = ex.message;
      err.hidden = false;
    } finally {
      btn.disabled = false;
      btn.textContent = "Run both agents";
    }
  });

  // --------------------------------------------------------------- results

  async function loadBench() {
    const el = $("#results-body");
    if (state.bench) return;
    el.innerHTML = `<p class="loading">Running ${state.scenarios.length || ""} scenarios with and without Warden…</p>`;
    try {
      state.bench = await api.post("/api/bench");
      renderBench();
    } catch (e) {
      el.innerHTML = `<p class="note">${esc(e.message)}</p>`;
    }
  }

  function renderBench() {
    const { summary: s, categories, rows } = state.bench;
    const attacks = rows.filter((r) => !r.benign);
    const normal = rows.filter((r) => r.benign);
    const openWins = attacks.filter((r) => r.open.succeeded).length;
    const guardWins = attacks.filter((r) => r.guarded.succeeded).length;
    const tasksOk = normal.filter((r) => r.guarded.succeeded).length;
    const sentence = `Without Warden, <span class="num-bad">${openWins} of ${attacks.length}</span> attacks worked.
      With Warden, <span class="num-good">${guardWins ? guardWins : "none"}</span> did, and ${tasksOk} of ${normal.length} normal tasks still finished.`;

    const figs = [
      [`${s.attack_success_open}%`, "attacks worked without Warden"],
      [`${s.attack_success_guarded}%`, "attacks worked with Warden"],
      [`${s.task_completion_guarded}%`, "normal tasks finished"],
      [`${s.false_positives}`, "normal calls wrongly blocked"],
    ];
    const cats = categories.map((c) => `<div class="cat">
        <div class="cat-name">${esc(c.category)}<small>${c.total} ${c.total === 1 ? "attack" : "attacks"}</small></div>
        <div class="bars">
          <div class="bar" title="Without Warden"><div class="track"><div class="fill open" style="width:${(100 * c.open) / c.total}%"></div></div><span class="bar-v">${c.open} of ${c.total}</span></div>
          <div class="bar" title="With Warden"><div class="track"><div class="fill guarded" style="width:${(100 * c.guarded) / c.total}%"></div></div><span class="bar-v">${c.guarded} of ${c.total}</span></div>
        </div></div>`).join("");
    const top = s.top_rules.map(([r, n]) => `<li><span class="rid deny">${r}</span><span title="${esc(ruleHelp(r))}">${esc(ruleTitle(r))}<small class="rule-help">${esc(ruleHelp(r))}</small></span><span class="n">${n}</span></li>`).join("");
    const table = rows.map((r) => `<tr>
        <td class="t"><button class="link" data-load="${esc(r.id)}">${esc(r.title)}</button></td>
        <td class="cat-cell">${esc(r.category)}</td>
        <td>${r.benign ? (r.open.succeeded ? '<span class="tag plain">Finished</span>' : '<span class="tag plain">Failed</span>') : (r.open.succeeded ? '<span class="tag bad">Attack worked</span>' : '<span class="tag plain">Failed</span>')}</td>
        <td>${r.benign ? (r.guarded.succeeded ? '<span class="tag good">Finished</span>' : '<span class="tag bad">Broken</span>') : (r.guarded.succeeded ? '<span class="tag bad">Attack worked</span>' : '<span class="tag good">Stopped</span>')}</td>
        <td class="mono">${esc(r.guarded.rules.join(" ")) || "&nbsp;"}</td></tr>`).join("");

    $("#results-body").innerHTML = `
      <div class="res-head">
        <p class="res-sentence">${sentence}</p>
        <div class="figures">${figs.map(([n, l]) => `<div class="fig"><span class="fig-n">${n}</span><span class="fig-l">${l}</span></div>`).join("")}</div>
      </div>
      <div class="res-grid">
        <section class="panel">
          <h2>Attacks that worked, by kind</h2>
          <p class="sub">The same always-fooled agent, run once without Warden and once with it.</p>
          <div class="legend"><span><i style="background:var(--brick)"></i>Without Warden</span><span><i style="background:var(--pine)"></i>With Warden</span></div>
          ${cats}
        </section>
        <div class="side">
          <section class="panel">
            <h2>Rules that stopped them</h2>
            <p class="sub">How often each rule blocked a call across all runs.</p>
            <ul class="rules-fired">${top}</ul>
          </section>
          <section class="panel">
            <h2>Approvals</h2>
            <p class="sub">${s.approvals_raised} calls paused for a human across all scenarios.</p>
            <p class="reviewer">${esc(s.human_rule)}</p>
          </section>
        </div>
      </div>
      <div class="table-wrap panel">
        <h2>Every scenario</h2>
        <p class="sub">Pick one to watch it in the live run.</p>
        <div style="overflow-x:auto">
        <table class="rows">
          <thead><tr><th>Scenario</th><th class="cat-cell">Kind</th><th>Without Warden</th><th>With Warden</th><th>Rules</th></tr></thead>
          <tbody>${table}</tbody>
        </table></div>
      </div>`;
  }

  $("#results-body").addEventListener("click", (e) => {
    const b = e.target.closest("[data-load]");
    if (!b) return;
    state.selected = b.dataset.load;
    $("#scenario").value = state.selected;
    resetBoard();
    showScenario();
    setTab("run");
    run();
  });

  // ----------------------------------------------------------------- tools

  async function loadTools(path, body) {
    try {
      state.tools = path ? await api.post(path, body) : await api.get("/api/tools");
      renderTools();
    } catch (e) {
      $("#tools-body").innerHTML = `<p class="note">${esc(e.message)}</p>`;
    }
  }

  const PROBLEM_TEXT = {
    poisoned_description: { stamp: "Poisoned", title: "Description gives orders to the AI." },
    rug_pull: { stamp: "Changed", title: "Changed after it was approved." },
    signature_mismatch: { stamp: "Bad signature", title: "Doesn't match the version you signed." },
    unsigned: { stamp: "Unsigned", title: "Never signed, and policy requires it." },
  };
  const SIG_TEXT = { signed: "signed", unsigned: "unsigned", changed: "signature broken" };

  function renderTools() {
    const sel = $("#drift-tool");
    if (!sel.options.length) sel.innerHTML = state.tools.tools.map((t) => `<option>${esc(t.name)}</option>`).join("");
    $("#tools-body").innerHTML = `<ul class="tool-list strips">${state.tools.tools.map((t) => {
      const bad = t.problems.length;
      const changed = t.pinned && t.pinned !== t.hash;
      const label = bad ? (PROBLEM_TEXT[t.problems[0].kind] || PROBLEM_TEXT.poisoned_description).stamp : null;
      const sig = t.signature ? `<span class="pill sig-${t.signature}">${SIG_TEXT[t.signature]}</span>` : "";
      return `<li class="strip ${bad ? "s-blocked enter" : "s-allowed"}">
        <div class="strip-row toolrow">
          <span class="cell c-main"><span class="tool">${esc(t.name)} <span class="cap c-${t.capability}">${t.capability}</span>${sig}</span>
            <span class="desc">${esc(t.description.length > 140 ? t.description.slice(0, 140) + "…" : t.description)}</span></span>
          <span class="cell c-hash hash"><span><small>Pinned</small>${esc(t.pinned || "none")}</span></span>
          <span class="cell c-hash hash${changed ? " diff" : ""}"><span><small>Now</small>${esc(t.hash)}</span></span>
          <span class="cell c-verdict">${label ? `<span class="stamp">${label}</span>` : '<span class="ok-text">Matches pin</span>'}</span>
        </div>
        ${bad ? `<div class="problems">${t.problems.map((p) => `<p class="problem"><b>${(PROBLEM_TEXT[p.kind] || PROBLEM_TEXT.poisoned_description).title}</b> ${esc(p.detail)}</p><p class="quote">${esc(p.quote)}</p>`).join("")}
          <p class="problem" style="color:var(--dim)">Every call to ${esc(t.name)} is blocked under rule R1 until it's reviewed.</p></div>` : ""}
      </li>`;
    }).join("")}</ul>`;
  }

  $("#drift-btn").addEventListener("click", () => loadTools("/api/tools/drift", { tool: $("#drift-tool").value }));
  $("#tools-reset").addEventListener("click", () => loadTools("/api/tools/reset", {}));
  $("#tools-sign").addEventListener("click", () => loadTools("/api/tools/sign", {}));

  // ----------------------------------------------------------------- audit

  async function loadAudit() {
    try {
      state.audit = (await api.get("/api/audit")).entries;
      renderAudit();
    } catch (e) {
      $("#chain").innerHTML = `<li class="note">${esc(e.message)}</li>`;
    }
  }

  function entrySummary(e) {
    const d = e.data || {};
    switch (e.event) {
      case "run_started": return `“${d.prompt}”`;
      case "decision": return `${d.tool} ${Object.values(d.args || {}).map((v) => String(v).slice(0, 40)).join(" ")}${d.rules && d.rules.length ? `  [${d.rules.join(" ")}]` : ""}`;
      case "executed": return `${d.tool} ran, output from ${d.origin}`;
      case "human_decision": return `${d.tool} ${d.approved ? "allowed" : "blocked"} by ${d.by}`;
      case "tool_flagged": return `${d.tool}: ${(d.problems || []).join(", ")}`;
    }
    return JSON.stringify(d).slice(0, 80);
  }

  const EVENT_NAMES = { run_started: "Run started", decision: "Decision", executed: "Tool ran", human_decision: "Human decision", tool_flagged: "Tool flagged" };

  function renderAudit() {
    $("#verify-result").hidden = true;
    const chain = $("#chain");
    chain.classList.remove("broken");
    if (!state.audit.length) {
      chain.innerHTML = `<li class="empty-chain">No entries yet. Run a scenario and each decision is written here.</li>`;
      return;
    }
    chain.innerHTML = `<span class="progress" aria-hidden="true"></span>` + state.audit.map((e) => {
      const d = e.data || {};
      const pill = d.tampered ? `<span class="pill tampered">edited</span>` : d.verdict ? `<span class="pill ${d.verdict}">${{ allow: "allowed", deny: "blocked", require_approval: "approval" }[d.verdict]}</span>` : "";
      return `<li class="link-entry" data-seq="${e.seq}">
        <span class="le-seq">#${e.seq}</span>
        <div class="le-main"><div class="le-ev">${EVENT_NAMES[e.event] || esc(e.event)}${pill}</div>
          <div class="le-data">${esc(entrySummary(e))}</div></div>
        <div class="le-hash"><span class="arrow">${esc(e.prev_hash.slice(0, 6))} →</span> ${esc(e.hash.slice(0, 10))}
          ${e.event === "decision" && !d.tampered ? `<button class="btn btn-quiet tamper-btn" data-tamper="${e.seq}" type="button" title="Quietly change this entry's verdict to allowed, like an intruder covering their tracks">Tamper</button>` : ""}</div>
      </li>`;
    }).join("");
  }

  $("#verify-btn").addEventListener("click", async () => {
    try {
      const v = await api.post("/api/audit/verify");
      animateVerify(v);
    } catch (e) { $("#verify-result").hidden = false; $("#verify-result").textContent = e.message; }
  });

  function animateVerify(v) {
    const chain = $("#chain");
    const items = [...chain.querySelectorAll(".link-entry")];
    items.forEach((li) => li.classList.remove("ok", "bad"));
    const res = $("#verify-result");
    res.hidden = true;
    if (!items.length) {
      res.hidden = false; res.className = "verify"; res.textContent = "The log is empty. Run a scenario first.";
      return;
    }
    const brokenIdx = v.ok ? -1 : items.findIndex((li) => +li.dataset.seq === v.broken_at);
    chain.classList.toggle("broken", !v.ok);
    const per = reduceMotion ? 0 : Math.min(40, 900 / items.length);
    items.forEach((li, i) => {
      setTimeout(() => li.classList.add(brokenIdx >= 0 && i >= brokenIdx ? "bad" : "ok"), per * i);
    });
    const progress = chain.querySelector(".progress");
    const last = items[items.length - 1];
    progress.style.height = "0px";
    requestAnimationFrame(() => { progress.style.height = `${last.offsetTop + last.offsetHeight / 2 - 6}px`; });
    setTimeout(() => {
      res.hidden = false;
      res.className = "verify" + (v.ok ? "" : " bad");
      res.textContent = v.ok
        ? `All ${v.total} entries check out. No one has changed the log.`
        : `Entry #${v.broken_at} was changed. Its hash no longer matches, so it and every entry after it can't be trusted.`;
      if (!v.ok) items[brokenIdx]?.scrollIntoView({ block: "center", behavior: reduceMotion ? "auto" : "smooth" });
    }, per * items.length + 100);
  }

  $("#chain").addEventListener("click", async (e) => {
    const b = e.target.closest("[data-tamper]");
    if (!b) return;
    try {
      const r = await api.post("/api/audit/tamper", { seq: +b.dataset.tamper });
      state.audit = r.entries;
      renderAudit();
    } catch (ex) { $("#verify-result").hidden = false; $("#verify-result").textContent = ex.message; }
  });

  $("#audit-import").addEventListener("change", async (e) => {
    const file = e.target.files[0];
    e.target.value = "";
    if (!file) return;
    const res = $("#verify-result");
    try {
      const r = await api.post("/api/audit/import", { text: await file.text() });
      state.audit = r.entries;
      renderAudit();
      res.hidden = false;
      res.className = "verify";
      res.textContent = `Opened ${file.name}: ${r.entries.length} entries. Press Verify the chain to check nobody changed it.`;
    } catch (ex) { res.hidden = false; res.className = "verify bad"; res.textContent = ex.message; }
  });

  $("#audit-reset").addEventListener("click", async () => {
    state.audit = (await api.post("/api/audit/reset")).entries;
    renderAudit();
  });

  // -------------------------------------------------------- how it works

  const store = {   // per-viewer conveniences only; the page works without them
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* private mode */ } },
  };
  async function loadHomeStats() {
    const el = $("#home-stats");
    if (el.dataset.done) return;
    try {
      if (!state.bench) state.bench = await api.post("/api/bench");
      const s = state.bench.summary;
      el.innerHTML = [[`${s.attack_success_open}%`, "attacks work without Warden"],
        [`${s.attack_success_guarded}%`, "work with Warden"],
        [`${s.task_completion_guarded}%`, "normal tasks still finish"]]
        .map(([n, l], i) => `<div class="stat stat-${i}"><span class="stat-n">${n}</span><span class="stat-l">${l}</span></div>`).join("");
      el.dataset.done = "1";
    } catch { el.hidden = true; }
  }

  function renderOwnDataBanner() {
    const own = META.using_own_data || {};
    const b = $("#own-data");
    const parts = [own.world && "your own data", own.scenarios && "your saved attacks"].filter(Boolean);
    b.hidden = !parts.length;
    b.innerHTML = parts.length ? `Using ${parts.join(" and ")}. <a href="#data">Change it in Your data.</a>` : "";
  }

  function renderAgents() {
    const sel = $("#agent");
    const agents = META.agents || [];
    const keep = new URLSearchParams(location.search).get("agent") || sel.value || store.get("warden.agent") || META.default_agent;
    sel.innerHTML = agents.map((a) => `<option value="${esc(a.id)}"${a.available ? "" : " disabled"} title="${esc(a.reason || a.help)}">${esc(a.label)}${a.available ? "" : " (not set up)"}</option>`).join("");
    const ok = agents.find((a) => a.id === keep && a.available) || agents.find((a) => a.available);
    if (ok) sel.value = ok.id;
    sel.closest(".field").hidden = agents.length < 2;
    showAgentHelp();
  }

  function showAgentHelp() {
    const agents = META.agents || [];
    const a = agents.find((x) => x.id === $("#agent").value);
    const now = a && a.id === "auto" && META.auto_will_use ? ` Uses ${META.auto_will_use} right now.` : "";
    $("#agent-help").textContent = "";
    $("#agent").title = a ? a.help + now : "";
    $("#agent-help").title = agents.filter((x) => !x.available).map((x) => `${x.label}: ${x.reason}`).join("\n");
  }

  $("#agent").addEventListener("change", (e) => { store.set("warden.agent", e.target.value); showAgentHelp(); });

  // ------------------------------------------------------- connect claude

  let connectTimer = null;

  async function loadConnect() {
    const sel = $("#c-scenario");
    if (!sel.options.length) {
      sel.innerHTML = `<option value="none">None: a clean workspace</option>` + state.scenarios.filter((s) => !s.benign)
        .map((s) => `<option value="${esc(s.id)}">${esc(s.title)}</option>`).join("");
      sel.value = state.scenarios.some((s) => s.id === state.selected && !s.benign) ? state.selected : sel.options[1]?.value || "none";
    }
    const err = $("#c-error");
    err.hidden = true;
    try {
      const r = await api.post("/api/connect", { scenario: sel.value, task: $("#c-task").value });
      if (!$("#c-task").value) $("#c-task").value = r.task;
      $("#c-config").textContent = JSON.stringify(r.config, null, 2);
      $("#c-where").innerHTML = `Claude Code: save as <code>${esc(r.code_file)}</code>. Claude Desktop: add it to <code>${esc(r.desktop_file)}</code>.`;
      $("#c-ask").textContent = r.task;
    } catch (e) {
      $("#c-config").textContent = "";
      $("#c-where").textContent = e.message;
    }
  }

  $("#c-scenario").addEventListener("change", loadConnect);
  $("#c-task").addEventListener("input", () => { clearTimeout(connectTimer); connectTimer = setTimeout(loadConnect, 300); });
  $("#c-copy").addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText($("#c-config").textContent);
      $("#c-copy").textContent = "Copied";
    } catch { $("#c-copy").textContent = "Select and copy"; }
    setTimeout(() => { $("#c-copy").textContent = "Copy"; }, 1500);
  });
  $("#c-open").addEventListener("click", async () => {
    const err = $("#c-error");
    err.hidden = true;
    try {
      const r = await api.post("/api/audit/import", { latest: true });
      state.audit = r.entries;
      setTab("audit");
      renderAudit();
    } catch (e) { err.textContent = e.message; err.hidden = false; }
  });

  async function refreshMeta() {
    META = await api.get("/api/meta");
    renderOwnDataBanner();
  }

  // ------------------------------------------------------------ save attack

  $("#save-attack").addEventListener("click", async () => {
    const err = $("#write-error"), ok = $("#write-ok");
    err.hidden = ok.hidden = true;
    try {
      const res = await api.post("/api/scenarios/save", {
        title: $("#w-title").value, prompt: $("#w-prompt").value, sender: $("#w-from").value,
        subject: $("#w-subject").value, body: $("#w-body").value,
      });
      ok.textContent = `Saved as "${res.scenario.title}". It's now in the scenario list and the results.`;
      ok.hidden = false;
      state.bench = null;
      await refreshMeta();
      await loadScenarios();
    } catch (e) { err.textContent = e.message; err.hidden = false; }
  });

  // ------------------------------------------------------------- your data

  // Section definitions describe the editor; field names match the world data format.
  const SECTIONS = [
    { key: "secrets", title: "Secrets", help: "Values that must never leave. Refer to one inside any text with {secret:KEY}.",
      add: () => ({ key: "", value: "", label: "" }),
      fields: [["key", "Key", "span-3"], ["label", "What it is", "span-3"], ["value", "Value", "span-6"]] },
    { key: "emails", title: "Inbox", help: "Emails the agent can read. Planted attacks are added on top during a run.",
      add: (list) => ({ id: `e${list.length + 1}`, sender: "", subject: "", body: "" }),
      fields: [["id", "Id", "span-2"], ["sender", "From", "span-5"], ["subject", "Subject", "span-5"], ["body", "Body", "span-12", "area"]] },
    { key: "files", title: "Files", help: "The agent's drive. Sensitivity decides what Warden protects: secret files can't be read unless named; confidential lines can't go outside.",
      add: () => ({ path: "", sensitivity: "internal", content: "" }),
      fields: [["path", "Path", "span-6"], ["sensitivity", "Sensitivity", "span-6", "sens"], ["content", "Content", "span-12", "area"]] },
    { key: "pages", title: "Web pages", help: "Pages the agent can fetch by URL.",
      add: () => ({ url: "https://", text: "" }),
      fields: [["url", "URL", "span-12"], ["text", "Text", "span-12", "area"]] },
  ];
  let worldDraft = null;

  async function loadWorld() {
    try {
      const res = await api.get("/api/world");
      worldDraft = res.world;
      renderWorld();
    } catch (e) { dataMsg(e.message, true); }
  }

  function dataMsg(text, bad) {
    $("#data-error").hidden = !bad; $("#data-ok").hidden = !!bad;
    $(bad ? "#data-error" : "#data-ok").textContent = text;
  }

  function fieldHTML(sec, i, [name, label, span, kind], item) {
    const id = `d-${sec.key}-${i}-${name}`;
    const v = item[name] ?? "";
    let input;
    if (kind === "area") input = `<textarea id="${id}" data-sec="${sec.key}" data-i="${i}" data-f="${name}" rows="4">${esc(v)}</textarea>`;
    else if (kind === "sens") input = `<select id="${id}" class="sens-${esc(v)}" data-sec="${sec.key}" data-i="${i}" data-f="${name}">${(META.sensitivities || []).map((x) => `<option${x === v ? " selected" : ""}>${esc(x)}</option>`).join("")}</select>`;
    else input = `<input id="${id}" type="text" value="${esc(v)}" data-sec="${sec.key}" data-i="${i}" data-f="${name}">`;
    return `<div class="${span}"><label for="${id}">${esc(label)}</label>${kind === "sens" ? `<div class="select-wrap">${input}</div>` : input}</div>`;
  }

  function renderWorld() {
    const w = worldDraft;
    $("#data-body").innerHTML = `
      <section class="box"><div class="data-sec-head"><div><h2>Who the agent works for</h2><p>The user's own address.</p></div></div>
        <div class="data-item"><div class="span-6"><label for="d-user">User email</label><input id="d-user" type="text" value="${esc(w.user || "")}" data-f="user"></div></div></section>`
      + SECTIONS.map((sec) => {
        const list = w[sec.key] || [];
        return `<section class="box">
          <div class="data-sec-head"><div><h2>${esc(sec.title)} <span class="muted">(${list.length})</span></h2><p>${esc(sec.help)}</p></div>
            <button class="btn btn-small" type="button" data-add="${sec.key}">Add</button></div>
          ${list.length ? list.map((item, i) => `<div class="data-item">${sec.fields.map((f) => fieldHTML(sec, i, f, item)).join("")}
            <div class="span-12"><button class="btn btn-small btn-quiet" type="button" data-remove="${sec.key}" data-i="${i}">Remove</button></div></div>`).join("")
            : `<p class="data-empty">Nothing here yet. Press Add.</p>`}
        </section>`;
      }).join("");
  }

  $("#data-body").addEventListener("input", (e) => {
    const el = e.target;
    if (el.dataset.f === "user") { worldDraft.user = el.value; return; }
    if (!el.dataset.sec) return;
    worldDraft[el.dataset.sec][+el.dataset.i][el.dataset.f] = el.value;
    if (el.tagName === "SELECT") el.className = `sens-${el.value}`;
  });
  $("#data-body").addEventListener("click", (e) => {
    const add = e.target.closest("[data-add]"), rm = e.target.closest("[data-remove]");
    if (add) {
      const sec = SECTIONS.find((x) => x.key === add.dataset.add);
      worldDraft[sec.key] = [...(worldDraft[sec.key] || []), sec.add(worldDraft[sec.key] || [])];
      renderWorld();
      const items = document.querySelectorAll(`[data-sec="${sec.key}"]`);
      if (items.length) items[items.length - sec.fields.length].focus();
    } else if (rm) {
      worldDraft[rm.dataset.remove].splice(+rm.dataset.i, 1);
      renderWorld();
    }
  });

  async function afterWorldChange(msg) {
    dataMsg(msg, false);
    state.bench = null;
    await refreshMeta();
    renderPresets();
    await loadScenarios();
    resetBoard();
  }

  $("#data-save").addEventListener("click", async () => {
    try {
      const res = await api.post("/api/world", { world: worldDraft });
      worldDraft = res.world;
      renderWorld();
      await afterWorldChange("Saved. Every run now uses your data.");
    } catch (e) { dataMsg(e.message, true); }
  });
  $("#data-reset").addEventListener("click", async () => {
    try {
      const res = await api.post("/api/world/reset");
      worldDraft = res.world;
      renderWorld();
      await afterWorldChange("Back to the sample data.");
    } catch (e) { dataMsg(e.message, true); }
  });
  $("#data-export").addEventListener("click", () => {
    const blob = new Blob([JSON.stringify(worldDraft, null, 2)], { type: "application/json" });
    const a = Object.assign(document.createElement("a"), { href: URL.createObjectURL(blob), download: "warden-world.json" });
    a.click();
    URL.revokeObjectURL(a.href);
  });
  $("#data-import").addEventListener("change", async (e) => {
    const file = e.target.files[0];
    e.target.value = "";
    if (!file) return;
    try {
      const parsed = JSON.parse(await file.text());
      worldDraft = parsed.world || parsed;
      renderWorld();
      dataMsg(`Loaded ${file.name}. Check it, then press Save changes.`, false);
    } catch { dataMsg(`${file.name} isn't valid JSON.`, true); }
  });

  // ------------------------------------------------------------------ boot

  const theme = new URLSearchParams(location.search).get("theme");   // ?theme=light|dark overrides the system
  if (theme === "light" || theme === "dark") document.documentElement.dataset.theme = theme;
  setTab(location.hash.slice(1) || "home");
  const deepLink = new URLSearchParams(location.search).get("run");   // ?run=<scenario id> runs it on load
  api.get("/api/meta")
    .then((m) => {
      META = m;
      state.selected = deepLink || m.default_scenario;
      renderOwnDataBanner();
      renderAgents();
      renderPresets();
      return loadScenarios();
    })
    .then(() => { if (deepLink && state.tab === "run") run(); })
    .catch((e) => alertNote(e.message));
})();
