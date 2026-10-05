// Conversation trace: filters, replay, detail drawer, live refresh.
// Works inside the dashboard (htmx present, CSP script-src 'self') and inlined in the offline export.
(() => {
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const BAD = new Set(["block", "blocked", "deny", "rejected", "confirm", "observe", "flag", "alert"]);
  const state = { hiddenLanes: new Set(), replay: false, idx: -1, runUrl: null };

  const rows = () => $$("#timeline .tl-row.ev");

  function apply() {
    const q = ($("#f-search")?.value || "").trim().toLowerCase();
    const badOnly = $("#f-blocked")?.checked;
    rows().forEach((r, i) => {
      const hide =
        state.hiddenLanes.has(r.dataset.lane) ||
        (badOnly && !BAD.has(r.dataset.worst)) ||
        (q && !r.textContent.toLowerCase().includes(q)) ||
        (state.replay && i > state.idx);
      r.classList.toggle("is-hidden", hide);
      r.classList.toggle("current", state.replay && i === state.idx);
    });
    const pos = $("#r-pos");
    if (pos) pos.textContent = state.replay ? `${state.idx + 1} / ${rows().length}` : "";
  }

  function buildLaneFilter() {
    const box = $("#lane-filter");
    if (!box) return;
    box.replaceChildren();
    $$("#timeline .lane-h").forEach((h) => {
      const lane = h.dataset.lane;
      const b = document.createElement("button");
      b.type = "button";
      b.className = "chip lane-chip" + (state.hiddenLanes.has(lane) ? " off" : "");
      b.textContent = lane;
      b.setAttribute("aria-pressed", String(!state.hiddenLanes.has(lane)));
      b.addEventListener("click", () => {
        state.hiddenLanes.has(lane) ? state.hiddenLanes.delete(lane) : state.hiddenLanes.add(lane);
        buildLaneFilter();
        apply();
      });
      box.appendChild(b);
    });
  }

  function setReplay(on) {
    state.replay = on;
    state.idx = on ? 0 : -1;
    const t = $("#r-toggle");
    if (t) {
      t.textContent = on ? "■ Stop replay" : "▶ Replay";
      t.setAttribute("aria-pressed", String(on));
    }
    ["#r-prev", "#r-next"].forEach((s) => { const b = $(s); if (b) b.disabled = !on; });
    if (on && $("#f-live")) $("#f-live").checked = false;
    apply();
    focusCurrent();
  }

  function step(d) {
    if (!state.replay) return;
    state.idx = Math.max(0, Math.min(rows().length - 1, state.idx + d));
    apply();
    focusCurrent();
  }

  function focusCurrent() {
    const r = rows()[state.idx];
    if (r) { r.scrollIntoView({ block: "nearest", behavior: "smooth" }); openDrawer(r); }
  }

  function openDrawer(row) {
    const d = $("#drawer");
    if (!d) return;
    $("#d-title").textContent = row.querySelector(".b-title")?.textContent || "Event";
    $("#d-meta").textContent = row.dataset.meta || "";
    const v = $("#d-verdicts");
    v.replaceChildren(...$$(".b-head .tag", row).map((t) => t.cloneNode(true)));
    $("#d-body").textContent = row.querySelector(".b-body")?.textContent || "(no content)";
    $("#d-raw").textContent = row.querySelector(".raw")?.textContent || "";
    $$("#timeline .tl-row.selected").forEach((r) => r.classList.remove("selected"));
    row.classList.add("selected");
    d.hidden = false;
  }

  function init() {
    buildLaneFilter();
    if (state.replay) state.idx = Math.min(state.idx, rows().length - 1);
    apply();
    const tl = $("#timeline .tl");
    if (tl && tl.dataset.run) state.runUrl = "/p/trace/run/" + encodeURIComponent(tl.dataset.run);
  }

  document.addEventListener("DOMContentLoaded", () => {
    $("#f-search")?.addEventListener("input", apply);
    $("#f-blocked")?.addEventListener("change", apply);
    $("#r-toggle")?.addEventListener("click", () => setReplay(!state.replay));
    $("#r-prev")?.addEventListener("click", () => step(-1));
    $("#r-next")?.addEventListener("click", () => step(1));
    $("#d-close")?.addEventListener("click", () => { $("#drawer").hidden = true; });
    document.addEventListener("keydown", (e) => {
      if (e.target.matches("input, select, textarea")) return;
      if (e.key === "ArrowRight" || e.key === " ") { if (state.replay) { e.preventDefault(); step(1); } }
      else if (e.key === "ArrowLeft") step(-1);
      else if (e.key === "Escape") { const d = $("#drawer"); if (d) d.hidden = true; }
      else if (e.key === "Enter" && e.target.classList?.contains("ev")) openDrawer(e.target);
    });
    $("#timeline")?.addEventListener("click", (e) => {
      const r = e.target.closest(".tl-row.ev");
      if (r && !e.target.closest("form, a")) openDrawer(r);
    });
    document.body.addEventListener("click", (e) => {
      const b = e.target.closest(".run");
      if (!b) return;
      $$(".run.active").forEach((x) => x.classList.remove("active"));
      b.classList.add("active");
    });
    document.body.addEventListener("htmx:afterSwap", (e) => { if (e.target.id === "timeline") init(); });
    setInterval(() => {
      if (window.htmx && $("#f-live")?.checked && !state.replay && state.runUrl) {
        htmx.ajax("GET", state.runUrl, "#timeline");
      }
    }, 5000);
    init();
  });
})();
