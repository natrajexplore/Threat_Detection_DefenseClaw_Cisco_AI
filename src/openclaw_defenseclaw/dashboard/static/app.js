// No inline scripts (CSP: script-src 'self'). Demo runner + copy-to-clipboard.
document.addEventListener("DOMContentLoaded", () => {
  const pick = document.getElementById("case-pick");
  if (pick) {
    const load = () => htmx.ajax("GET", "/p/case/" + encodeURIComponent(pick.value), "#case");
    pick.addEventListener("change", load);
    load();
  }
  document.body.addEventListener("click", async (ev) => {
    const btn = ev.target.closest("[data-copy]");
    if (!btn) return;
    const src = document.querySelector(btn.dataset.copy);
    try {
      await navigator.clipboard.writeText(src.textContent);
      btn.textContent = "Copied";
    } catch {
      btn.textContent = "Select & copy manually";
    }
    setTimeout(() => (btn.textContent = "Copy"), 1500);
  });
});
