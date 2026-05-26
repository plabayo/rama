(() => {
  /* Feature-detect native declarative-partial-updates: if the marker is
     consumed during fragment parsing, the firstChild of the parsed fragment
     is null. When that's the case we skip our marker->template swap and let
     the browser do it; we still run the mutation observer so the loaded
     state attributes get set the same way for both code paths. */
  let native = false;
  try {
    native = document.createRange()
      .createContextualFragment('<?marker name=__dpu_t><template for=__dpu_t></template>')
      .firstChild === null;
  } catch {}

  const findMarker = (name) => {
    const it = document.createNodeIterator(document, NodeFilter.SHOW_COMMENT);
    let n;
    while ((n = it.nextNode())) {
      const d = n.data || '';
      if (/^\?marker\b/.test(d)) {
        const m = d.match(/\bname *= *"?([^"\s]+)"?/);
        if (m && m[1] === name) return n;
      }
    }
    return null;
  };

  const swap = (t) => {
    if (native) return;
    const name = t.getAttribute('for');
    if (!name) return;
    const m = findMarker(name);
    if (!m) return;
    m.replaceWith(t.content.cloneNode(true));
    t.remove();
  };

  const markLoaded = (panel) => {
    if (panel.hasAttribute('data-dpu-loaded')) return;
    panel.setAttribute('data-dpu-loaded', '');
    const ps = document.querySelectorAll('section.panel');
    const ld = document.querySelectorAll('section.panel[data-dpu-loaded]');
    if (ps.length > 0 && ps.length === ld.length)
      document.body.setAttribute('data-dpu-done', '');
  };

  if (!native) document.querySelectorAll('template[for]').forEach(swap);

  new MutationObserver(ms => {
    for (const m of ms) {
      if (!native) for (const n of m.addedNodes)
        if (n.nodeType === 1 && n.tagName === 'TEMPLATE' && n.hasAttribute('for')) swap(n);
      if (m.target instanceof HTMLElement && m.target.matches('section.panel'))
        for (const n of m.addedNodes)
          if (n.nodeType === 1 && n.tagName !== 'H2' && !(n.classList && n.classList.contains('spinner'))) {
            markLoaded(m.target);
            break;
          }
    }
  }).observe(document, { childList: true, subtree: true });
})();
