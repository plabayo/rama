(() => {
  /* Feature-detect native declarative-partial-updates: if the marker is
     consumed during fragment parsing, the firstChild of the parsed
     fragment is null. When native support is present we do nothing — the
     browser performs the marker->template swap and CSS clears the loading
     chrome. Otherwise we polyfill the swap below; either way the spinners
     and banner are removed by structural CSS as the fragments land. */
  let native = false;
  try {
    native = document.createRange()
      .createContextualFragment('<?marker name=__dpu_t><template for=__dpu_t></template>')
      .firstChild === null;
  } catch {}
  if (native) return;

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
    const name = t.getAttribute('for');
    if (!name) return;
    const m = findMarker(name);
    if (!m) return;
    m.replaceWith(t.content.cloneNode(true));
    t.remove();
  };

  document.querySelectorAll('template[for]').forEach(swap);

  new MutationObserver(ms => {
    for (const m of ms)
      for (const n of m.addedNodes)
        if (n.nodeType === 1 && n.tagName === 'TEMPLATE' && n.hasAttribute('for')) swap(n);
  }).observe(document, { childList: true, subtree: true });
})();
