const previewStates = new Map();
const previewOutputs = new WeakMap();

function formatHex(bytes) {
  let text = "";
  for (const byte of bytes) {
    text += `${byte.toString(16).padStart(2, "0")} `;
  }
  return text;
}

function setButtonLabel(button, text) {
  const label = button.querySelector("[data-capture-label]");
  if (label && label.textContent !== text) label.textContent = text;
}

function setLoading(button, loading) {
  button.disabled = loading;
  button.toggleAttribute("data-loading", loading);
  button.setAttribute("aria-busy", String(loading));
}

function previewKey(button) {
  return button.dataset.url;
}

function previewButtons(key) {
  return [...document.querySelectorAll("[data-capture-preview]")]
    .filter((button) => previewKey(button) === key);
}

function previewOutput(button) {
  return button
    .closest("[data-capture-container]")
    ?.querySelector("[data-capture-output]");
}

function renderPreviewState(key) {
  const state = previewStates.get(key);
  if (!state) return;
  for (const button of previewButtons(key)) {
    const output = previewOutput(button);
    if (!output) continue;
    const loading = state.phase === "loading";
    setLoading(button, loading);
    button.dataset.loaded = state.phase === "loaded" ? "true" : "false";
    setButtonLabel(button, state.phase === "loaded"
      ? "Hide preview"
      : state.phase === "error"
        ? "Retry preview"
        : "Loading preview…");
    output.hidden = !state.visible;
    let rendered = previewOutputs.get(output);
    if (rendered?.chunks !== state.chunks || output.lastChild !== rendered.lastNode
        || output.childNodes.length !== rendered.index) {
      output.replaceChildren();
      rendered = { chunks: state.chunks, index: 0, lastNode: null };
      previewOutputs.set(output, rendered);
    }
    while (rendered.index < state.chunks.length) {
      const node = document.createTextNode(state.chunks[rendered.index++]);
      output.append(node);
      rendered.lastNode = node;
    }
  }
}

function flushPreview(state) {
  if (state.pending.length === 0) return;
  const delta = state.pending.join("");
  state.pending.length = 0;
  if (delta) state.chunks.push(delta);
}

function appendPreview(key, state, delta) {
  if (!delta) return;
  state.pending.push(delta);
  if (state.frame !== undefined) return;
  state.frame = requestAnimationFrame(() => {
    state.frame = undefined;
    if (previewStates.get(key) !== state) return;
    flushPreview(state);
    renderPreviewState(key);
  });
}

async function copyText(text, button) {
  const label = button.querySelector("[data-copy-label]") || button;
  const previous = label.textContent;
  try {
    let copied = false;
    if (navigator.clipboard?.writeText) {
      try {
        await navigator.clipboard.writeText(text);
        copied = true;
      } catch {
        // Some embedded browsers expose the Clipboard API but reject writes.
        // Fall through to the selection-based local copy path.
      }
    }
    if (!copied) {
      const input = document.createElement("textarea");
      input.value = text;
      input.setAttribute("readonly", "");
      input.style.position = "fixed";
      input.style.opacity = "0";
      document.body.append(input);
      input.select();
      copied = document.execCommand("copy");
      input.remove();
    }
    if (!copied) throw new Error("copy command was rejected");
    label.textContent = "Copied";
  } catch {
    label.textContent = "Copy failed";
  }
  setTimeout(() => {
    if (button.isConnected) label.textContent = previous;
  }, 900);
}

async function copyCurl(button) {
  const label = button.querySelector("[data-copy-label]") || button;
  const previous = label.textContent;
  setLoading(button, true);
  try {
    const response = await fetch(button.dataset.copyCurl, {
      cache: "no-store",
      credentials: "same-origin",
    });
    if (!response.ok) {
      const message = (await response.text()).trim();
      throw new Error(message || `cURL export returned HTTP ${response.status}`);
    }
    await copyText(await response.text(), button);
  } catch {
    label.textContent = "Copy failed";
    setTimeout(() => {
      if (button.isConnected) label.textContent = previous;
    }, 900);
  } finally {
    setLoading(button, false);
  }
}

async function streamPreview(button) {
  const key = previewKey(button);
  if (!key) return;
  const controller = new AbortController();
  const state = {
    controller,
    phase: "loading",
    chunks: [],
    pending: [],
    frame: undefined,
    visible: true,
  };
  previewStates.get(key)?.controller?.abort();
  previewStates.set(key, state);
  renderPreviewState(key);

  try {
    const response = await fetch(button.dataset.url, {
      cache: "no-store",
      credentials: "same-origin",
      signal: controller.signal,
    });
    if (!response.ok || !response.body) {
      throw new Error(`capture returned HTTP ${response.status}`);
    }

    const reader = response.body.getReader();
    const textual = button.dataset.payloadFormat === "text";
    const decoder = textual ? new TextDecoder("utf-8", { fatal: false }) : null;
    let remaining = Number(button.dataset.byteLimit);
    if (!Number.isSafeInteger(remaining) || remaining <= 0) {
      throw new Error("missing preview byte limit");
    }
    while (remaining > 0) {
      const { done, value } = await reader.read();
      if (done) break;
      const bytes = value.subarray(0, remaining);
      remaining -= bytes.byteLength;
      appendPreview(key, state, textual
        ? decoder.decode(bytes, { stream: true })
        : formatHex(bytes));
    }
    if (remaining === 0) {
      // The full payload remains available through its download endpoint. Do not
      // drain an arbitrarily large message merely to display a bounded prefix.
      await reader.cancel();
    } else if (decoder) {
      appendPreview(key, state, decoder.decode());
    }
    state.phase = "loaded";
  } catch (error) {
    controller.abort();
    if (error.name !== "AbortError") {
      state.phase = "error";
      state.pending.length = 0;
      state.chunks = [`Unable to load payload: ${error.message}`];
    }
  } finally {
    if (state.frame !== undefined) cancelAnimationFrame(state.frame);
    state.controller = undefined;
    if (previewStates.get(key) === state) {
      flushPreview(state);
      renderPreviewState(key);
    }
  }
}

document.addEventListener("click", (event) => {
  const openClear = event.target.closest("[data-open-clear]");
  if (openClear) {
    document.getElementById("clear-captures-dialog")?.showModal();
    return;
  }

  const closeClear = event.target.closest("[data-close-clear]");
  if (closeClear) {
    closeClear.closest("dialog")?.close();
    return;
  }

  const confirmClear = event.target.closest("[data-confirm-clear]");
  if (confirmClear) {
    queueMicrotask(() => confirmClear.closest("dialog")?.close());
    return;
  }

  const copyOverview = event.target.closest("[data-copy-overview]");
  if (copyOverview) {
    const text = copyOverview
      .closest(".detail-overview-item")
      ?.querySelector(".detail-overview-value")
      ?.textContent?.trim();
    if (text) void copyText(text, copyOverview);
    return;
  }

  const copyHeader = event.target.closest("[data-copy-header]");
  if (copyHeader) {
    const text = copyHeader.closest(".header-line")?.querySelector("code")?.textContent;
    if (text) void copyText(text, copyHeader);
    return;
  }

  const copyTarget = event.target.closest("[data-copy-target]");
  if (copyTarget) {
    const target = document.getElementById(copyTarget.dataset.copyTarget);
    const text = Array.from(target?.querySelectorAll("code") ?? [], (node) => node.textContent)
      .filter(Boolean)
      .join("\n");
    if (text) void copyText(text, copyTarget);
    return;
  }

  const curl = event.target.closest("[data-copy-curl]");
  if (curl) {
    void copyCurl(curl);
    return;
  }

  const button = event.target.closest("[data-capture-preview]");
  if (!button) return;

  const output = previewOutput(button);
  if (!output) return;
  const key = previewKey(button);
  const state = key ? previewStates.get(key) : undefined;
  if (state?.phase === "loaded" && state.visible) {
    previewStates.delete(key);
    output.hidden = true;
    previewOutputs.delete(output);
    output.replaceChildren();
    button.dataset.loaded = "false";
    setButtonLabel(button, button.dataset.label);
    return;
  }
  void streamPreview(button);
});

new MutationObserver(() => {
  for (const [key, state] of previewStates) {
    if (previewButtons(key).length === 0) {
      state.controller?.abort();
      previewStates.delete(key);
    } else {
      renderPreviewState(key);
    }
  }
}).observe(document.documentElement, { childList: true, subtree: true });
