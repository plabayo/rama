const activePreviews = new Map();

function formatHex(bytes) {
  let text = "";
  for (const byte of bytes) {
    text += `${byte.toString(16).padStart(2, "0")} `;
  }
  return text;
}

function setButtonLabel(button, text) {
  const label = button.querySelector("[data-capture-label]");
  if (label) label.textContent = text;
}

function setLoading(button, loading) {
  button.disabled = loading;
  button.toggleAttribute("data-loading", loading);
  button.setAttribute("aria-busy", String(loading));
}

async function copyText(text, button) {
  const previous = button.textContent;
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
    button.textContent = "Copied";
  } catch {
    button.textContent = "Copy failed";
  }
  setTimeout(() => {
    if (button.isConnected) button.textContent = previous;
  }, 900);
}

async function streamPreview(button, output) {
  const controller = new AbortController();
  activePreviews.set(button, controller);
  setLoading(button, true);
  setButtonLabel(button, "Loading preview…");
  output.hidden = false;
  output.replaceChildren();

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
    let preview = "";
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (textual) {
        preview += decoder.decode(value, { stream: true });
      } else {
        preview += formatHex(value);
      }
    }
    if (decoder) {
      preview += decoder.decode();
    }
    output.textContent = preview;
    button.dataset.loaded = "true";
    setButtonLabel(button, "Hide preview");
  } catch (error) {
    if (error.name !== "AbortError") {
      output.textContent = `Unable to load payload: ${error.message}`;
      setButtonLabel(button, "Retry preview");
    }
  } finally {
    setLoading(button, false);
    activePreviews.delete(button);
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

  const button = event.target.closest("[data-capture-preview]");
  if (!button) return;

  const output = button
    .closest("[data-capture-container]")
    ?.querySelector("[data-capture-output]");
  if (!output) return;
  if (button.dataset.loaded === "true") {
    output.hidden = true;
    output.replaceChildren();
    button.dataset.loaded = "false";
    setButtonLabel(button, button.dataset.label);
    return;
  }
  void streamPreview(button, output);
});

new MutationObserver(() => {
  for (const [button, controller] of activePreviews) {
    if (!button.isConnected) {
      controller.abort();
      activePreviews.delete(button);
    }
  }
}).observe(document.documentElement, { childList: true, subtree: true });
