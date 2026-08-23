const activePreviews = new Map();

function appendHex(output, bytes) {
  let text = "";
  for (const byte of bytes) {
    text += `${byte.toString(16).padStart(2, "0")} `;
  }
  output.append(document.createTextNode(text));
}

async function streamPreview(button, output) {
  const controller = new AbortController();
  activePreviews.set(button, controller);
  button.disabled = true;
  button.textContent = "Loading…";
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
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (textual) {
        output.append(document.createTextNode(decoder.decode(value, { stream: true })));
      } else {
        appendHex(output, value);
      }
    }
    if (decoder) {
      output.append(document.createTextNode(decoder.decode()));
    }
    button.dataset.loaded = "true";
    button.textContent = "Hide preview";
  } catch (error) {
    if (error.name !== "AbortError") {
      output.textContent = `Unable to load payload: ${error.message}`;
      button.textContent = "Retry preview";
    }
  } finally {
    button.disabled = false;
    activePreviews.delete(button);
  }
}

document.addEventListener("click", (event) => {
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
    button.textContent = button.dataset.label;
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
