const destination = {
  handle: null,
  busy: false,
};

document.documentElement.dataset.harPicker = "ready";

let noticeTimer;

function showNotice(message, error = false) {
  const notice = document.getElementById("har-notice");
  if (!notice) return;
  clearTimeout(noticeTimer);
  notice.textContent = message;
  notice.classList.toggle("error", error);
  notice.hidden = false;
  noticeTimer = setTimeout(() => {
    notice.hidden = true;
  }, 5000);
}

function suggestedName() {
  const timestamp = new Date().toISOString().replaceAll(":", "-").replace(".", "-");
  return `rama-proxy-${timestamp}.har`;
}

async function pickHarFile(name = suggestedName()) {
  if (typeof window.showSaveFilePicker !== "function") {
    throw new Error(
      "This browser does not support the save-file picker required for HAR recording.",
    );
  }
  return window.showSaveFilePicker({
    suggestedName: name,
    excludeAcceptAllOption: true,
    types: [
      {
        description: "HTTP Archive",
        accept: { "application/json": [".har"] },
      },
    ],
  });
}

async function request(path, parameters) {
  const url = new URL(path, window.location.href);
  for (const [name, value] of Object.entries(parameters)) {
    url.searchParams.set(name, value);
  }
  const response = await fetch(url, {
    method: "POST",
    credentials: "same-origin",
  });
  if (!response.ok) {
    const message = (await response.text()).trim();
    throw new Error(message || `HAR request failed (${response.status})`);
  }
  return response;
}

async function startRecording(button) {
  const handle = await pickHarFile();
  await request("/api/har/start", {
    session: button.dataset.session,
    file_name: handle.name,
  });
  destination.handle = handle;
  showNotice(`Recording HAR to ${handle.name}`);
}

async function stopRecording(button) {
  const fileName = button.dataset.fileName || suggestedName();
  const handle = destination.handle || (await pickHarFile(fileName));
  const response = await request("/api/har/stop", {
    session: button.dataset.session,
  });
  const writable = await handle.createWritable();
  try {
    if (response.body) {
      await response.body.pipeTo(writable);
    } else {
      await writable.write(await response.blob());
      await writable.close();
    }
  } catch (error) {
    await writable.abort(error).catch(() => {});
    throw error;
  }
  destination.handle = null;
  showNotice(`Saved ${handle.name}`);
}

document.addEventListener("click", async (event) => {
  if (!(event.target instanceof Element)) return;
  const button = event.target.closest("button[data-har-action]");
  if (!button || destination.busy) return;
  event.preventDefault();
  destination.busy = true;
  button.disabled = true;
  try {
    if (button.dataset.harAction === "start") {
      await startRecording(button);
    } else {
      await stopRecording(button);
    }
  } catch (error) {
    if (error?.name !== "AbortError") {
      showNotice(error?.message || "HAR recording failed", true);
    }
  } finally {
    destination.busy = false;
    button.disabled = false;
  }
});
