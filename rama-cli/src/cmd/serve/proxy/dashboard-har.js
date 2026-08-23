const recording = {
  busy: false,
};

document.documentElement.dataset.harDelivery = "browser-download";

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
  const fileName = suggestedName();
  await request("/api/har/start", {
    session: button.dataset.session,
    file_name: fileName,
  });
  showNotice(`Recording ${fileName}; stop to choose where your browser saves it.`);
}

document.addEventListener("click", async (event) => {
  if (!(event.target instanceof Element)) return;
  const exportLink = event.target.closest("[data-har-export]");
  if (exportLink) {
    showNotice("Preparing selected HAR download…");
    return;
  }
  const button = event.target.closest("button[data-har-action]");
  if (!button || recording.busy) return;
  event.preventDefault();
  recording.busy = true;
  button.disabled = true;
  try {
    await startRecording(button);
  } catch (error) {
    showNotice(error?.message || "HAR recording failed", true);
  } finally {
    recording.busy = false;
    button.disabled = false;
  }
});

document.addEventListener("submit", (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement) || !form.matches(".har-control.recording")) {
    return;
  }
  showNotice("Finishing HAR; your browser will ask where to save it.");
});
