// Function to make a fetch request with exponential backoff
async function fetchWithBackoff(url, options) {
  const maxRetries = 3;
  const initialDelay = 1000;
  let delay = initialDelay;

  for (let i = 0; i < maxRetries; i++) {
    try {
      const response = await fetch(url, options);
      if (response.ok) {
        return response;
      }
    } catch (error) {
      console.error(`Request failed: ${error}`);
    }

    // Exponential backoff
    await new Promise((resolve) => setTimeout(resolve, delay));
    delay *= 2;
  }

  throw new Error("Max retries exceeded");
}

function getJsProfile() {
  return {
    navigator: {
      appCodeName: window.navigator?.appCodeName,
      appName: window.navigator?.appName,
      appVersion: window.navigator?.appVersion,
      buildID: window.navigator?.buildID,
      cookieEnabled: window.navigator?.cookieEnabled,
      doNotTrack: window.navigator?.doNotTrack,
      language: window.navigator?.language,
      languages: window.navigator?.languages,
      oscpu: window.navigator?.oscpu,
      pdfViewerEnabled: window.navigator?.pdfViewerEnabled,
      platform: window.navigator?.platform,
      product: window.navigator?.product,
      productSub: window.navigator?.productSub,
      userAgent: window.navigator?.userAgent,
      vendor: window.navigator?.vendor,
      vendorSub: window.navigator?.vendorSub,
    },
    screen: {
      width: window.screen?.width,
      height: window.screen?.height,
      availWidth: window.screen?.availWidth,
      availHeight: window.screen?.availHeight,
      availLeft: window.screen?.availLeft,
      left: window.screen?.left,
      availTop: window.screen?.availTop,
      top: window.screen?.top,
      colorDepth: window.screen?.colorDepth,
      pixelDepth: window.screen?.pixelDepth,
      type: window.screen?.type,
      mozOrientation: window.screen?.mozOrientation,
      mozBrightness: window.screen?.mozBrightness,
      lockOrientation: window.screen?.lockOrientation,
      unlockOrientation: window.screen?.unlockOrientation,
    },
  };
}

function getSourceInfo() {
  // Extract source information from cookies
  function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(";").shift();
    return null;
  }

  return {
    deviceName: getCookie("source-device-name"),
    os: getCookie("source-os-name"),
    osVersion: getCookie("source-os-version"),
    browserName: getCookie("source-browser-name"),
    browserVersion: getCookie("source-browser-version"),
  };
}

// Function to make a POST request
async function makePostRequest(url, number) {
  const headers = {
    "x-RAMA-custom-header-marker": `rama-fp${Date.now()}`,
  };

  const jsWebApis = getJsProfile();
  const sourceInfo = getSourceInfo();

  const body = JSON.stringify({ number, jsWebApis, sourceInfo });

  const options = {
    method: "POST",
    headers,
    body,
  };

  return fetchWithBackoff(url, options);
}

// Function to make requests using XMLHttpRequest
function makeRequestWithXHR(url, method, number) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open(method, url);
    xhr.setRequestHeader("x-RAMA-custom-header-marker", `rama-fp${Date.now()}`);

    xhr.onload = function () {
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(xhr.response);
      } else {
        reject(new Error(`Request failed with status ${xhr.status}`));
      }
    };

    xhr.onerror = function () {
      reject(new Error("Request failed"));
    };

    xhr.send(JSON.stringify({ number }));
  });
}

// A greeting alone proves only server-to-browser delivery. Require a UTF-8
// round trip and a clean close before reporting this flow as successful.
function connectWebSocket(probe = "rama-fp echo: " + "🐢".repeat(32)) {
  return new Promise((completed, reject) => {
    const socket = new WebSocket(
      `ws${location.protocol === "https:" ? "s" : ""}://${location.host}/api/ws`,
      ["a", "b"],
    );
    let greeting;
    let echoed = false;
    let settled = false;

    function fail(error) {
      if (settled) return;
      settled = true;
      clearTimeout(deadline);
      reject(error);
      socket.close();
    }

    const deadline = setTimeout(
      () => fail(new Error("WebSocket round trip timed out")),
      10000,
    );
    socket.onmessage = function (event) {
      if (settled) return;
      try {
        if (!greeting) {
          const result = JSON.parse(event.data);
          if (result.initiator !== "ws" || typeof result.version !== "string") {
            throw new Error("Invalid WebSocket greeting");
          }
          greeting = result;
          socket.send(probe);
        } else if (!echoed && event.data === probe) {
          echoed = true;
        } else {
          throw new Error("Unexpected WebSocket echo");
        }
      } catch (error) {
        fail(error);
      }
    };
    socket.onerror = () => fail(new Error("WebSocket connection error"));
    socket.onclose = function (event) {
      if (settled) return;
      if (!echoed || !event.wasClean || event.code !== 1000) {
        fail(new Error("WebSocket closed before a successful round trip"));
        return;
      }
      settled = true;
      clearTimeout(deadline);
      showProtocol("WebSocket", greeting.version);
      completed({ greeting, probe });
    };
  });
}

// Keep the text labels stable for the shared browser journey, while presenting
// each flow separately. The observed version already describes H3 fallback.
function showProtocol(flow, protocol, status = "") {
  let report = document.getElementById("flow-protocols");
  if (!report) {
    const section = document.createElement("section");
    section.className = "flow-protocols";
    section.setAttribute("aria-labelledby", "flow-protocols-title");
    const heading = document.createElement("h2");
    heading.id = "flow-protocols-title";
    heading.textContent = "Connection protocols";
    report = document.createElement("ul");
    report.id = "flow-protocols";
    section.append(heading, report);
    document.getElementById("input").before(section);
  }
  const versions = {
    "h2": "HTTP/2", "HTTP/2.0": "HTTP/2",
    "h3": "HTTP/3", "HTTP/3.0": "HTTP/3",
    "http/1.1": "HTTP/1.1",
  };
  const item = document.createElement("li");
  const label = document.createElement("span");
  label.className = "flow-label";
  label.textContent = `${flow}: `;
  const version = document.createElement("span");
  version.className = "flow-version";
  version.textContent = versions[protocol] || protocol || "unavailable";
  item.append(label, version);
  if (status) {
    const note = document.createElement("small");
    note.textContent = ` (${status})`;
    item.append(note);
  }
  report.append(item);
}

// Each page load has its own echo payload; standalone callers keep the fixed default.
function websocketProbe() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const nonce = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return "rama-fp echo: " + "🐢".repeat(32) + " #" + nonce;
}

// Return the responses already consumed by this page, without issuing another journey.
async function main() {
  // A non-H3 HTTPS navigation can learn Alt-Svc. Reload once to discover it;
  // an already-H3 navigation can run the journey immediately.
  const navigation = performance.getEntriesByType("navigation")[0];
  const url = new URL(location.href);
  const probeHttp3 = document.querySelector('meta[name="rama-h3-probe"]')?.content === "enabled";
  if (probeHttp3 && url.protocol === "https:" && navigation?.nextHopProtocol !== "h3" && !url.searchParams.has("h3_probe")) {
    url.searchParams.set("h3_probe", "1");
    location.replace(url.href);
    return;
  }
  showProtocol("Navigation", navigation?.nextHopProtocol);
  try {
    // Generate random numbers for the requests
    const number = Math.floor(Math.random() * 1000) + 1;
    const number2 = Math.floor(Math.random() * 1000) + 1;

    console.log("Generated random numbers:", number, number2);

    // Fetch POST request
    const response2 = await makePostRequest(
      `/api/fetch/number/${number}`,
      number,
    );
    console.log("Fetch POST request response:", response2);
    const result = await response2.json();
    showProtocol("Fetch", result.fp.request_info.version);

    // XMLHttpRequest POST request
    const response4 = await makeRequestWithXHR(
      `/api/xml/number/${number2}`,
      "POST",
      number2,
    );
    console.log("XMLHttpRequest POST request response:", response4);
    const result2 = JSON.parse(response4);
    showProtocol("XMLHttpRequest", result2.fp.request_info.version);

    // WS connection — best-effort probe. The fingerprint is captured
    // on connect, so a WS hiccup must not fail the whole report (and
    // trigger the redirect below).
    let websocket = null;
    try {
      websocket = await connectWebSocket(websocketProbe());
    } catch (wsError) {
      console.warn("WebSocket probe failed:", wsError);
      showProtocol("WebSocket", "unavailable", "unsupported or connection failed");
    }

    console.log("Requests completed successfully");
    console.log("Result:", result);
    console.log("Result2:", result2);

    // Display a form to submit a rating
    const formHtml = `
            <form method="POST" action="/form">
                <input type="hidden" name="source" value="web">
                <label for="rating">Rate Rama from 1 to 5:</label>
                <select name="rating" id="rating">
                    <option value="1">1</option>
                    <option value="2">2</option>
                    <option value="3" selected>3</option>
                    <option value="4">4</option>
                    <option value="5">5</option>
                </select>
                <button type="submit">Submit</button>
            </form>
        `;
    const inputEl = document.getElementById("input");
    inputEl.hidden = false;
    inputEl.innerHTML = formHtml;
    return { fetch: result, xhr: result2, websocket };
  } catch (error) {
    console.error("An error occurred:", error);
    window.location.href = "/";
  }
}

// Execute the main function when the page is loaded
window.addEventListener("load", () => {
  window.ramaFpFlow = main();
});
