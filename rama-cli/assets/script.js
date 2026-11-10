// A stalled host must not hold the page's journey, so every request has a deadline.
const REQUEST_DEADLINE_MS = 10000;
// Automation awaits the site probes for at most 30s after the form shows, then
// submits it: every site shares this budget so the page's own forms are still captured.
const SITE_PROBE_BUDGET_MS = 20000;

// Function to make a fetch request with exponential backoff
async function fetchWithBackoff(url, options) {
  const maxRetries = 3;
  const initialDelay = 1000;
  let delay = initialDelay;

  for (let i = 0; i < maxRetries; i++) {
    const controller = new AbortController();
    const deadline = setTimeout(() => controller.abort(), REQUEST_DEADLINE_MS);
    try {
      // The deadline keeps running while the caller reads the body.
      const response = await fetch(url, { ...options, signal: controller.signal });
      if (response.ok) {
        return response;
      }
    } catch (error) {
      console.error(`Request failed: ${error}`);
    }
    clearTimeout(deadline);

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
    xhr.timeout = REQUEST_DEADLINE_MS;

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

    xhr.ontimeout = function () {
      reject(new Error("Request timed out"));
    };

    xhr.send(JSON.stringify({ number }));
  });
}

// A greeting alone proves only server-to-browser delivery. Require a UTF-8
// round trip and a clean close before reporting this flow as successful.
function connectWebSocket(
  probe = "rama-fp echo: " + "🐢".repeat(32),
  url = `ws${location.protocol === "https:" ? "s" : ""}://${location.host}/api/ws`,
  flow = "WebSocket",
) {
  return new Promise((completed, reject) => {
    const socket = new WebSocket(url, ["a", "b"]);
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
      REQUEST_DEADLINE_MS,
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
      showProtocol(flow, greeting.version);
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

// Other hosts of this service, whose requests are same-site or cross-site to this
// page. Their site token authorizes requests that carry no storage cookie.
function siteProbeConfig() {
  const content = document.querySelector('meta[name="rama-fp-sites"]')?.content;
  return content ? JSON.parse(content) : [];
}

function siteUrl(site, path, protocol) {
  const url = new URL(path, site.origin);
  if (protocol) url.protocol = protocol;
  url.searchParams.set("rama-fp-site", site.token);
  return url.href;
}

// The resource timing entry tells which protocol served a subresource.
function loadedProtocol(url) {
  return performance.getEntriesByName(url).at(-1)?.nextHopProtocol || "";
}

// Errors name no URL: its site token must not reach the evidence.
function loadSubresource(element, attribute, url, parent) {
  return new Promise((resolve, reject) => {
    const deadline = setTimeout(() => reject(new Error("load timed out")), REQUEST_DEADLINE_MS);
    element.onload = () => {
      clearTimeout(deadline);
      resolve(loadedProtocol(url));
    };
    element.onerror = () => {
      clearTimeout(deadline);
      reject(new Error("failed to load"));
    };
    element[attribute] = url;
    parent?.append(element);
  });
}

// A frame fires load even when its navigation fails, so only the frame's own
// message from the probe host confirms it, with the protocol its server observed.
function loadFrame(site, url) {
  return new Promise((resolve, reject) => {
    const frame = document.createElement("iframe");
    frame.hidden = true;
    let deadline;
    function onMessage(event) {
      const version = event.data?.version;
      if (event.source !== frame.contentWindow || event.origin !== site.origin
          || event.data?.type !== "rama-fp-frame" || typeof version !== "string") {
        return;
      }
      clearTimeout(deadline);
      window.removeEventListener("message", onMessage);
      resolve(version);
    }
    deadline = setTimeout(() => {
      window.removeEventListener("message", onMessage);
      reject(new Error("frame did not confirm its load"));
    }, REQUEST_DEADLINE_MS);
    window.addEventListener("message", onMessage);
    frame.src = url;
    document.body.append(frame);
  });
}

// Settles each flow by the shared deadline; flows not yet started there never start.
function siteBudget(ms) {
  const exhausted = () => new Error("site probe budget exhausted");
  let expired = false;
  let timer;
  const expiry = new Promise((_, reject) => {
    timer = setTimeout(() => {
      expired = true;
      reject(exhausted());
    }, ms);
  });
  expiry.catch(() => {});
  return {
    run: (flow) => (expired ? Promise.reject(exhausted()) : Promise.race([flow(), expiry])),
    release: () => clearTimeout(timer),
  };
}

// Each flow a page sends to another site; a failed flow is reported, not thrown.
async function probeSite(site, budget) {
  const label = (flow) => `${flow} (${site.site})`;
  const number = Math.floor(Math.random() * 1000) + 1;
  const flows = {
    image: ["Image", () => loadSubresource(new Image(), "src", siteUrl(site, "/assets/banner.jpeg"))],
    style: ["Stylesheet", () => {
      const link = document.createElement("link");
      link.rel = "stylesheet";
      return loadSubresource(link, "href", siteUrl(site, "/assets/style.css"), document.head);
    }],
    script: ["Script", () => loadSubresource(
      document.createElement("script"), "src", siteUrl(site, "/assets/site.js"), document.head,
    )],
    frame: ["Frame", () => loadFrame(site, siteUrl(site, "/frame"))],
    fetch: ["Fetch", async () => {
      const response = await makePostRequest(siteUrl(site, `/api/fetch/number/${number}`), number);
      return JSON.parse(await response.text()).fp.request_info.version;
    }],
    xhr: ["XMLHttpRequest", async () => {
      const response = await makeRequestWithXHR(
        siteUrl(site, `/api/xml/number/${number}`), "POST", number,
      );
      return JSON.parse(response).fp.request_info.version;
    }],
    ws: ["WebSocket", async () => {
      const url = siteUrl(site, "/api/ws", "wss:");
      const { greeting } = await connectWebSocket(websocketProbe(), url, label("WebSocket"));
      return greeting.version;
    }],
  };
  const results = {};
  for (const [name, [flow, run]] of Object.entries(flows)) {
    try {
      const protocol = await budget.run(run);
      results[name] = { protocol };
      if (name !== "ws") showProtocol(label(flow), protocol);
    } catch (error) {
      results[name] = { error: String(error?.message || error) };
      showProtocol(label(flow), "unavailable", results[name].error);
    }
  }
  return results;
}

// Site probes never fail the page's own journey; missing results fail its verification.
async function probeSites() {
  const results = {};
  let sites;
  try {
    sites = siteProbeConfig();
  } catch (error) {
    showProtocol("Sites", "unavailable", `invalid configuration: ${error?.message || error}`);
    return results;
  }
  // Sites run side by side, so one stalled host cannot use up the other's budget.
  const budget = siteBudget(SITE_PROBE_BUDGET_MS);
  try {
    const probed = await Promise.all(sites.map((site) => probeSite(site, budget)));
    sites.forEach((site, index) => { results[site.site] = probed[index]; });
  } finally {
    budget.release();
  }
  return results;
}

// Each page load has its own echo payload; standalone callers keep the fixed default.
function websocketProbe() {
  const bytes = crypto.getRandomValues(new Uint8Array(16));
  const nonce = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return "rama-fp echo: " + "🐢".repeat(32) + " #" + nonce;
}

// Return original response text: parsing and reserializing in JavaScript rounds large integers.
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
    const responseText = await response2.text();
    const result = JSON.parse(responseText);
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
    // The form never waits for the other hosts; the flow's result still does.
    const sites = await probeSites();

    console.log("Requests completed successfully");
    console.log("Result:", result);
    console.log("Result2:", result2);

    return { fetch: responseText, xhr: response4, websocket, sites };
  } catch (error) {
    console.error("An error occurred:", error);
    window.location.href = "/";
  }
}

// Execute the main function when the page is loaded
window.addEventListener("load", () => {
  window.ramaFpFlow = main();
});
