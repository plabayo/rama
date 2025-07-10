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

// Function to open a WebSocket connection to /api/ws
function connectWebSocket() {
  return new Promise((_, reject) => {
    const socket = new WebSocket(
      `ws${location.protocol === "https:" ? "s" : ""}://${location.host}/api/ws`,
    );

    socket.onerror = function () {
      reject(new Error("WebSocket connection error"));
    };

    socket.onclose = function (event) {
      if (!event.wasClean) {
        console.warn("WebSocket closed unexpectedly:", event);
      }
    };
  });
}

// Main function to execute the requests
async function main() {
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

    // XMLHttpRequest POST request
    const response4 = await makeRequestWithXHR(
      `/api/xml/number/${number2}`,
      "POST",
      number2,
    );
    console.log("XMLHttpRequest POST request response:", response4);
    const result2 = JSON.parse(response4);

    // WS connection
    await connectWebSocket();

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
  } catch (error) {
    console.error("An error occurred:", error);
    window.location.href = "/";
  }
}

// Execute the main function when the page is loaded
window.addEventListener("load", main);
