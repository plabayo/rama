(async function () {
  const ipEl = document.getElementById("ip");
  const copyBtn = document.getElementById("copyBtn");
  copyBtn.addEventListener("click", async () => {
    const txt = ipEl.textContent.trim();
    try {
      await navigator.clipboard.writeText(txt);
      copyBtn.textContent = "Copied";
      setTimeout(() => (copyBtn.textContent = "Copy IP"), 1400);
    } catch (e) {
      const ta = document.createElement("textarea");
      ta.value = txt;
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
        copyBtn.textContent = "Copied";
      } catch (e) {
        alert("Copy failed. Select and copy manually.");
      }
      ta.remove();
      setTimeout(() => (copyBtn.textContent = "Copy IP"), 1400);
    }
  });
})();
