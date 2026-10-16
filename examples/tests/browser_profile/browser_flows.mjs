import fs from 'node:fs';

const ready = `new Promise((resolve, reject) => {
  const deadline = Date.now() + 10000;
  function check() {
    if (document.querySelector('form[action="/form"]')) resolve(true);
    else if (Date.now() > deadline) reject(new Error('browser flow completion timeout'));
    else setTimeout(check, 50);
  }
  check();
})`;
const submit = `(() => {
  setTimeout(() => document.querySelector('form[action="/form"]').requestSubmit(), 0);
  return true;
})()`;
const form = 'location.pathname === "/form" && document.readyState === "complete" ? document.documentElement.outerHTML : ""';

export async function waitForFlows(evaluate) {
  if (await evaluate(ready, true) !== true) throw new Error('browser flows did not finish');
}

export async function submitFormAndSave(evaluate, output) {
  await evaluate(submit);
  const deadline = Date.now() + 10000;
  while (Date.now() < deadline) {
    let html;
    try { html = await evaluate(form); } catch { /* The navigation can replace the realm. */ }
    if (html) {
      fs.writeFileSync(output, html);
      return;
    }
    await new Promise(resolve => setTimeout(resolve, 50));
  }
  throw new Error('form navigation did not complete');
}
