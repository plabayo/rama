import {waitForFlows, submitFormAndSave} from './browser_flows.mjs';
import fs from 'node:fs';
import {once} from 'node:events';
const [socketUrl, url, output, flows = "navigate"] = process.argv.slice(2);
const ws = new WebSocket(socketUrl);
await once(ws, 'open');
let nextId=0;
const pending = new Map();
const events = new Map();
ws.addEventListener('message', ({data}) => {
  const message = JSON.parse(data);
  if (message.id && pending.has(message.id)) {
    const {resolve, reject, timer} = pending.get(message.id);
    pending.delete(message.id); clearTimeout(timer);
    if(message.error) reject(new Error(JSON.stringify(message.error))); else resolve(message.result);
  }
  const key = `${message.sessionId ?? ''}:${message.method}`;
  if(events.has(key)) { const done=events.get(key); events.delete(key); done(message.params); }
});
function call(method, params={}, sessionId) {
  return new Promise((resolve,reject) => {
    const id=++nextId;
    const timer=setTimeout(()=>{pending.delete(id);reject(new Error(`CDP timeout: ${method}`));},15000);
    pending.set(id,{resolve,reject,timer});
    ws.send(JSON.stringify({id,method,params,sessionId}));
  });
}
function event(method, sessionId) {
  return new Promise((resolve,reject) => {
    const key=`${sessionId}:${method}`;
    const timer=setTimeout(()=>{events.delete(key);reject(new Error(`CDP event timeout: ${method}`));},15000);
    events.set(key,value=>{clearTimeout(timer);resolve(value);});
  });
}
try {
  const version=await call('Browser.getVersion');
  const {targetId}=await call('Target.createTarget',{url:'about:blank'});
  const {sessionId}=await call('Target.attachToTarget',{targetId,flatten:true});
  await call('Page.enable',{},sessionId);
  const loaded=event('Page.loadEventFired',sessionId);
  const navigation=await call('Page.navigate',{url},sessionId);
  if(navigation.errorText) throw new Error(navigation.errorText);
  await loaded;
  const evaluate = async (expression, awaitPromise = false) => {
    const value = await call('Runtime.evaluate', {expression, returnByValue: true, awaitPromise}, sessionId);
    if (value.exceptionDetails) throw new Error(JSON.stringify(value.exceptionDetails));
    return value.result.value;
  };
  if (flows === 'all') await waitForFlows(evaluate);
  fs.writeFileSync(output, await evaluate('document.documentElement.outerHTML'));
  if (flows === 'all') await submitFormAndSave(evaluate, output + '.form.html');
  console.log(JSON.stringify({browser:version.product}));
  await call('Target.closeTarget',{targetId});
} finally {
  try {await call('Browser.close');} catch {}
  ws.close();
}
