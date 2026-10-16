import {waitForFlows, submitFormAndSave} from './browser_flows.mjs';
import fs from 'node:fs';
import {once} from 'node:events';
const [socketUrl,url,output,flows="navigate"]=process.argv.slice(2);
const ws=new WebSocket(socketUrl);
await Promise.race([once(ws,'open'),new Promise((_,reject)=>setTimeout(()=>reject(new Error('socket timeout')),5000))]);
const pending=new Map();let next=0;
ws.addEventListener('message',({data})=>{
 const message=JSON.parse(data);
 if(message.id&&pending.has(message.id)){
  const {resolve,reject,timer}=pending.get(message.id);pending.delete(message.id);clearTimeout(timer);
  if(message.error)reject(new Error(JSON.stringify(message)));else resolve(message.result);
 }
});
function call(method,params={}){return new Promise((resolve,reject)=>{
 const id=++next;const timer=setTimeout(()=>{pending.delete(id);reject(new Error(`timeout: ${method}`));},15000);
 pending.set(id,{resolve,reject,timer});ws.send(JSON.stringify({id,method,params}));
});}
try{
 const session=await call('session.new',{capabilities:{alwaysMatch:{acceptInsecureCerts:false}}});
 const {contexts}=await call('browsingContext.getTree');
 const context=contexts[0].context;
 await call('browsingContext.navigate',{context,url,wait:'complete'});
 const evaluate = async (expression, awaitPromise = false) => {
  const value = await call('script.evaluate', {expression, target: {context}, awaitPromise});
  if (value.type === 'exception') throw new Error(JSON.stringify(value.exceptionDetails));
  return value.result.value;
 };
 if (flows === 'all') await waitForFlows(evaluate);
 fs.writeFileSync(output, await evaluate('document.documentElement.outerHTML'));
 if (flows === 'all') await submitFormAndSave(evaluate, output + '.form.html');
 console.log(JSON.stringify({browser:`${session.capabilities.browserName}/${session.capabilities.browserVersion}`}));
}finally{
 try{await call('browser.close');}catch{}
 for(const {timer} of pending.values())clearTimeout(timer);
 ws.close();
}
