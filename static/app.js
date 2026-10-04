'use strict';
let csrf = '', current = null;
const $ = id => document.getElementById(id);
async function api(path, options={}) {
  const response = await fetch(path, {credentials:'same-origin', ...options, headers:{'X-CSRF-Token':csrf, ...(options.headers || {})}});
  const body = await response.json();
  if (!response.ok) throw new Error(body.error || 'Request failed.');
  return body;
}
function node(tag, text, className='') { const el=document.createElement(tag); el.textContent=text; el.className=className; return el; }
function show(item) {
  current=item; $('output').textContent=item.output; $('matches').textContent=item.matches;
  $('lines').textContent=item.line_count; $('saved').textContent=item.id.slice(0,8);
  $('export').href='/api/runs/'+item.id+'/export'; $('export').classList.remove('hidden');
  $('findings').replaceChildren();
  for (const [rule,count] of Object.entries(item.counts)) $('findings').append(node('span', rule.replaceAll('_',' ')+' · '+count, 'chip'));
  if (!item.matches) $('findings').append(node('span','No supported patterns detected — review manually.','chip'));
  $('digest').textContent='SANITIZED OUTPUT SHA-256 / '+item.output_sha256;
}
async function history() {
  const data=await api('/api/runs'); $('history').replaceChildren();
  for (const item of data.runs) {
    const button=node('button', item.matches+' masks · '+item.line_count+' lines', 'history-item');
    button.append(node('span', new Date(item.created).toLocaleString()+' / '+item.id.slice(0,8)));
    button.addEventListener('click', async()=>{try {show(await api('/api/runs/'+item.id)); $('status').textContent='Loaded saved redacted artifact.';}catch(e){$('status').textContent=e.message;}});
    $('history').append(button);
  }
  if (!data.runs.length) $('history').append(node('p','No saved runs.','helper'));
}
$('source').addEventListener('input',()=>{$('input-count').textContent=$('source').value.length.toLocaleString()+' characters'; $('file').value='';});
$('load-demo').addEventListener('click',async()=>{try {const demo=await api('/api/demo');$('source').value=demo.text;$('mode').value=demo.mode;$('file').value='';$('input-count').textContent=demo.text.length+' characters';$('status').textContent='Original fictional sample loaded. Nothing has been saved.';}catch(e){$('status').textContent=e.message;}});
$('analyze').addEventListener('click',async()=>{
  $('analyze').disabled=true; $('status').textContent='Applying supported patterns locally…';
  try {
    let options;
    if ($('file').files.length) {const form=new FormData();form.append('file',$('file').files[0]);form.append('mode',$('mode').value);options={method:'POST',body:form};}
    else options={method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:$('source').value,mode:$('mode').value})};
    const item=await api('/api/runs',options);show(item);await history();
    $('source').value='';$('file').value='';$('input-count').textContent='0 characters';
    $('status').textContent='Redacted artifact saved. Raw input cleared from this form. Inspect before sharing.';
  }catch(e){$('status').textContent=e.message;}finally{$('analyze').disabled=false;}
});
(async()=>{try {const bootstrap=await api('/api/bootstrap');csrf=bootstrap.csrf;$('load-demo').hidden=!bootstrap.demo_enabled;for(const [rule,explanation] of Object.entries(bootstrap.rules)){const row=node('div','','rule');row.append(node('strong',rule.replaceAll('_',' ')),node('span',explanation));$('rules').append(row);}await history();}catch(e){$('status').textContent=e.message;}})();
