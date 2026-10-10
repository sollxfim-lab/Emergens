import io, sys

sys.stdout.reconfigure(encoding="utf-8", errors="replace")
P = r"C:\Users\RDP\Documents\Emergens\Emergens\templates\js\script.js"
with io.open(P, encoding="utf-8") as f:
    text = f.read()

start = text.rfind("// \u2554", 0, text.index("AI ASSISTANT"))
end_marker = "// ---- main Chat section rendering"
end = text.index(end_marker)

NEW_BLOCK = """// ╔════════════════════════════════════════════════════════════╗
// ║  AI ASSISTANT — server-backed chat with model selection      ║
// ╚════════════════════════════════════════════════════════════╝
// The browser talks to the local Flask server (/api/chat), never to a
// third-party API directly: the server selects the backend from the
// chosen model and keeps API keys off the client. Scan results can be
// attached as context so the assistant analyses live findings.
const CHAT_HISTORY_KEY='emergens-chat-history';
const AI_MODEL_KEY='emergens-ai-model';
let aiAttachedContext=null;   // { entryId, target, summary }
let aiAttachedIds=new Set(JSON.parse(localStorage.getItem('emergens-ai-attached')||'[]'));

function persistAiAttached(){try{localStorage.setItem('emergens-ai-attached',JSON.stringify([...aiAttachedIds].slice(-50)));}catch(e){}}

function getChatHistory(){try{return JSON.parse(localStorage.getItem(CHAT_HISTORY_KEY)||'[]');}catch(e){return[];}}
function setChatHistory(arr){try{localStorage.setItem(CHAT_HISTORY_KEY,JSON.stringify(arr.slice(-100)));}catch(e){}}
function appendChatHistory(role,content,meta){const h=getChatHistory();h.push(Object.assign({role,content,ts:new Date().toISOString()},meta||{}));setChatHistory(h);return h;}

async function askServerAI(promptText, model){
    let res;
    try{
        res=await fetch('/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({message:promptText,model:model||null,context:aiAttachedContext?aiAttachedContext.summary:null})});
    }catch(networkErr){
        throw new Error('Could not reach the server chat endpoint (network error).');
    }
    let data;
    try{ data=await res.json(); }
    catch(parseErr){ throw new Error(`Server returned an unreadable response (HTTP ${res.status}).`); }
    if(data && data.error){ throw new Error(typeof data.error==='string'?data.error:'The chat service returned an error.'); }
    if(!res.ok){ throw new Error(`Server replied with HTTP ${res.status}.`); }
    const reply = data.reply || data.message || data.response || data.answer || '';
    if(!reply){ throw new Error('The AI returned no readable reply text.'); }
    return {reply: reply, model: data.model||model||''};
}

// ── Model selector ─────────────────────────────────────────
async function initAiModelPicker(){
    const sel=document.getElementById('aiModelSelect');
    const ready=document.getElementById('aiModelReady');
    if(!sel)return;
    try{
        const r=await fetch('/api/chat/models');
        const d=await r.json();
        const models=d.models||[];
        if(!models.length){ sel.innerHTML='<option value="">No models</option>'; return; }
        sel.innerHTML=models.map(m=>`<option value="${escapeHtml(m.id)}" ${m.ready?'':'disabled'}>${escapeHtml(m.label)}${m.ready?'':' (no key)'}</option>`).join('');
        const saved=localStorage.getItem(AI_MODEL_KEY);
        const ok=saved&&models.some(m=>m.id===saved&&m.ready);
        sel.value = ok ? saved : (d.default&&models.some(m=>m.id===d.default&&m.ready)?d.default:(models.find(m=>m.ready)||models[0]).id);
        const current=models.find(m=>m.id===sel.value);
        if(ready){ready.classList.toggle('ok',!!(current&&current.ready));ready.classList.toggle('off',!(current&&current.ready));}
        sel.addEventListener('change',()=>{localStorage.setItem(AI_MODEL_KEY,sel.value);showToast(`AI model: ${sel.options[sel.selectedIndex]?.text||sel.value}`);});
    }catch(e){
        sel.innerHTML='<option value="">Unavailable</option>';
        if(ready)ready.classList.add('off');
    }
}
initAiModelPicker();

// ── Scan context attachment ────────────────────────────────
function summarizeScanForAi(entry){
    const results=entry.result||entry.results||{};
    const tools=Object.keys(results);
    const lines=[`Target: ${entry.target||'unknown'}`,`Mode: ${entry.mode||'basic'}`,`Tools: ${tools.join(', ')||'none'}`,`Status: ${entry.status||'completed'}`,''];
    for(const[k,r]of Object.entries(results)){
        const d=(r&&typeof r==='object')?(r.data||r):{};
        const bits=[];
        if(d.risk)bits.push(`risk=${d.risk}`);
        if(d.vulnerable!==undefined)bits.push(`vulnerable=${!!d.vulnerable}`);
        if(Array.isArray(d.findings))bits.push(`findings=${d.findings.length}`);
        if(Array.isArray(d.exposed))bits.push(`exposed=${d.exposed.map(x=>x.path).join(', ')}`);
        if(Array.isArray(d.open_ports_details))bits.push(`open_ports=${d.open_ports_details.map(p=>p.port!==undefined?p.port:p).join(', ')}`);
        if(d.score_percent!==undefined)bits.push(`header_score=${d.score_percent}`);
        if(d.summary_by_category)bits.push(`tech=${JSON.stringify(d.summary_by_category).slice(0,300)}`);
        if(d.subdomains&&Array.isArray(d.subdomains))bits.push(`subdomains=${d.subdomains.length}`);
        if(d.error)bits.push(`error=${d.error}`);
        lines.push(`- ${k}: ${bits.join('; ')||'no notable data'}`);
    }
    return lines.join('\\n');
}

function attachScanToAi(entry){
    aiAttachedContext={entryId:String(entry.id),target:entry.target||'unknown',summary:summarizeScanForAi(entry)};
    aiAttachedIds.add(String(entry.id));persistAiAttached();
    renderAiContextBar();refreshAssetKpis();
    showToast(`Scan #${entry.id} attached to AI context`);
    navigateToSection('chat');
}

function attachAllScansToAi(entries){
    const done=(entries||[]).filter(e=>(e.status||'completed')==='completed');
    if(!done.length){showToast('No completed scans to attach','error');return;}
    const summary=done.map(summarizeScanForAi).join('\\n\\n---\\n\\n');
    aiAttachedContext={entryId:'batch',target:`${done.length} scans`,summary:summary.slice(0,50000)};
    done.forEach(e=>aiAttachedIds.add(String(e.id)));persistAiAttached();
    renderAiContextBar();refreshAssetKpis();
    showToast(`${done.length} scans attached to AI context`);
    navigateToSection('chat');
}

function detachAiContext(){
    aiAttachedContext=null;
    renderAiContextBar();refreshAssetKpis();
}

function renderAiContextBar(){
    const bar=document.getElementById('aiContextBar');
    const summary=document.getElementById('aiContextSummary');
    if(!bar)return;
    if(aiAttachedContext){
        bar.hidden=false;
        if(summary)summary.textContent=`Context: ${aiAttachedContext.target}${aiAttachedContext.entryId==='batch'?' (batch)':''} — ${aiAttachedContext.summary.length.toLocaleString()} chars`;
    }else{bar.hidden=true;}
}

function refreshAssetKpis(){
    const kpi=document.getElementById('assetKpiAiAttached');
    if(kpi)kpi.textContent=aiAttachedIds.size;
    document.querySelectorAll('.asset-ai-btn').forEach(btn=>{
        btn.classList.toggle('is-attached',aiAttachedIds.has(String(btn.dataset.id)));
        const lbl=btn.querySelector('span');
        if(lbl)lbl.textContent=aiAttachedIds.has(String(btn.dataset.id))?'Attached to AI':'AI';
    });
}

const aiContextBtn=document.getElementById('aiContextBtn');
if(aiContextBtn)aiContextBtn.addEventListener('click',detachAiContext);
const aiContextRemove=document.getElementById('aiContextRemove');
if(aiContextRemove)aiContextRemove.addEventListener('click',detachAiContext);
const assetsSendAllAiBtn=document.getElementById('assetsSendAllAiBtn');
if(assetsSendAllAiBtn)assetsSendAllAiBtn.addEventListener('click',()=>attachAllScansToAi(allHistory||[]));

"""

text = text[:start] + NEW_BLOCK + text[end:]

with io.open(P, "w", encoding="utf-8", newline="") as f:
    f.write(text)
print("AI block replaced OK")
