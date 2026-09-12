const base=(import.meta.env.VITE_API_BASE_URL||'').replace(/\/$/,'');
export async function api(path,{method='GET',body,token='',text=false,timeoutMs=20000}={}){
 const controller=new AbortController();const timer=setTimeout(()=>controller.abort(),timeoutMs);
 try{const r=await fetch(`${base}/api/v1/triage${path}`,{method,headers:{...(body instanceof FormData?{}:{'Content-Type':'application/json'}),...(token?{'X-API-Key':token}:{})},body:body===undefined?undefined:body instanceof FormData?body:JSON.stringify(body),signal:controller.signal});if(!r.ok){const e=await r.json().catch(()=>({}));throw Error(Array.isArray(e.detail)?e.detail.map(x=>x.msg).join('; '):e.detail||`API request failed (${r.status})`)}return text?r.text():r.json()}catch(e){if(e.name==='AbortError')throw Error('Request timed out. Check the backend.');if(e instanceof TypeError)throw Error('Cannot reach Triage-6. Start the backend on port 8000.');throw e}finally{clearTimeout(timer)}
}
export function liveURL(){const u=new URL(base||location.origin);u.protocol=u.protocol==='https:'?'wss:':'ws:';u.pathname='/ws/events';return u.toString()}
export function download(name,content,type='text/markdown'){const url=URL.createObjectURL(new Blob([content],{type}));const a=document.createElement('a');a.href=url;a.download=name;a.click();setTimeout(()=>URL.revokeObjectURL(url),1000)}
