export const $  = (s, r=document) => r.querySelector(s);
export const $$ = (s, r=document) => Array.from(r.querySelectorAll(s));
export function toast(m){ console.log('[ui]', m); }

export function xApiKey(){ return localStorage.getItem('x_api_key') || ''; }
export function setKey(k){
  if (k) localStorage.setItem('x_api_key', k); else localStorage.removeItem('x_api_key');
  document.dispatchEvent(new Event('auth:changed'));
}

export async function api(path, opt = {}) {
  const method  = (opt.method || 'GET').toUpperCase();
  const headers = Object.assign({}, opt.headers || {});
  if (method !== 'GET' && method !== 'HEAD') headers['Content-Type'] = 'application/json';
  const key = xApiKey();
  if (key) headers['X-API-Key'] = key;

  const res = await fetch(path, Object.assign({}, opt, { headers }));
  if (!res.ok) throw new Error(await res.text().catch(()=>res.statusText));
  const ct = res.headers.get('content-type') || '';
  return ct.includes('application/json') ? res.json() : res.text();
}

