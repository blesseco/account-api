import { $, api, setKey, xApiKey } from './api.js';

export function initAuth(){
  $('#btnLogin').addEventListener('click', ()=> $('#loginDlg').showModal());
  $('#btnLogout').addEventListener('click', ()=> { setKey(''); location.reload(); });

  $('#loginForm').addEventListener('submit', async (e)=>{
    e.preventDefault();
    const key = $('#login_api_key').value.trim();
    if (key) {
      setKey(key);
      $('#loginDlg').close();
      document.dispatchEvent(new Event('app:load'));
      return;
    }
    const email = $('#login_email').value.trim();
    const password = $('#login_password').value;
    if (email && password){
      try{
        const r = await api('/v1/admin/login', { method:'POST', body: JSON.stringify({email,password}) });
        if (r.api_key) {
          setKey(r.api_key);
          $('#loginDlg').close();
          document.dispatchEvent(new Event('app:load'));
        }
      }catch(err){ alert('Login failed: '+err.message); }
    }
  });

  // show who is logged in
  const setBadge = ()=> $('#meBadge').textContent = xApiKey() ? xApiKey().split('.')[0] : '—';
  setBadge();
  document.addEventListener('auth:changed', setBadge);
}

