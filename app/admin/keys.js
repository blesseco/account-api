import { $, $$, api, toast } from './api.js';

export async function loadKeys(){
  const r = await api('/v1/admin/list_keys');
  renderKeys(r.keys || r);
}

export async function createKey(){
  const key_id = $('#new_key_id').value.trim();
  if (!key_id) return alert('key_id required');
  const payload = {
    key_id,
    label: $('#new_label').value.trim(),
    can_upload: $('#new_upload').checked ? 1 : 0,
    can_consume: $('#new_consume').checked ? 1 : 0,
    active: $('#new_active').checked ? 1 : 0,
    daily_cap: Number($('#new_cap').value || 5000),
    rpm_limit: Number($('#new_rpm').value || 60),
  };
  const r = await api('/v1/admin/create_key', { method:'POST', body: JSON.stringify(payload) });
  if (r.api_key) { await navigator.clipboard.writeText(r.api_key); toast('Created & copied'); }
  await loadKeys();
}

function rowHtml(k){
  return `
  <td><code>${k.key_id}</code></td>
  <td>${k.label || ''}</td>
  <td><input type="checkbox" ${k.active? 'checked':''} data-field="active"></td>
  <td><input type="checkbox" ${k.can_upload? 'checked':''} data-field="can_upload"></td>
  <td><input type="checkbox" ${k.can_consume? 'checked':''} data-field="can_consume"></td>
  <td><input type="number" class="w-70" data-field="rpm_limit" value="${k.rpm_limit ?? 60}"></td>
  <td><input type="number" class="w-90" data-field="daily_cap" value="${k.daily_cap ?? 5000}"></td>
  <td>${k.created_at || ''}</td>
  <td>
    <button class="btn s" data-act="reveal">Reveal + Copy</button>
    <button class="btn s warn" data-act="regen">Regen + Copy</button>
    <button class="btn s" data-act="copyid">Copy ID</button>
    <button class="btn s danger" data-act="delete">Delete</button>
  </td>`;
}

function bindRowEvents(tbody){
  // actions
  tbody.addEventListener('click', async (e)=>{
    const btn = e.target.closest('[data-act]'); if (!btn) return;
    const tr = btn.closest('tr'); const key_id = tr.dataset.key;
    const act = btn.dataset.act;
    try{
      if (act === 'reveal'){
        const r = await api('/v1/admin/show_secret',{method:'POST', body: JSON.stringify({key_id})});
        await navigator.clipboard.writeText(r.api_key); toast('Copied');
      } else if (act === 'regen'){
        const r = await api('/v1/admin/regen_secret',{method:'POST', body: JSON.stringify({key_id})});
        await navigator.clipboard.writeText(r.api_key); toast('Regenerated & copied');
      } else if (act === 'copyid'){
        await navigator.clipboard.writeText(key_id); toast('Key id copied');
      } else if (act === 'delete'){
        if (!confirm(`Delete ${key_id}?`)) return;
        await api('/v1/admin/delete_key',{method:'POST', body: JSON.stringify({key_id})});
        tr.remove();
      }
    }catch(err){ alert(err.message); }
  });

  // inline updates
  tbody.addEventListener('change', async (e)=>{
    const el = e.target;
    const field = el.dataset.field; if(!field) return;
    const tr = el.closest('tr'); const key_id = tr.dataset.key;
    const value = el.type === 'checkbox' ? (el.checked ? 1 : 0) : Number(el.value);
    try{
      await api('/v1/admin/update_key',{method:'POST', body: JSON.stringify({key_id, [field]: value})});
      toast('Saved');
    }catch(err){ alert('Update failed: '+err.message); }
  });
}

function renderKeys(keys){
  const tbody = $('#keysTbody');
  tbody.innerHTML = '';
  keys.forEach(k=>{
    const tr = document.createElement('tr');
    tr.dataset.key = k.key_id;
    tr.innerHTML = rowHtml(k);
    tbody.appendChild(tr);
  });
  bindRowEvents(tbody);
}

