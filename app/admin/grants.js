import { $, api } from './api.js';

export async function loadGrants(){
  const r = await api('/v1/admin/list_grants'); // shape: { owners:[], consumers:[], data:{consumer:{owner:1}} }
  renderMatrix(r);
}

function renderMatrix(m){
  const owners = m.owners || Object.keys(m.columns || {});
  const consumers = m.consumers || Object.keys(m.rows || {});
  const table = $('#grantsTable');
  table.querySelector('thead tr').innerHTML =
    '<th>Consumer / Owner →</th>' + owners.map(o=>`<th>${o}</th>`).join('') + '<th>Actions</th>';
  const tbody = table.querySelector('tbody');
  tbody.innerHTML = '';

  consumers.forEach(c=>{
    const tr = document.createElement('tr'); tr.dataset.consumer = c;
    const cells = owners.map(o=>{
      const granted = !!(m.data?.[c]?.[o] ?? m.rows?.[c]?.[o]);
      return `<td class="t-center"><input type="checkbox" class="grant" data-owner="${o}" ${granted?'checked':''}></td>`;
    }).join('');
    tr.innerHTML = `<td>${c}</td>${cells}
      <td><button class="btn s" data-act="grantall">Grant all</button>
          <button class="btn s" data-act="revokeall">Revoke all</button></td>`;
    tbody.appendChild(tr);
  });

  // events
  tbody.addEventListener('change', async (e)=>{
    const box = e.target.closest('.grant'); if(!box) return;
    const consumer = box.closest('tr').dataset.consumer;
    const owner = box.dataset.owner;
    try{
      if (box.checked){
        await api('/v1/admin/grant',{method:'POST', body: JSON.stringify({consumer, owner})});
      }else{
        await api('/v1/admin/revoke',{method:'POST', body: JSON.stringify({consumer, owner})});
      }
    }catch(err){ alert(err.message); box.checked = !box.checked; }
  });

  tbody.addEventListener('click', async (e)=>{
    const btn = e.target.closest('[data-act]'); if(!btn) return;
    const tr = btn.closest('tr'); const consumer = tr.dataset.consumer;
    const owners = ownersFromRow(tr);
    try{
      if (btn.dataset.act === 'grantall'){
        await api('/v1/admin/grant',{method:'POST', body: JSON.stringify({consumer, owners})});
        owners.forEach(o=> tr.querySelector(`[data-owner="${o}"]`).checked = true);
      } else {
        await api('/v1/admin/revoke',{method:'POST', body: JSON.stringify({consumer, owners})});
        owners.forEach(o=> tr.querySelector(`[data-owner="${o}"]`).checked = false);
      }
    }catch(err){ alert(err.message); }
  });
}

function ownersFromRow(tr){
  return Array.from(tr.querySelectorAll('input.grant')).map(x=>x.dataset.owner);
}

