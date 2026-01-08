import { $, api, toast } from './api.js';

export async function loadStats(){
  const from = $('#fromDate').value;
  const to   = $('#toDate').value;
  const paths = [
    `/v1/admin/stats?from=${from}&to=${to}`,
    `/v1/admin/stats_main?from=${from}&to=${to}`,
    `/v1/admin/overview?from=${from}&to=${to}`,
    `/v1/admin/usage_stats?from=${from}&to=${to}`,
  ];

  let data = null;
  for (const p of paths){
    try{ data = await api(p); break; }
    catch { /* try next */ }
  }
  if (!data){ toast('Stats endpoint not found; tiles will stay blank.'); return; }
  renderStats(data);
}

function n(v){ return (v ?? 0).toLocaleString(); }
function setBox(id, v){ $(`${id} .value`).textContent = n(v); }

function renderStats(s){
  setBox('#boxUploaded',  s.uploaded);
  setBox('#boxUnused',    s.unused);
  setBox('#boxUsed',      s.used_total);
  setBox('#boxLocked',    s.locked);
  setBox('#boxRegSuccess',s.reg_success);
  setBox('#boxCode282',   s.code_282);

  const tbody = $('#ownersTbody'); tbody.innerHTML = '';
  (s.owners || []).forEach(o=>{
    const tr = document.createElement('tr');
    tr.innerHTML = `
      <td>${o.owner}</td>
      <td>${n(o.uploaded)}</td>
      <td>${n(o.unused)}</td>
      <td>${n(o.used)}</td>
      <td>${n(o.locked)}</td>
      <td>
        <span class="chip success">success ${n(o.breakup?.success)}</span>
        <span class="chip warn">282 ${n(o.breakup?.code_282)}</span>
        <span class="chip muted">other ${n(o.breakup?.other)}</span>
      </td>`;
    tbody.appendChild(tr);
  });
}

