import { $, setKey } from './api.js';
import { initAuth } from './auth.js';
import { loadStats } from './stats.js';
import { loadKeys, createKey } from './keys.js';
import { loadGrants } from './grants.js';

function todayStr(d){ return d.toISOString().slice(0,10); }

window.addEventListener('DOMContentLoaded', ()=>{
  // dates default
  const now = new Date();
  $('#toDate').value = todayStr(now);
  const d2 = new Date(now); d2.setDate(d2.getDate()-2);
  $('#fromDate').value = todayStr(d2);

  initAuth();

  // theme
  $('#btnTheme').addEventListener('click', ()=>{
    const root = document.documentElement;
    root.dataset.theme = root.dataset.theme === 'light' ? 'dark' : 'light';
  });

  // actions
  $('#btnRefreshStats').addEventListener('click', loadStats);
  $('#btnCreateKey').addEventListener('click', createKey);
  $('#btnRefreshKeys').addEventListener('click', loadKeys);
  $('#btnFind').addEventListener('click', ()=>alert('Helper action TODO'));

  // when auth changes, load everything
  document.addEventListener('app:load', async ()=>{
    await Promise.allSettled([loadStats(), loadKeys(), loadGrants()]);
  });

  // auto-load if key was already stored
  if (localStorage.getItem('x_api_key')) document.dispatchEvent(new Event('app:load'));
});

