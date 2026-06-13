// ============================================================
// AutoFill Pro — Popup Script
// ============================================================

document.addEventListener('DOMContentLoaded', async () => {
  // Elements
  const activeName   = document.getElementById('popup-profile-name');
  const activeEmail  = document.getElementById('popup-profile-email');
  const activeIcon   = document.getElementById('popup-profile-icon');
  const activeMeta   = document.getElementById('popup-profile-meta');
  const badge        = document.getElementById('popup-fill-badge');
  const btnFill      = document.getElementById('btn-fill');
  const fillStatus   = document.getElementById('fill-status');
  const profilesList = document.getElementById('profiles-list');
  const toggleAuto   = document.getElementById('toggle-autofill');
  const btnSettings  = document.getElementById('btn-settings');
  const btnManage    = document.getElementById('btn-manage');
  const btnOpenOpt   = document.getElementById('btn-open-options');

  let currentProfile = null;
  let allProfiles = [];
  let settings = {};

  // ── Load Data ───────────────────────────────────────────
  async function loadData() {
    const res = await chrome.runtime.sendMessage({ type: 'GET_ALL_DATA' });
    if (!res || !res.ok) return;

    allProfiles = res.profiles || [];
    settings    = res.settings || {};
    currentProfile = allProfiles.find(p => p.id === settings.activeProfile) || allProfiles[0];

    if (!currentProfile) return;

    // Render Active Profile Card
    activeName.textContent  = currentProfile.name || 'Unnamed Profile';
    activeEmail.textContent = currentProfile.fields.email || currentProfile.fields.phone || 'No email set';
    activeIcon.textContent  = currentProfile.icon || '👤';
    activeIcon.style.background = currentProfile.color || '#3f3f46';

    // Render Meta
    const fields = currentProfile.fields;
    const filledCount = Object.values(fields).filter(v => v.trim() !== '').length;
    activeMeta.innerHTML = `
      <span class="meta-tag">${filledCount} fields mapped</span>
      ${fields.phone   ? `<span class="meta-tag">📞 ${fields.phone}</span>` : ''}
      ${fields.company ? `<span class="meta-tag">🏢 ${fields.company}</span>` : ''}
    `;

    // Render Auto-fill toggle
    toggleAuto.checked = !!settings.autoFill;

    // Render Profiles List
    profilesList.innerHTML = '';
    allProfiles.forEach(p => {
      const isActive = p.id === currentProfile.id;
      const item = document.createElement('div');
      item.className = `profile-item ${isActive ? 'active' : ''}`;
      item.innerHTML = `
        <div class="p-item-icon" style="color: ${p.color}">${p.icon}</div>
        <div class="p-item-name">${p.name}</div>
        <div class="p-item-check">✓</div>
      `;
      item.addEventListener('click', () => selectProfile(p.id));
      profilesList.appendChild(item);
    });

    // Check if we are on a page with a form
    checkForms();
  }

  // ── Select Profile ──────────────────────────────────────
  async function selectProfile(id) {
    if (settings.activeProfile === id) return;
    settings.activeProfile = id;
    await chrome.runtime.sendMessage({ type: 'SAVE_SETTINGS', settings });
    loadData();
  }

  // ── Check Forms on Active Tab ───────────────────────────
  async function checkForms() {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab || tab.url.startsWith('chrome://') || tab.url.startsWith('edge://')) {
      badge.textContent = 'Extension page';
      btnFill.disabled = true;
      btnFill.style.opacity = '0.5';
      btnFill.style.cursor = 'not-allowed';
      return;
    }

    try {
      const res = await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: () => {
          return document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="file"]):not([type="checkbox"]):not([type="radio"]), textarea, select').length;
        }
      });
      const count = res[0].result;
      if (count > 0) {
        badge.textContent = `${count} fields detected`;
        badge.style.color = '#10b981';
        badge.style.background = 'rgba(16, 185, 129, 0.1)';
        badge.style.borderColor = 'rgba(16, 185, 129, 0.3)';
      } else {
        badge.textContent = 'No form detected';
        badge.style.color = '#a1a1aa';
        badge.style.background = 'transparent';
        badge.style.borderColor = '#3f3f46';
      }
    } catch (err) {
      console.log('Cannot access page forms', err);
      badge.textContent = 'Protected page';
    }
  }

  // ── Actions ─────────────────────────────────────────────
  btnFill.addEventListener('click', async () => {
    const origText = btnFill.innerHTML;
    btnFill.innerHTML = 'Filling...';
    
    try {
      const res = await chrome.runtime.sendMessage({ type: 'FILL_PAGE' });
      if (res && res.ok) {
        fillStatus.textContent = '✨ Form filled successfully!';
        fillStatus.classList.add('show');
        setTimeout(() => fillStatus.classList.remove('show'), 3000);
      } else {
        fillStatus.textContent = '❌ Could not fill this page.';
        fillStatus.style.color = '#ef4444';
        fillStatus.classList.add('show');
      }
    } catch (err) {
      console.error(err);
    }

    setTimeout(() => { btnFill.innerHTML = origText; }, 1000);
  });

  toggleAuto.addEventListener('change', async (e) => {
    settings.autoFill = e.target.checked;
    await chrome.runtime.sendMessage({ type: 'SAVE_SETTINGS', settings });
  });

  const openOptions = () => chrome.runtime.openOptionsPage();
  btnSettings.addEventListener('click', openOptions);
  btnManage.addEventListener('click', openOptions);
  btnOpenOpt.addEventListener('click', openOptions);

  // Initialize
  loadData();
});
