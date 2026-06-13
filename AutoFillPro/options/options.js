// ============================================================
// AutoFill Pro — Options Script
// ============================================================

document.addEventListener('DOMContentLoaded', async () => {

  const FIELD_IDS = [
    'profileName', 'icon', 'color',
    'firstName', 'lastName', 'fullName', 'dob',
    'email', 'emailAlt', 'phone', 'mobile',
    'address1', 'address2', 'city', 'state', 'zip', 'country',
    'company', 'jobTitle', 'website', 'username'
  ];

  let profiles = [];
  let settings = {};
  let currentProfileId = null;

  // DOM Elements
  const navList = document.getElementById('nav-profiles-list');
  const btnAdd = document.getElementById('btn-add-profile');
  const navGeneral = document.getElementById('nav-general');
  const viewProfile = document.getElementById('view-profile');
  const viewSettings = document.getElementById('view-settings');
  const btnSave = document.getElementById('btn-save-profile');
  const btnDel = document.getElementById('btn-delete-profile');
  const toast = document.getElementById('toast');

  // Settings Toggles
  const setAutoFill = document.getElementById('set-autoFill');
  const setHighlight = document.getElementById('set-highlight');

  // Import/Export
  const btnExport = document.getElementById('btn-export');
  const btnImport = document.getElementById('btn-import');
  const fileImport = document.getElementById('file-import');

  // ── Initialization ──────────────────────────────────────
  async function loadData() {
    const res = await chrome.runtime.sendMessage({ type: 'GET_ALL_DATA' });
    profiles = res.profiles || [];
    settings = res.settings || {};
    
    renderNav();
    
    // Load general settings
    setAutoFill.checked = !!settings.autoFill;
    setHighlight.checked = settings.highlightFills !== false;

    // Open first profile by default
    if (profiles.length > 0) {
      openProfile(profiles[0].id);
    }
  }

  function renderNav() {
    navList.innerHTML = '';
    profiles.forEach(p => {
      const el = document.createElement('div');
      el.className = `nav-item ${p.id === currentProfileId ? 'active' : ''}`;
      el.innerHTML = `<span style="color:${p.color}">${p.icon}</span> ${p.name}`;
      el.addEventListener('click', () => openProfile(p.id));
      navList.appendChild(el);
    });
  }

  // ── Views ───────────────────────────────────────────────
  function switchView(viewId) {
    viewProfile.classList.add('hidden');
    viewSettings.classList.add('hidden');
    document.getElementById(viewId).classList.remove('hidden');

    // Update nav active states
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    if (viewId === 'view-settings') {
      navGeneral.classList.add('active');
      currentProfileId = null;
    }
  }

  navGeneral.addEventListener('click', () => switchView('view-settings'));

  // ── Profile Management ──────────────────────────────────
  function openProfile(id) {
    const p = profiles.find(x => x.id === id);
    if (!p) return;
    currentProfileId = id;

    // Populate form
    document.getElementById('f_profileName').value = p.name || '';
    document.getElementById('f_icon').value = p.icon || '👤';
    document.getElementById('f_color').value = p.color || '#7c3aed';

    FIELD_IDS.forEach(key => {
      if (['profileName', 'icon', 'color'].includes(key)) return;
      document.getElementById(`f_${key}`).value = p.fields[key] || '';
    });

    switchView('view-profile');
    renderNav(); // update active state in nav
  }

  btnAdd.addEventListener('click', () => {
    const newId = 'prof_' + Date.now();
    const newProfile = {
      id: newId,
      name: 'New Profile',
      color: '#3b82f6',
      icon: '👤',
      fields: {}
    };
    profiles.push(newProfile);
    openProfile(newId);
  });

  btnSave.addEventListener('click', async () => {
    if (!currentProfileId) return;
    const p = profiles.find(x => x.id === currentProfileId);
    if (!p) return;

    p.name = document.getElementById('f_profileName').value || 'Unnamed';
    p.icon = document.getElementById('f_icon').value || '👤';
    p.color = document.getElementById('f_color').value || '#7c3aed';

    FIELD_IDS.forEach(key => {
      if (['profileName', 'icon', 'color'].includes(key)) return;
      p.fields[key] = document.getElementById(`f_${key}`).value;
    });

    await chrome.runtime.sendMessage({ type: 'SAVE_PROFILE', profile: p });
    renderNav();
    showToast('Profile saved!');
  });

  btnDel.addEventListener('click', async () => {
    if (!currentProfileId) return;
    if (!confirm('Are you sure you want to delete this profile?')) return;

    await chrome.runtime.sendMessage({ type: 'DELETE_PROFILE', profileId: currentProfileId });
    profiles = profiles.filter(x => x.id !== currentProfileId);
    
    if (profiles.length > 0) {
      openProfile(profiles[0].id);
    } else {
      // Background script should recreate default, let's reload
      loadData();
    }
  });

  // ── Settings Save ───────────────────────────────────────
  async function saveSettings() {
    settings.autoFill = setAutoFill.checked;
    settings.highlightFills = setHighlight.checked;
    await chrome.runtime.sendMessage({ type: 'SAVE_SETTINGS', settings });
    showToast('Settings saved!');
  }

  setAutoFill.addEventListener('change', saveSettings);
  setHighlight.addEventListener('change', saveSettings);

  // ── Import / Export ─────────────────────────────────────
  btnExport.addEventListener('click', async () => {
    const res = await chrome.runtime.sendMessage({ type: 'EXPORT_PROFILES' });
    if (res.ok) {
      const blob = new Blob([res.data], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'autofill_profiles.json';
      a.click();
      URL.revokeObjectURL(url);
    }
  });

  btnImport.addEventListener('click', () => fileImport.click());

  fileImport.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = async (ev) => {
      const res = await chrome.runtime.sendMessage({ type: 'IMPORT_PROFILES', json: ev.target.result });
      if (res.ok) {
        showToast(`Imported ${res.count} profiles!`);
        loadData();
      } else {
        alert('Error importing profiles: ' + res.error);
      }
      fileImport.value = ''; // reset
    };
    reader.readAsText(file);
  });

  // ── Utils ───────────────────────────────────────────────
  function showToast(msg) {
    toast.textContent = msg;
    toast.classList.add('show');
    setTimeout(() => toast.classList.remove('show'), 3000);
  }

  // Run
  loadData();
});
