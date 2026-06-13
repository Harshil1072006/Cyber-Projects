// ============================================================
// AutoFill Pro — Background Service Worker
// ============================================================

// ── Default profile structure ──────────────────────────────
const DEFAULT_PROFILE = {
  id: 'default',
  name: 'Personal',
  color: '#7c3aed',
  icon: '👤',
  fields: {
    fullName:      '',
    firstName:     '',
    lastName:      '',
    email:         '',
    emailAlt:      '',
    phone:         '',
    mobile:        '',
    address1:      '',
    address2:      '',
    city:          '',
    state:         '',
    zip:           '',
    country:       '',
    dob:           '',
    company:       '',
    jobTitle:      '',
    website:       '',
    username:      '',
    linkedin:      '',
    twitter:       '',
    github:        '',
  }
};

const DEFAULT_SETTINGS = {
  autoFill:       false,
  highlightFills: true,
  activeProfile:  'default',
  showBadge:      true,
};

// ── Initialize storage on install ─────────────────────────
chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === 'install') {
    await chrome.storage.local.set({
      profiles:  [DEFAULT_PROFILE],
      settings:  DEFAULT_SETTINGS,
      version:   '1.0.0',
    });
    console.log('[AutoFill Pro] Initialized with default profile.');
  }
});

// ── Message handler ────────────────────────────────────────
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  handleMessage(message, sender).then(sendResponse).catch(err => {
    console.error('[AutoFill Pro BG] Error:', err);
    sendResponse({ ok: false, error: err.message });
  });
  return true; // Keep channel open for async
});

async function handleMessage(msg, sender) {
  switch (msg.type) {

    case 'GET_ACTIVE_PROFILE': {
      const data = await chrome.storage.local.get(['profiles', 'settings']);
      const settings = data.settings || DEFAULT_SETTINGS;
      const profiles = data.profiles || [DEFAULT_PROFILE];
      const active = profiles.find(p => p.id === settings.activeProfile) || profiles[0];
      return { ok: true, profile: active, settings };
    }

    case 'GET_ALL_DATA': {
      const data = await chrome.storage.local.get(['profiles', 'settings']);
      return { ok: true, ...data };
    }

    case 'SAVE_PROFILE': {
      const data = await chrome.storage.local.get('profiles');
      let profiles = data.profiles || [];
      const idx = profiles.findIndex(p => p.id === msg.profile.id);
      if (idx >= 0) {
        profiles[idx] = msg.profile;
      } else {
        profiles.push(msg.profile);
      }
      await chrome.storage.local.set({ profiles });
      return { ok: true };
    }

    case 'DELETE_PROFILE': {
      const data = await chrome.storage.local.get(['profiles', 'settings']);
      let profiles = (data.profiles || []).filter(p => p.id !== msg.profileId);
      if (profiles.length === 0) profiles = [DEFAULT_PROFILE];
      const settings = data.settings || DEFAULT_SETTINGS;
      if (settings.activeProfile === msg.profileId) {
        settings.activeProfile = profiles[0].id;
      }
      await chrome.storage.local.set({ profiles, settings });
      return { ok: true };
    }

    case 'SAVE_SETTINGS': {
      const data = await chrome.storage.local.get('settings');
      const settings = { ...(data.settings || DEFAULT_SETTINGS), ...msg.settings };
      await chrome.storage.local.set({ settings });
      return { ok: true };
    }

    case 'FILL_PAGE': {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      if (!tab) return { ok: false, error: 'No active tab' };
      const data = await chrome.storage.local.get(['profiles', 'settings']);
      const settings = data.settings || DEFAULT_SETTINGS;
      const profiles = data.profiles || [DEFAULT_PROFILE];
      const profile = profiles.find(p => p.id === settings.activeProfile) || profiles[0];
      await chrome.scripting.executeScript({
        target: { tabId: tab.id },
        func: injectFill,
        args: [profile.fields, settings.highlightFills],
      });
      return { ok: true };
    }

    case 'EXPORT_PROFILES': {
      const data = await chrome.storage.local.get('profiles');
      return { ok: true, data: JSON.stringify(data.profiles || [], null, 2) };
    }

    case 'IMPORT_PROFILES': {
      try {
        const imported = JSON.parse(msg.json);
        if (!Array.isArray(imported)) throw new Error('Invalid format');
        await chrome.storage.local.set({ profiles: imported });
        return { ok: true, count: imported.length };
      } catch (e) {
        return { ok: false, error: e.message };
      }
    }

    case 'FORM_DETECTED': {
      // Update badge to show form count
      if (sender.tab) {
        const count = msg.count || 0;
        chrome.action.setBadgeText({ text: count > 0 ? '✓' : '', tabId: sender.tab.id });
        chrome.action.setBadgeBackgroundColor({ color: '#7c3aed', tabId: sender.tab.id });
      }
      return { ok: true };
    }

    default:
      return { ok: false, error: `Unknown message type: ${msg.type}` };
  }
}

// ── Injected fill function (runs in page context) ──────────
function injectFill(fields, highlight) {
  const FIELD_MAP = {
    // Full name
    fullName:  [/^(full.?name|fullname|your.?name|name)$/i, ['name', 'fullname', 'full_name', 'full-name', 'yourname']],
    firstName: [/^(first.?name|fname|given.?name|forename)$/i, ['firstname', 'first_name', 'first-name', 'fname', 'given_name']],
    lastName:  [/^(last.?name|lname|surname|family.?name)$/i, ['lastname', 'last_name', 'last-name', 'lname', 'surname']],
    email:     [/^(e.?mail|email.?address|your.?email)$/i, ['email', 'mail', 'email_address', 'user_email']],
    emailAlt:  [/^(alt.?email|secondary.?email|email2)$/i, ['email2', 'alt_email', 'secondary_email']],
    phone:     [/^(phone|telephone|tel|phone.?number|contact.?number)$/i, ['phone', 'telephone', 'tel', 'phone_number', 'contact']],
    mobile:    [/^(mobile|cell|cell.?phone|mobile.?number)$/i, ['mobile', 'cell', 'cellphone', 'mobile_number']],
    address1:  [/^(address|address.?1|street|street.?address|addr)$/i, ['address', 'address1', 'street', 'street_address', 'addr1']],
    address2:  [/^(address.?2|apt|apartment|suite|unit)$/i, ['address2', 'apt', 'apartment', 'suite', 'unit']],
    city:      [/^(city|town|locality)$/i, ['city', 'town', 'locality']],
    state:     [/^(state|province|region)$/i, ['state', 'province', 'region', 'state_name']],
    zip:       [/^(zip|postal|postcode|zip.?code|postal.?code)$/i, ['zip', 'postal', 'postcode', 'zipcode', 'postal_code']],
    country:   [/^(country|nation|country.?name)$/i, ['country', 'nation', 'country_name']],
    dob:       [/^(dob|birth.?date|date.?of.?birth|birthday)$/i, ['dob', 'birthdate', 'birth_date', 'birthday', 'date_of_birth']],
    company:   [/^(company|organization|organisation|employer|business)$/i, ['company', 'organization', 'organisation', 'employer', 'business_name']],
    jobTitle:  [/^(title|job.?title|position|role|designation)$/i, ['title', 'job_title', 'position', 'role', 'designation']],
    website:   [/^(website|url|web|homepage|site)$/i, ['website', 'url', 'web', 'homepage', 'site_url']],
    username:  [/^(username|user.?name|login|handle|nick)$/i, ['username', 'user_name', 'login', 'handle', 'nickname']],
  };

  let filled = 0;
  const inputs = document.querySelectorAll('input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="file"]):not([type="checkbox"]):not([type="radio"]), textarea, select');

  inputs.forEach(input => {
    const attrs = [
      input.name || '',
      input.id || '',
      input.getAttribute('placeholder') || '',
      input.getAttribute('autocomplete') || '',
      input.getAttribute('aria-label') || '',
      input.closest('label')?.textContent?.trim() || '',
      input.previousElementSibling?.textContent?.trim() || '',
    ].map(a => a.toLowerCase());

    const inputType = (input.type || 'text').toLowerCase();

    // Try autocomplete attribute first (most reliable)
    const autocomplete = input.getAttribute('autocomplete') || '';
    const autocompleteMap = {
      'name':        'fullName',
      'given-name':  'firstName',
      'family-name': 'lastName',
      'email':       'email',
      'tel':         'phone',
      'tel-national':'phone',
      'street-address': 'address1',
      'address-line1':  'address1',
      'address-line2':  'address2',
      'address-level2': 'city',
      'address-level1': 'state',
      'postal-code':    'zip',
      'country':        'country',
      'country-name':   'country',
      'organization':   'company',
      'bday':           'dob',
      'url':            'website',
      'username':       'username',
    };

    let matchedKey = autocompleteMap[autocomplete.toLowerCase()];

    // Fall back to heuristic matching
    if (!matchedKey) {
      for (const [key, [regex, aliases]] of Object.entries(FIELD_MAP)) {
        const attrStr = attrs.join(' ');
        if (regex.test(attrStr) || aliases.some(a => attrs.some(attr => attr.includes(a)))) {
          matchedKey = key;
          break;
        }
      }
    }

    // Special: email type input
    if (!matchedKey && inputType === 'email') matchedKey = 'email';
    if (!matchedKey && inputType === 'tel')   matchedKey = 'phone';
    if (!matchedKey && inputType === 'url')   matchedKey = 'website';

    if (matchedKey && fields[matchedKey]) {
      const value = fields[matchedKey];

      if (input.tagName === 'SELECT') {
        const optionMatch = Array.from(input.options).find(o =>
          o.text.toLowerCase().includes(value.toLowerCase()) ||
          o.value.toLowerCase().includes(value.toLowerCase())
        );
        if (optionMatch) {
          input.value = optionMatch.value;
          input.dispatchEvent(new Event('change', { bubbles: true }));
          filled++;
        }
      } else {
        input.focus();
        input.value = value;
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
        input.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
        input.blur();
        filled++;

        if (highlight) {
          input.style.transition = 'box-shadow 0.3s ease, background 0.3s ease';
          input.style.boxShadow  = '0 0 0 3px rgba(124,58,237,0.6)';
          input.style.background = 'rgba(124,58,237,0.08)';
          setTimeout(() => {
            input.style.boxShadow  = '';
            input.style.background = '';
          }, 1800);
        }
      }
    }
  });

  return filled;
}

// ── Context menu ───────────────────────────────────────────
chrome.runtime.onInstalled.addListener(() => {
  // Create context menu (wrapper prevents duplicate ID errors on reload)
  chrome.contextMenus.create({
    id:       'autofill-fill',
    title:    '⚡ AutoFill Pro — Fill this page',
    contexts: ['page', 'editable'],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId === 'autofill-fill') {
    chrome.runtime.sendMessage({ type: 'FILL_PAGE' });
  }
});
