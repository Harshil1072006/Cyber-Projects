// ============================================================
// AutoFill Pro — Content Script
// Detects forms on page and handles auto-fill messaging
// ============================================================

(function () {
  'use strict';

  let formCount = 0;
  let alreadyScanned = false;

  // ── Count interactive form fields ──────────────────────
  function countFormFields() {
    return document.querySelectorAll(
      'input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="file"]):not([type="checkbox"]):not([type="radio"]), textarea, select'
    ).length;
  }

  // ── Notify background about forms ─────────────────────
  function notifyBackground(count) {
    chrome.runtime.sendMessage({ type: 'FORM_DETECTED', count }, () => {
      if (chrome.runtime.lastError) { /* extension context invalidated, ignore */ }
    });
  }

  // ── Scan on load ───────────────────────────────────────
  function initialScan() {
    if (alreadyScanned) return;
    alreadyScanned = true;
    formCount = countFormFields();
    if (formCount > 0) {
      notifyBackground(formCount);

      // Check if auto-fill is enabled
      chrome.runtime.sendMessage({ type: 'GET_ACTIVE_PROFILE' }, (res) => {
        if (chrome.runtime.lastError || !res) return;
        if (res.settings?.autoFill) {
          // Small delay so page JS finishes initializing inputs
          setTimeout(() => triggerFill(res.profile.fields, res.settings.highlightFills), 800);
        }
      });
    }
  }

  // ── Fill fields ────────────────────────────────────────
  function triggerFill(fields, highlight) {
    const FIELD_MAP = {
      fullName:  [/^(full.?name|fullname|your.?name|name)$/i, ['name','fullname','full_name','full-name','yourname']],
      firstName: [/^(first.?name|fname|given.?name|forename)$/i, ['firstname','first_name','first-name','fname','given_name']],
      lastName:  [/^(last.?name|lname|surname|family.?name)$/i, ['lastname','last_name','last-name','lname','surname']],
      email:     [/^(e.?mail|email.?address|your.?email)$/i, ['email','mail','email_address','user_email']],
      emailAlt:  [/^(alt.?email|secondary.?email|email2)$/i, ['email2','alt_email','secondary_email']],
      phone:     [/^(phone|telephone|tel|phone.?number|contact.?number)$/i, ['phone','telephone','tel','phone_number','contact']],
      mobile:    [/^(mobile|cell|cell.?phone|mobile.?number)$/i, ['mobile','cell','cellphone','mobile_number']],
      address1:  [/^(address|address.?1|street|street.?address|addr)$/i, ['address','address1','street','street_address','addr1']],
      address2:  [/^(address.?2|apt|apartment|suite|unit)$/i, ['address2','apt','apartment','suite','unit']],
      city:      [/^(city|town|locality)$/i, ['city','town','locality']],
      state:     [/^(state|province|region)$/i, ['state','province','region','state_name']],
      zip:       [/^(zip|postal|postcode|zip.?code|postal.?code)$/i, ['zip','postal','postcode','zipcode','postal_code']],
      country:   [/^(country|nation|country.?name)$/i, ['country','nation','country_name']],
      dob:       [/^(dob|birth.?date|date.?of.?birth|birthday)$/i, ['dob','birthdate','birth_date','birthday','date_of_birth']],
      company:   [/^(company|organization|organisation|employer|business)$/i, ['company','organization','organisation','employer','business_name']],
      jobTitle:  [/^(title|job.?title|position|role|designation)$/i, ['title','job_title','position','role','designation']],
      website:   [/^(website|url|web|homepage|site)$/i, ['website','url','web','homepage','site_url']],
      username:  [/^(username|user.?name|login|handle|nick)$/i, ['username','user_name','login','handle','nickname']],
    };

    const autocompleteMap = {
      'name':           'fullName',
      'given-name':     'firstName',
      'family-name':    'lastName',
      'email':          'email',
      'tel':            'phone',
      'tel-national':   'phone',
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

    let filled = 0;
    const inputs = document.querySelectorAll(
      'input:not([type="hidden"]):not([type="submit"]):not([type="button"]):not([type="file"]):not([type="checkbox"]):not([type="radio"]), textarea, select'
    );

    inputs.forEach(input => {
      const attrs = [
        input.name || '',
        input.id || '',
        (input.getAttribute('placeholder') || ''),
        (input.getAttribute('autocomplete') || ''),
        (input.getAttribute('aria-label') || ''),
        (input.closest('label')?.textContent?.trim() || ''),
        (input.previousElementSibling?.textContent?.trim() || ''),
      ].map(a => a.toLowerCase());

      const inputType = (input.type || 'text').toLowerCase();
      const autocomplete = (input.getAttribute('autocomplete') || '').toLowerCase();

      let matchedKey = autocompleteMap[autocomplete];

      if (!matchedKey) {
        for (const [key, [regex, aliases]] of Object.entries(FIELD_MAP)) {
          const attrStr = attrs.join(' ');
          if (regex.test(attrStr) || aliases.some(a => attrs.some(attr => attr.includes(a)))) {
            matchedKey = key;
            break;
          }
        }
      }

      if (!matchedKey && inputType === 'email') matchedKey = 'email';
      if (!matchedKey && inputType === 'tel')   matchedKey = 'phone';
      if (!matchedKey && inputType === 'url')   matchedKey = 'website';

      if (matchedKey && fields[matchedKey]) {
        const value = fields[matchedKey];

        if (input.tagName === 'SELECT') {
          const opt = Array.from(input.options).find(o =>
            o.text.toLowerCase().includes(value.toLowerCase()) ||
            o.value.toLowerCase().includes(value.toLowerCase())
          );
          if (opt) {
            input.value = opt.value;
            input.dispatchEvent(new Event('change', { bubbles: true }));
            filled++;
          }
        } else {
          input.focus();
          input.value = value;
          input.dispatchEvent(new Event('input',  { bubbles: true }));
          input.dispatchEvent(new Event('change', { bubbles: true }));
          input.dispatchEvent(new KeyboardEvent('keyup', { bubbles: true }));
          input.blur();
          filled++;

          if (highlight) {
            const prev = {
              transition: input.style.transition,
              boxShadow:  input.style.boxShadow,
              background: input.style.background,
            };
            input.style.transition = 'box-shadow 0.3s ease, background 0.3s ease';
            input.style.boxShadow  = '0 0 0 3px rgba(124,58,237,0.7)';
            input.style.background = 'rgba(124,58,237,0.07)';
            setTimeout(() => {
              input.style.transition = prev.transition;
              input.style.boxShadow  = prev.boxShadow;
              input.style.background = prev.background;
            }, 2000);
          }
        }
      }
    });

    return filled;
  }

  // ── Listen for fill trigger from popup/background ──────
  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.type === 'FILL_NOW') {
      const count = triggerFill(msg.fields, msg.highlight !== false);
      sendResponse({ ok: true, filled: count });
    }
    return true;
  });

  // ── Observe dynamic SPAs (React, Vue, etc.) ───────────
  let debounceTimer;
  const observer = new MutationObserver(() => {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => {
      const newCount = countFormFields();
      if (newCount !== formCount) {
        formCount = newCount;
        if (formCount > 0) notifyBackground(formCount);
      }
    }, 600);
  });

  observer.observe(document.body || document.documentElement, {
    childList: true,
    subtree: true,
  });

  // Run initial scan after small delay
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', () => setTimeout(initialScan, 500));
  } else {
    setTimeout(initialScan, 500);
  }
})();
