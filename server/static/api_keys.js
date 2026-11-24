(function () {
  'use strict';

  const form = document.getElementById('api-key-form');
  const nameInput = document.getElementById('api-key-name');
  const submitBtn = document.getElementById('api-key-create-btn');
  const statusEl = document.getElementById('api-key-status');
  const createdBox = document.getElementById('api-key-created-box');
  const tokenValInput = document.getElementById('api-key-token-val');
  const copyBtn = document.getElementById('api-key-copy-btn');
  const copyFeedback = document.getElementById('api-key-copy-feedback');
  const listEl = document.getElementById('api-keys-list');
  const emptyEl = document.getElementById('api-keys-empty');

  let isBusy = false;
  let copyTimeout = null;

  function showStatus(msg, isSuccess) {
    if (!statusEl) return;
    if (!msg) {
      statusEl.className = 'alert is-hidden';
      statusEl.textContent = '';
      return;
    }
    statusEl.textContent = msg;
    statusEl.className = 'alert ' + (isSuccess ? 'alert-success' : 'alert-danger');
  }

  function setBusy(busy) {
    isBusy = busy;
    if (nameInput) nameInput.disabled = busy;
    if (submitBtn) submitBtn.disabled = busy;
    if (listEl) {
      const btns = listEl.querySelectorAll('button');
      for (let i = 0; i < btns.length; i++) {
        btns[i].disabled = busy;
      }
    }
  }

  function formatDate(val) {
    if (!val) return '—';
    let str = String(val);
    if (str.includes(' ') && !str.includes('T')) {
      str = str.replace(' ', 'T') + 'Z';
    }
    const d = new Date(str);
    return isNaN(d.getTime()) ? String(val) : d.toLocaleString();
  }

  async function request(url, opts) {
    opts = opts || {};
    const headers = Object.assign({}, opts.headers);
    headers['X-Requested-With'] = 'fetch';

    const fetchOpts = {
      method: opts.method || 'GET',
      credentials: 'same-origin',
      headers: headers
    };

    if (opts.json !== undefined) {
      headers['Content-Type'] = 'application/json';
      fetchOpts.body = JSON.stringify(opts.json);
    }

    const res = await fetch(url, fetchOpts);
    if (res.status === 401) {
      window.location.href = '/login';
      throw new Error('unauthorized');
    }
    if (res.status === 204) {
      return null;
    }

    let data = null;
    try {
      data = await res.json();
    } catch (_) {}

    if (!res.ok) {
      const detail = data && data.detail;
      const msg = (typeof detail === 'string' ? detail : (detail ? JSON.stringify(detail) : '')) ||
                  res.statusText || ('Ошибка ' + res.status);
      throw new Error(msg);
    }
    return data;
  }

  async function loadKeys() {
    if (!listEl) return;
    try {
      const keys = await request('/api/web/api-keys');
      listEl.textContent = '';
      if (!Array.isArray(keys) || keys.length === 0) {
        if (emptyEl) emptyEl.classList.remove('is-hidden');
        return;
      }
      if (emptyEl) emptyEl.classList.add('is-hidden');

      keys.forEach(function (keyItem) {
        const li = document.createElement('li');
        li.className = 'api-key-item';

        const infoDiv = document.createElement('div');
        infoDiv.className = 'api-key-info';

        const nameSpan = document.createElement('span');
        nameSpan.className = 'api-key-name';
        nameSpan.textContent = keyItem.name;

        const metaSpan = document.createElement('span');
        metaSpan.className = 'api-key-meta';
        metaSpan.textContent = 'Создан: ' + formatDate(keyItem.created_at);

        infoDiv.appendChild(nameSpan);
        infoDiv.appendChild(metaSpan);

        const revokeBtn = document.createElement('button');
        revokeBtn.type = 'button';
        revokeBtn.className = 'btn btn-danger btn-sm';
        revokeBtn.textContent = 'Отозвать';
        revokeBtn.setAttribute('aria-label', 'Отозвать ключ ' + keyItem.name);
        revokeBtn.disabled = isBusy;

        revokeBtn.addEventListener('click', async function () {
          if (isBusy || revokeBtn.disabled) return;
          const confirmMsg = 'Отозвать API-ключ «' + keyItem.name + '»? Доступ с этим ключом будет заблокирован.';
          if (!window.confirm(confirmMsg)) return;

          setBusy(true);
          showStatus('');
          try {
            await request('/api/web/api-keys/' + encodeURIComponent(keyItem.id), {
              method: 'DELETE'
            });
            showStatus('Ключ успешно отозван', true);
            await loadKeys();
          } catch (err) {
            if (err.message !== 'unauthorized') {
              showStatus(err.message, false);
            }
          } finally {
            setBusy(false);
          }
        });

        li.appendChild(infoDiv);
        li.appendChild(revokeBtn);
        listEl.appendChild(li);
      });
    } catch (err) {
      if (err.message !== 'unauthorized') {
        showStatus(err.message, false);
      }
    }
  }

  if (form) {
    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      if (isBusy) return;

      const name = (nameInput ? nameInput.value : '').trim();
      if (!name) {
        showStatus('Укажите имя ключа', false);
        return;
      }
      if (name.length > 80) {
        showStatus('Имя ключа не должно превышать 80 символов', false);
        return;
      }

      setBusy(true);
      showStatus('');
      if (copyFeedback) {
        copyFeedback.textContent = '';
        copyFeedback.classList.add('is-hidden');
      }

      try {
        const data = await request('/api/web/api-keys', {
          method: 'POST',
          json: { name: name }
        });

        form.reset();
        showStatus('API-ключ успешно создан', true);

        if (createdBox && tokenValInput && data && data.token) {
          tokenValInput.value = data.token;
          createdBox.classList.remove('is-hidden');
        }

        await loadKeys();
      } catch (err) {
        if (err.message !== 'unauthorized') {
          showStatus(err.message, false);
        }
      } finally {
        setBusy(false);
      }
    });
  }

  if (copyBtn && tokenValInput) {
    copyBtn.addEventListener('click', async function () {
      if (!tokenValInput.value) return;
      const textToCopy = tokenValInput.value;

      let copied = false;
      if (navigator.clipboard && typeof navigator.clipboard.writeText === 'function') {
        try {
          await navigator.clipboard.writeText(textToCopy);
          copied = true;
        } catch (_) {}
      }

      if (!copied) {
        try {
          tokenValInput.focus();
          tokenValInput.select();
          tokenValInput.setSelectionRange(0, 99999);
          copied = document.execCommand('copy');
        } catch (_) {}
      }

      if (copyFeedback) {
        copyFeedback.classList.remove('is-hidden');
        if (copied) {
          copyFeedback.textContent = 'Ключ скопирован в буфер обмена!';
          copyBtn.textContent = 'Скопировано!';
        } else {
          tokenValInput.focus();
          tokenValInput.select();
          copyFeedback.textContent = 'Не удалось скопировать автоматически. Скопируйте выделенный текст вручную.';
        }

        clearTimeout(copyTimeout);
        copyTimeout = setTimeout(function () {
          copyBtn.textContent = 'Копировать';
          if (copied && copyFeedback) {
            copyFeedback.classList.add('is-hidden');
            copyFeedback.textContent = '';
          }
        }, 3000);
      }
    });
  }

  setBusy(true);
  loadKeys().finally(function () {
    setBusy(false);
  });
})();
