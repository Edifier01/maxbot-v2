const token = location.pathname.split('/').filter(Boolean).at(-1);
const root = document.querySelector('#guest');
const storageKey = 'maxbot:onboarding-session';
let session = '';
let timer;
let expiresAt = '';

const esc = value => String(value ?? '').replace(/[&<>"']/g, character => ({
  '&': '&amp;',
  '<': '&lt;',
  '>': '&gt;',
  '"': '&quot;',
  "'": '&#39;',
}[character]));

const errors = {
  proxy_assignment_required: 'Для группы пока не настроен доступный прокси. Сообщите владельцу группы.',
  proxy_unavailable: 'Не удалось открыть назначенный прокси. Владелец может исправить его и повторить подключение.',
  onboarding_in_progress: 'Подключение этого номера уже выполняется. Вернитесь к открытой странице или обновите её.',
  phone_already_exists: 'Этот номер уже подключён или назначен другой группе. Обратитесь к владельцу группы.',
  invite_unavailable: 'Ссылка истекла, отозвана или достигла лимита. Попросите владельца выдать новую.',
  onboarding_rate_limited: 'Слишком много попыток. Подождите и попробуйте позже.',
  code_rate_limited: 'Слишком много попыток ввода кода. Подождите и попробуйте позже.',
  password_rate_limited: 'Слишком много попыток ввода пароля. Подождите и попробуйте позже.',
  invalid_russian_phone: '\u0412\u0432\u0435\u0434\u0438\u0442\u0435 10 \u0446\u0438\u0444\u0440 \u0440\u043e\u0441\u0441\u0438\u0439\u0441\u043a\u043e\u0433\u043e \u043d\u043e\u043c\u0435\u0440\u0430; \u043c\u043e\u0436\u043d\u043e \u0443\u043a\u0430\u0437\u0430\u0442\u044c \u043a\u043e\u0434 7 \u0438\u043b\u0438 8.',
  proxy_check_failed: '\u041d\u0430\u0437\u043d\u0430\u0447\u0435\u043d\u043d\u044b\u0439 \u043f\u0440\u043e\u043a\u0441\u0438 \u043d\u0435 \u043f\u0440\u043e\u0448\u0451\u043b \u043f\u0440\u043e\u0432\u0435\u0440\u043a\u0443. \u0412\u043b\u0430\u0434\u0435\u043b\u0435\u0446 \u0433\u0440\u0443\u043f\u043f\u044b \u043c\u043e\u0436\u0435\u0442 \u043f\u0435\u0440\u0435\u043f\u0440\u043e\u0432\u0435\u0440\u0438\u0442\u044c \u0435\u0433\u043e \u0438\u043b\u0438 \u043d\u0430\u0437\u043d\u0430\u0447\u0438\u0442\u044c \u0434\u0440\u0443\u0433\u043e\u0439.',
  auto_join_failed: '\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u0432\u0441\u0442\u0443\u043f\u0438\u0442\u044c \u0432 \u0433\u0440\u0443\u043f\u043f\u0443 \u0430\u0432\u0442\u043e\u043c\u0430\u0442\u0438\u0447\u0435\u0441\u043a\u0438. \u041e\u0442\u043a\u0440\u043e\u0439\u0442\u0435 \u043f\u0440\u0438\u0433\u043b\u0430\u0448\u0435\u043d\u0438\u0435 \u0433\u0440\u0443\u043f\u043f\u044b \u0432\u044b\u0448\u0435 \u0438 \u0432\u0441\u0442\u0443\u043f\u0438\u0442\u0435 \u0432\u0440\u0443\u0447\u043d\u0443\u044e.',
  membership_check_unavailable: '\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u043f\u0440\u043e\u0432\u0435\u0440\u0438\u0442\u044c \u0447\u043b\u0435\u043d\u0441\u0442\u0432\u043e. \u041f\u043e\u043f\u0440\u043e\u0431\u0443\u0439\u0442\u0435 \u043f\u043e\u0437\u0436\u0435.',
  membership_not_confirmed: '\u041d\u0435 \u0443\u0434\u0430\u043b\u043e\u0441\u044c \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0434\u0438\u0442\u044c \u0432\u0441\u0442\u0443\u043f\u043b\u0435\u043d\u0438\u0435. \u041f\u043e\u0434\u0442\u0432\u0435\u0440\u0434\u0438\u0442\u0435 \u0435\u0433\u043e \u043a\u043d\u043e\u043f\u043a\u043e\u0439 \u043d\u0438\u0436\u0435.',
  invalid_code: 'Введите код MAX из 4–8 цифр.',
  invalid_password: 'Введите облачный пароль MAX.',
  network_timeout: 'Не удалось получить ответ от MAX. Проверьте сеть и назначенный прокси.',
  network_error: 'Нет связи с панелью. Проверьте интернет и повторите попытку.',
  code_rejected: 'MAX не принял код. Проверьте последние цифры и при необходимости начните попытку заново.',
  password_rejected: 'MAX отклонил облачный пароль. Начните попытку заново и проверьте пароль.',
  max_auth_request_failed: 'MAX не принял запрос кода. Подождите и попробуйте позже.',
  auth_token_missing: 'MAX не подтвердил вход. Проверьте код и запустите подключение заново.',
  proxy_assignment_changed: 'Назначенный прокси изменился во время подключения. Начните попытку заново.',
  account_assignment_changed_during_verification: 'Назначение аккаунта или прокси изменилось. Повторите проверку.',
  code_entry_timeout: 'Время ожидания кода истекло. Запустите подключение ещё раз.',
  password_entry_timeout: 'Время ожидания пароля истекло. Запустите подключение ещё раз.',
  session_save_failed: 'MAX не удалось сохранить сессию. Попросите владельца проверить подключение.',
  group_resolution_failed: 'Не удалось проверить ссылку MAX. Проверьте ссылку и попробуйте позже.',
  group_destination_mismatch: 'Ссылка ведёт в другую группу. Сообщите владельцу группы.',
  account_registration_required: 'Для этого номера MAX требует завершить регистрацию в приложении.',
  cloud_password_rejected: 'Облачный пароль MAX не подошёл. Запустите подключение ещё раз.',
  cancelled_by_guest: 'Подключение отменено.',
  onboarding_attempt_expired: 'Время этой попытки истекло. Запустите подключение ещё раз.',
  process_interrupted: 'Приложение перезапустилось до завершения попытки. Запустите подключение ещё раз.',
  request_timeout: 'MAX не ответил на запрос кода. Проверьте сеть и назначенный прокси.',
  runtimeerror: 'MAX отклонил авторизацию. Проверьте код и повторите подключение.',
  adapterunavailable: 'Клиент MAX временно недоступен. Попросите владельца проверить сервер.',
};

function friendly(error) {
  const value = error?.message || String(error || '');
  return errors[value] || 'Не удалось выполнить действие. Проверьте данные и повторите попытку.';
}

function getStoredSession() {
  try { return sessionStorage.getItem(storageKey) || ''; } catch { return ''; }
}

function storeSession(value) {
  try {
    if (value) sessionStorage.setItem(storageKey, value);
    else sessionStorage.removeItem(storageKey);
  } catch { /* Storage can be disabled; the current page still works. */ }
}

async function api(path, body) {
  let response;
  try {
    response = await fetch(path, {
      method: body ? 'POST' : 'GET',
      headers: body ? { 'Content-Type': 'application/json' } : {},
      body: body ? JSON.stringify(body) : undefined,
      cache: 'no-store',
    });
  } catch {
    throw Error('network_error');
  }
  const data = await response.json().catch(() => ({}));
  if (!response.ok) throw Error(data.detail || 'request_failed');
  return data;
}

function setError(target, error) {
  const element = document.querySelector(target);
  if (element) element.textContent = error ? friendly(error) : '';
}

function clearSession() {
  clearTimeout(timer);
  session = '';
  expiresAt = '';
  storeSession('');
}

function showStartForm() {
  clearSession();
  const form = document.querySelector('#start');
  if (form) form.hidden = false;
  const flow = document.querySelector('#flow');
  if (flow) flow.innerHTML = '';
}

function terminalMessage(text, { error = false, retryable = false } = {}) {
  clearTimeout(timer);
  const flow = document.querySelector('#flow');
  if (!flow) return;
  flow.innerHTML = `<div class="panel"><p class="${error ? 'error' : 'muted'}" role="status">${esc(text)}</p>${retryable ? '<button type="button" id="retry">Повторить подключение</button>' : ''}</div>`;
  document.querySelector('#retry')?.addEventListener('click', showStartForm);
}

function remainingTime() {
  if (!expiresAt) return '';
  const seconds = Math.max(0, Math.ceil((Date.parse(expiresAt) - Date.now()) / 1000));
  return ` · осталось ${Math.floor(seconds / 60)}:${String(seconds % 60).padStart(2, '0')}`;
}

function addCancelButton(form) {
  if (form.querySelector('[data-cancel]')) return;
  const button = document.createElement('button');
  button.type = 'button';
  button.className = 'secondary';
  button.dataset.cancel = '1';
  button.textContent = 'Отменить подключение';
  button.addEventListener('click', cancelAttempt);
  form.append(button);
}

async function init() {
  try {
    const invite = await api(`/join-info/${token}`);
    root.innerHTML = `<h1>${esc(invite.group)}</h1><p>Укажите имя и номер MAX. Затем введите код и, если потребуется, облачный пароль.</p><form id="start"><label>ФИО<input name="full_name" required maxlength="120" autocomplete="name"></label><label>Телефон<input name="phone" type="tel" required placeholder="+7…" autocomplete="tel"></label><button>Начать подключение</button><p class="error" id="start-error" role="alert"></p></form><p class="muted">После авторизации программа сама попробует вступить в группу. Если не получится, откройте приглашение выше и вступите вручную.</p><p><a target="_blank" rel="noreferrer" href="${esc(invite.invite_link)}">Открыть приглашение группы MAX</a></p><div id="flow" aria-live="polite"></div>`;
    document.querySelector('#start').onsubmit = async event => {
      event.preventDefault();
      const form = event.currentTarget;
      const button = form.querySelector('button');
      button.disabled = true;
      setError('#start-error', null);
      try {
        const data = await api(`/api/public/onboarding/${token}/start`, Object.fromEntries(new FormData(form)));
        session = data.session_id;
        storeSession(session);
        form.hidden = true;
        poll();
      } catch (error) {
        setError('#start-error', error);
      } finally {
        button.disabled = false;
      }
    };
    session = getStoredSession();
    if (session) {
      document.querySelector('#start').hidden = true;
      poll();
    }
  } catch (error) {
    root.innerHTML = `<p class="error" role="alert">${esc(friendly(error))}</p>`;
  }
}

function message(text, error = false) {
  const element = document.querySelector('#flow');
  if (element) element.innerHTML = `<p class="${error ? 'error' : 'muted'}" role="status">${esc(text)}</p>`;
}

function ensureCodeForm(hint, requestCountLeft, codeLength) {
  if (!document.querySelector('#code')) {
    document.querySelector('#flow').innerHTML = `<form id="code"><h3>Введите код MAX</h3><p class="muted" id="code-hint"></p><label>Код<input name="code" inputmode="numeric" autocomplete="one-time-code" required></label><button>Проверить код</button><p class="error" id="code-error" role="alert"></p></form>`;
    document.querySelector('#code').onsubmit = submitForm('code', '#code-error');
    addCancelButton(document.querySelector('#code'));
  }
  const hintElement = document.querySelector('#code-hint');
  const metadata = [];
  if (codeLength) metadata.push(`Введите ${codeLength} цифр.`);
  if (Number.isInteger(requestCountLeft)) metadata.push(`Запросов осталось: ${requestCountLeft}.`);
  if (hintElement) hintElement.textContent = `${hint || 'Ожидается сообщение с кодом MAX.'} ${metadata.join(' ')}${remainingTime()}`;
  const input = document.querySelector('#code input');
  if (input && codeLength) {
    input.maxLength = codeLength;
    input.minLength = codeLength;
  }
}

function ensurePasswordForm(hint) {
  if (!document.querySelector('#password')) {
    document.querySelector('#flow').innerHTML = `<form id="password"><h3>Облачный пароль MAX</h3><p class="muted" id="password-hint"></p><label>Пароль<input name="password" type="password" autocomplete="current-password" required></label><button>Продолжить</button><p class="error" id="password-error" role="alert"></p></form>`;
    document.querySelector('#password').onsubmit = submitForm('password', '#password-error');
    addCancelButton(document.querySelector('#password'));
  }
  const hintElement = document.querySelector('#password-hint');
  if (hintElement) hintElement.textContent = `${hint || 'Введите облачный пароль MAX.'}${remainingTime()}`;
}

function ensureMembership(errorCode = '') {
  if (document.querySelector('#check')) return;
  const reason = errorCode ? friendly(errorCode) : '\u041f\u0440\u043e\u0433\u0440\u0430\u043c\u043c\u0430 \u043f\u043e\u043f\u044b\u0442\u0430\u0435\u0442\u0441\u044f \u0432\u0441\u0442\u0443\u043f\u0438\u0442\u044c \u0432 \u0433\u0440\u0443\u043f\u043f\u0443. \u0415\u0441\u043b\u0438 \u0430\u0432\u0442\u043e\u043c\u0430\u0442\u0438\u0447\u0435\u0441\u043a\u043e\u0435 \u0432\u0441\u0442\u0443\u043f\u043b\u0435\u043d\u0438\u0435 \u043d\u0435 \u0441\u0440\u0430\u0431\u043e\u0442\u0430\u0435\u0442, \u043e\u0442\u043a\u0440\u043e\u0439\u0442\u0435 \u043f\u0440\u0438\u0433\u043b\u0430\u0448\u0435\u043d\u0438\u0435 \u0432\u044b\u0448\u0435.';
  document.querySelector('#flow').innerHTML = `<div class="panel"><p class="error" role="status">${esc(reason)}</p><p>\u041f\u043e\u0441\u043b\u0435 \u0432\u0441\u0442\u0443\u043f\u043b\u0435\u043d\u0438\u044f \u043d\u0430\u0436\u043c\u0438\u0442\u0435 \u043a\u043d\u043e\u043f\u043a\u0443 \u043d\u0438\u0436\u0435, \u0447\u0442\u043e\u0431\u044b \u043f\u043e\u0434\u0442\u0432\u0435\u0440\u0434\u0438\u0442\u044c \u0447\u043b\u0435\u043d\u0441\u0442\u0432\u043e.</p><button id="check">\u041f\u0440\u043e\u0432\u0435\u0440\u0438\u0442\u044c \u0432\u0441\u0442\u0443\u043f\u043b\u0435\u043d\u0438\u0435</button><button type="button" class="secondary" id="cancel">\u041e\u0442\u043c\u0435\u043d\u0438\u0442\u044c \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0435\u043d\u0438\u0435</button><p id="check-result" role="status"></p></div>`;
  document.querySelector('#check').onclick = async event => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      const result = await api(`/api/public/onboarding/${token}/${session}/check-membership`, {});
      document.querySelector('#check-result').textContent = result.completed ? '\u041d\u043e\u043c\u0435\u0440 \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0451\u043d. \u041c\u043e\u0436\u043d\u043e \u0437\u0430\u043a\u0440\u044b\u0442\u044c \u0441\u0442\u0440\u0430\u043d\u0438\u0446\u0443.' : '\u041f\u043e\u043a\u0430 \u043d\u0435 \u0432\u0438\u0434\u0438\u043c \u0432\u0441\u0442\u0443\u043f\u043b\u0435\u043d\u0438\u0435. \u041f\u0440\u043e\u0432\u0435\u0440\u044c\u0442\u0435 \u0433\u0440\u0443\u043f\u043f\u0443 MAX \u0438 \u043f\u043e\u0432\u0442\u043e\u0440\u0438\u0442\u0435.';
      if (result.completed) terminalMessage('\u041d\u043e\u043c\u0435\u0440 \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0451\u043d. \u041c\u043e\u0436\u043d\u043e \u0437\u0430\u043a\u0440\u044b\u0442\u044c \u0441\u0442\u0440\u0430\u043d\u0438\u0446\u0443.');
    } catch (error) {
      document.querySelector('#check-result').textContent = friendly(error);
    } finally {
      button.disabled = false;
    }
  };
  document.querySelector('#cancel').addEventListener('click', cancelAttempt);
}

async function cancelAttempt() {
  const buttons = document.querySelectorAll('#flow button');
  buttons.forEach(button => { button.disabled = true; });
  try {
    await api(`/api/public/onboarding/${token}/${session}/cancel`, {});
    terminalMessage('Подключение отменено.', { retryable: true });
    clearSession();
  } catch (error) {
    message(friendly(error), true);
  } finally {
    buttons.forEach(button => { button.disabled = false; });
  }
}

async function poll() {
  clearTimeout(timer);
  try {
    const data = await api(`/api/public/onboarding/${token}/${session}`);
    expiresAt = data.expires_at || '';
    if (data.state === 'waiting_code') ensureCodeForm(data.hint, data.request_count_left, data.code_length);
    else if (data.state === 'waiting_password') ensurePasswordForm(data.hint);
    else if (data.state === 'waiting_membership') ensureMembership(data.error_code || data.error || '');
    else if (data.state === 'completed') {
      clearSession();
      terminalMessage('Номер подключён. Можно закрыть страницу.');
      return;
    } else if (data.state === 'failed' || data.state === 'expired' || data.state === 'cancelled') {
      const reason = data.hint || errors[data.error] || 'Подключение не завершилось. Попросите владельца группы проверить состояние.';
      clearSession();
      terminalMessage(reason, { error: data.state !== 'cancelled', retryable: data.retryable });
      return;
    } else {
      const progress = document.querySelector('#progress');
      if (progress) progress.textContent = `Подключаемся к MAX…${remainingTime()}`;
      else document.querySelector('#flow').innerHTML = `<p class="muted" id="progress" role="status">Подключаемся к MAX…${remainingTime()}</p><button type="button" class="secondary" id="cancel">Отменить подключение</button>`;
      document.querySelector('#cancel')?.addEventListener('click', cancelAttempt, { once: true });
    }
    timer = setTimeout(poll, 1500);
  } catch (error) {
    if (error.message === 'onboarding_session_unavailable') {
      clearSession();
      const start = document.querySelector('#start');
      if (start) start.hidden = false;
      message('Предыдущая попытка не найдена. Введите данные и начните заново.', true);
      return;
    }
    if (document.querySelector('#code')) setError('#code-error', error);
    else if (document.querySelector('#password')) setError('#password-error', error);
    else message(friendly(error), true);
    timer = setTimeout(poll, 3000);
  }
}

function submitForm(kind, errorTarget) {
  return async event => {
    event.preventDefault();
    const form = event.currentTarget;
    const button = form.querySelector('button');
    const data = Object.fromEntries(new FormData(form));
    button.disabled = true;
    setError(errorTarget, null);
    try {
      await api(`/api/public/onboarding/${token}/${session}/${kind}`, data);
      const input = form.querySelector('input');
      if (input) input.value = '';
      poll();
    } catch (error) {
      setError(errorTarget, error);
    } finally {
      button.disabled = false;
    }
  };
}

init();
