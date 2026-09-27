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
  ip_assignment_required: 'На VDS пока нет включённого IP для MAX. Сообщите владельцу группы.',
  ip_assignment_unavailable: 'Назначенный IP MAX недоступен. Владелец может выбрать другой IP.',
  onboarding_in_progress: 'Подключение этого номера уже выполняется. Вернитесь к открытой странице или обновите её.',
  phone_already_exists: 'Этот номер уже подключён или назначен другой группе. Обратитесь к владельцу группы.',
  invite_unavailable: 'Ссылка истекла, отозвана или достигла лимита. Попросите владельца выдать новую.',
  onboarding_rate_limited: 'Слишком много попыток. Подождите и попробуйте позже.',
  code_rate_limited: 'Слишком много попыток ввода кода. Подождите и попробуйте позже.',
  password_rate_limited: 'Слишком много попыток ввода пароля. Подождите и попробуйте позже.',
  invalid_code: 'Введите код MAX из 4–8 цифр.',
  invalid_password: 'Введите пароль для входа MAX.',
  network_timeout: 'Не удалось получить ответ от MAX. Проверьте сеть и назначенный IP.',
  network_error: 'Нет связи с панелью. Проверьте интернет и повторите попытку.',
  code_rejected: 'MAX не принял код. Проверьте последние цифры и при необходимости начните попытку заново.',
  password_rejected: 'MAX отклонил облачный пароль. Начните попытку заново и проверьте пароль.',
  max_auth_request_failed: 'MAX не принял запрос кода. Подождите и попробуйте позже.',
  auth_token_missing: 'MAX не подтвердил вход. Проверьте код и запустите подключение заново.',
  ip_assignment_changed: 'Назначенный IP изменился во время подключения. Начните попытку заново.',
  account_assignment_changed_during_verification: 'Назначение IP аккаунта изменилось. Повторите проверку.',
  max_password_required_on_active_session: 'MAX требует пароль для входа при активной сессии. Установите его в официальном приложении MAX и повторите подключение позже.',
  code_entry_timeout: 'Время ожидания кода истекло. Запустите подключение ещё раз.',
  password_entry_timeout: 'Время ожидания пароля истекло. Запустите подключение ещё раз.',
  session_save_failed: 'MAX не удалось сохранить сессию. Попросите владельца проверить подключение.',
  invalid_russian_phone: 'Введите российский номер: +7, 7, 8 или 10 цифр без кода страны.',
  auto_join_failed: 'Не удалось подтвердить автоматическое вступление. Откройте приглашение группы и проверьте вступление.',
  membership_not_confirmed: 'MAX пока не подтвердил членство. Откройте приглашение группы и повторите проверку.',
  membership_check_unavailable: 'Не удалось проверить членство через назначенный IP. Повторите проверку позже.',
  group_resolution_failed: 'Вход сохранён, но ссылка MAX недоступна. Попросите владельца проверить ссылку группы и затем повторить проверку членства.',
  invalid_request: 'Проверьте заполнение полей и повторите действие.',
  group_destination_mismatch: 'Ссылка ведёт в другую группу. Сообщите владельцу группы.',
  account_registration_required: 'Для этого номера MAX требует завершить регистрацию в приложении.',
  cloud_password_rejected: 'Облачный пароль MAX не подошёл. Запустите подключение ещё раз.',
  cancelled_by_guest: 'Подключение отменено.',
  onboarding_attempt_expired: 'Время этой попытки истекло. Запустите подключение ещё раз.',
  process_interrupted: 'Приложение перезапустилось до завершения попытки. Запустите подключение ещё раз.',
  request_timeout: 'MAX не ответил на запрос кода. Проверьте сеть и назначенный IP.',
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
    root.innerHTML = `<h1>${esc(invite.group)}</h1><p>Укажите имя и российский номер MAX. Затем введите код и, если потребуется, облачный пароль.</p><form id="start"><label>ФИО<input name="full_name" required maxlength="120" autocomplete="name"></label><label>Телефон<input name="phone" type="tel" required placeholder="+7…" autocomplete="tel"></label><button>Начать подключение</button><p class="error" id="start-error" role="alert"></p></form><p class="muted">После авторизации попробуем вступить в группу автоматически. Если MAX потребует ваше действие, откройте приглашение и проверьте членство.</p><p><a target="_blank" rel="noreferrer" href="${esc(invite.invite_link)}">Открыть приглашение группы MAX</a></p><div id="flow" aria-live="polite"></div>`;
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

function ensureMembership(reason) {
  if (document.querySelector('#check')) return;
  document.querySelector('#flow').innerHTML = `<div class="panel"><p>${esc(errors[reason] || 'Авторизация прошла. Откройте приглашение группы выше, затем проверьте членство.')}</p><button id="check">Проверить вступление</button><p id="check-result" role="status"></p></div>`;
  document.querySelector('#check').onclick = async event => {
    const button = event.currentTarget;
    button.disabled = true;
    try {
      const result = await api(`/api/public/onboarding/${token}/${session}/check-membership`, {});
      document.querySelector('#check-result').textContent = result.completed ? 'Номер подключён. Можно закрыть страницу.' : 'Пока не видим вступление. Проверьте группу MAX и повторите.';
      if (result.completed) terminalMessage('Номер подключён. Можно закрыть страницу.');
    } catch (error) {
      document.querySelector('#check-result').textContent = friendly(error);
    } finally {
      button.disabled = false;
    }
  };
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
    else if (data.state === 'waiting_membership') ensureMembership(data.error);
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
