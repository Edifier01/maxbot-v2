const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

test('successful onboarding start hides the form after the async response', async () => {
  const button = { disabled: false };
  const form = { hidden: false, onsubmit: null, querySelector: () => button };
  const root = { innerHTML: '' };
  const flow = { innerHTML: '' };
  const error = { textContent: '' };
  const requests = [];
  const elements = { '#guest': root, '#start': form, '#flow': flow, '#start-error': error };
  const context = {
    location: { pathname: '/join/test-token' },
    document: { querySelector: selector => elements[selector] ?? null },
    FormData: class { *[Symbol.iterator]() { yield ['full_name', 'Иван']; yield ['phone', '+79990000000']; } },
    fetch: async (url) => {
      requests.push(url);
      const data = url.startsWith('/join-info/')
        ? { group: 'Клуб', invite_link: 'https://max.ru/join/test' }
        : url.endsWith('/start')
          ? { session_id: 'session-test', state: 'starting' }
          : { state: 'starting' };
      return { ok: true, json: async () => data };
    },
    setTimeout: () => 1,
    clearTimeout: () => {},
  };

  const source = fs.readFileSync(path.join(__dirname, '..', 'static', 'join.js'), 'utf8');
  vm.runInNewContext(source, context, { filename: 'join.js' });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(typeof form.onsubmit, 'function');

  const event = { currentTarget: form, preventDefault() {} };
  const submission = form.onsubmit(event);
  event.currentTarget = null;
  await submission;

  assert.equal(form.hidden, true);
  assert.equal(error.textContent, '');
  assert.equal(requests[1], '/api/public/onboarding/test-token/start');
});

test('onboarding start explains that the account is being removed', async () => {
  const button = { disabled: false };
  const form = { hidden: false, onsubmit: null, querySelector: () => button };
  const root = { innerHTML: '' };
  const flow = { innerHTML: '' };
  const error = { textContent: '' };
  const elements = { '#guest': root, '#start': form, '#flow': flow, '#start-error': error };
  const context = {
    location: { pathname: '/join/test-token' },
    document: { querySelector: selector => elements[selector] ?? null },
    FormData: class { *[Symbol.iterator]() { yield ['full_name', 'Ivan']; yield ['phone', '89380021575']; } },
    fetch: async url => url.startsWith('/join-info/')
      ? { ok: true, json: async () => ({ group: 'Club', invite_link: 'https://max.ru/join/test' }) }
      : { ok: false, json: async () => ({ detail: 'account_removal_in_progress' }) },
    setTimeout: () => 1,
    clearTimeout: () => {},
  };

  const source = fs.readFileSync(path.join(__dirname, '..', 'static', 'join.js'), 'utf8');
  vm.runInNewContext(source, context, { filename: 'join.js' });
  await new Promise(resolve => setImmediate(resolve));

  await form.onsubmit({ currentTarget: form, preventDefault() {} });

  assert.equal(form.hidden, false);
  assert.equal(error.textContent, '\u041d\u043e\u043c\u0435\u0440 \u0441\u0435\u0439\u0447\u0430\u0441 \u0443\u0434\u0430\u043b\u044f\u0435\u0442\u0441\u044f \u0438\u0437 \u043f\u0430\u043d\u0435\u043b\u0438. \u041f\u043e\u0434\u043e\u0436\u0434\u0438\u0442\u0435 \u0438 \u0437\u0430\u043f\u0443\u0441\u0442\u0438\u0442\u0435 \u043f\u043e\u0434\u043a\u043b\u044e\u0447\u0435\u043d\u0438\u0435 \u0435\u0449\u0451 \u0440\u0430\u0437.');
});
