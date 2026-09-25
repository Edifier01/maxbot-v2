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
