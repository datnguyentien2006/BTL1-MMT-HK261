"use strict";
// Emulate HTTP on a LAN IP: getRandomValues exists, randomUUID does not.
const assert = require('node:assert/strict');
const {webcrypto} = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');

const requests = [];
const elements = new Map();
const storage = new Map();
let copied = false;
function element(id) {
    if (!elements.has(id)) elements.set(id, {
        value: id === 'login-username' ? 'alice' : '', disabled: false,
        classList: {add() {}, remove() {}}, replaceChildren() {}, append() {},
        focus() {}, select() {}, setSelectionRange() {},
    });
    return elements.get(id);
}
const context = vm.createContext({
    crypto: {getRandomValues: webcrypto.getRandomValues.bind(webcrypto)},
    sessionStorage: {
        getItem: key => storage.get(key), setItem: (key, value) => storage.set(key, value),
        removeItem: key => storage.delete(key),
    },
    document: {getElementById: element, createElement: () => ({append() {}}),
        execCommand: command => { copied = command === 'copy'; return copied; }},
    navigator: {}, // Clipboard API also unavailable on HTTP LAN.
    window: {addEventListener() {}},
    console, setTimeout() {},
    fetch: async (url, options) => {
        requests.push({url, options});
        return {ok: true, json: async () => url === '/api/network'
            ? {local_only: false, addresses: [{ip: '192.168.1.31', interface: 'Wi-Fi',
                url: 'http://192.168.1.31:5000', qr_url: '/api/invite-qr.svg?ip=192.168.1.31'}]}
            : url === '/api/login'
            ? {success: true, session_id: 'server-issued-token'}
            : {logged_in: true, username: 'alice', peers: [], messages: [], transfers: []}};
    },
});

(async () => {
    vm.runInContext(fs.readFileSync(path.join(__dirname, '../btl_btlmmt/web_ui/app.js'), 'utf8'), context);
    await new Promise(resolve => setImmediate(resolve));
    assert.equal(requests.filter(r => r.url === '/api/status').length, 0);
    assert.equal(element('invite-url').value, 'http://192.168.1.31:5000');
    assert.equal(element('invite-qr').src, '/api/invite-qr.svg?ip=192.168.1.31');
    await vm.runInContext('copyInviteAddress()', context);
    assert.equal(copied, true);
    await vm.runInContext('login()', context);
    const login = requests.find(request => request.url === '/api/login');
    assert.deepEqual(JSON.parse(login.options.body), {username: 'alice'});
    const pageId = login.options.headers['X-Page-ID'];
    assert.match(pageId, /^[0-9a-f]{32}$/);
    assert.equal(login.options.headers['X-Page-ID'], pageId);
    const status = requests.find(request => request.url === '/api/status');
    assert.equal(status.options.headers['X-Page-ID'], pageId);
    assert.equal(status.options.headers['X-Session-ID'], 'server-issued-token');
    assert.equal(element('username-display').textContent, 'alice');
    assert.equal(element('login-button').disabled, false);
    assert.equal(element('login-error').textContent, undefined);
    console.log('PASS: LAN invitation, copy fallback and login work without secure-context APIs or Internet assets');
})().catch(error => { console.error(error); process.exitCode = 1; });
