'use strict';

const test   = require('node:test');
const assert = require('node:assert/strict');
const fs     = require('node:fs');
const path   = require('node:path');
const vm     = require('node:vm');
const { ROOT } = require('./load-app.js');

test('translations work when the browser blocks localStorage', () => {
    const window  = {};
    const blocked = () => { throw new Error('SecurityError'); };
    const context = {
        window,
        document: { documentElement: {}, querySelectorAll: () => [] },
    };
    Object.defineProperty(context, 'localStorage', { get: blocked });
    vm.createContext(context);
    vm.runInContext(fs.readFileSync(path.join(ROOT, 'js/i18n.js'), 'utf8'), context);
    assert.equal(typeof window.t, 'function');
    assert.equal(window.t('severityCritical'), 'Critical');
    assert.doesNotThrow(() => window.setLanguage('de'));
    assert.equal(window.t('severityCritical'), 'Kritisch');
});
