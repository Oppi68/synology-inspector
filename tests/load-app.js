/**
 * Loads the browser scripts into a Node vm context so checks can be tested
 * without a browser and without converting the app to ES modules (the app
 * must keep working from file://).
 */
'use strict';

const fs   = require('node:fs');
const path = require('node:path');
const vm   = require('node:vm');

const ROOT = path.join(__dirname, '..');

const SCRIPTS = [
    'js/i18n.js',
    'js/sqlite-reader.js',
    'js/compliance-engine.js',
    'js/compare.js',
    'js/checks/check-remote-access.js',
    'js/checks/check-network.js',
    'js/checks/check-protocols.js',
    'js/checks/check-auth.js',
    'js/checks/check-websecurity.js',
    'js/checks/check-users.js',
    'js/checks/check-maintenance.js',
    'js/checks/check-advisories.js',
    'js/checks/check-bestpractices.js',
];

function loadApp(lang = 'en') {
    const storage = new Map([['syno-inspector-lang', lang]]);
    const window  = {};
    const context = {
        window,
        console,
        TextDecoder,
        localStorage: {
            getItem: k => (storage.has(k) ? storage.get(k) : null),
            setItem: (k, v) => storage.set(k, String(v)),
        },
        document: { documentElement: {}, querySelectorAll: () => [] },
    };
    vm.createContext(context);
    for (const file of SCRIPTS) {
        vm.runInContext(fs.readFileSync(path.join(ROOT, file), 'utf8'), context, { filename: file });
        // i18n.js attaches its API to window; expose it as globals like a browser does
        Object.assign(context, window);
    }
    return context;
}

/**
 * Run the security checks for a config object and parseResult overrides.
 *
 * @param {Object} app          context from loadApp()
 * @param {Object} configObj    key → value
 * @param {Object} [extras]     parseResult fields (users, adminMembers, …)
 * @returns {Object[]} findings
 */
function runChecks(app, configObj, extras = {}) {
    const config = new Map(Object.entries(configObj));
    const parseResult = {
        config,
        tlsProfile: null,
        users: [],
        adminMembers: [],
        schedulerTasks: [],
        autoBackupConfigured: true,
        hasBtrfs: false,
        ...extras,
    };
    return app.runAllChecks(config, parseResult.tlsProfile, parseResult);
}

const VIEW_SCRIPTS = [
    'js/compliance-view.js',
    'js/bestpractices-view.js',
    'js/compare-view.js',
    'js/app.js',
];

/**
 * Additionally load the view renderers (and app.js for escapeHtml) into an
 * app context. Render functions return HTML strings, so no DOM is needed.
 *
 * @param {Object} app  context from loadApp()
 * @returns {Object} the same context
 */
function loadViews(app) {
    app.document.addEventListener = () => {};
    for (const file of VIEW_SCRIPTS) {
        vm.runInContext(fs.readFileSync(path.join(ROOT, file), 'utf8'), app, { filename: file });
    }
    return app;
}

module.exports = { loadApp, loadViews, runChecks, ROOT };
