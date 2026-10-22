'use strict';
/* TrustVault single-page UI. Presentation only: every permission decision is made by the server,
   hiding a button here is a convenience, never a control. All dynamic text is inserted with
   textContent (never innerHTML), and the CSP forbids inline script. */
(function () {
  var state = { user: null, csrf: null };
  var $view = document.getElementById('view');

  function h(tag, attrs) {
    var el = document.createElement(tag);
    if (attrs) Object.keys(attrs).forEach(function (k) {
      var v = attrs[k];
      if (v === false || v == null) return;
      if (k === 'class') el.className = v;
      else if (k.slice(0, 2) === 'on') el.addEventListener(k.slice(2), v);
      else if (k === 'value') el.value = v;
      else el.setAttribute(k, v === true ? '' : v);
    });
    for (var i = 2; i < arguments.length; i++) add(el, arguments[i]);
    return el;
  }
  function add(el, c) {
    if (c == null || c === false) return;
    if (Array.isArray(c)) return c.forEach(function (x) { add(el, x); });
    el.appendChild(c.nodeType ? c : document.createTextNode(String(c)));
  }
  function clear(el) { while (el.firstChild) el.removeChild(el.firstChild); }
  function show(node) { clear($view); $view.appendChild(node); window.scrollTo(0, 0); }

  function toast(msg, bad) {
    var box = document.getElementById('toast');
    var d = h('div', { class: bad ? 'bad' : '' }, msg);
    box.appendChild(d);
    setTimeout(function () { if (d.parentNode) d.parentNode.removeChild(d); }, 4500);
  }

  var fmt = function (iso) { return iso ? new Date(iso).toLocaleString() : ''; };
  var fmtSize = function (n) { return n < 1024 ? n + ' B' : n < 1048576 ? (n / 1024).toFixed(1) + ' KB' : (n / 1048576).toFixed(1) + ' MB'; };
  var pill = function (t, cls) { return h('span', { class: 'pill ' + (cls || t) }, t); };

  function api(method, path, body, raw) {
    var opts = { method: method, credentials: 'same-origin', headers: {} };
    if (state.csrf && method !== 'GET') opts.headers['X-CSRF-Token'] = state.csrf;
    if (body instanceof FormData) opts.body = body;
    else if (body !== undefined) { opts.headers['Content-Type'] = 'application/json'; opts.body = JSON.stringify(body); }
    return fetch('/api' + path, opts).then(function (res) {
      if (raw && res.ok) return res;
      return res.text().then(function (t) {
        var j = null; try { j = JSON.parse(t); } catch (e) { /* not json */ }
        if (res.status === 401 && state.user) { state.user = null; state.csrf = null; renderShell(); route(); }
        if (!res.ok) { var err = new Error((j && j.message) || 'Request failed (' + res.status + ')'); err.status = res.status; err.body = j; throw err; }
        return j;
      });
    });
  }
  function guarded(fn) { return function (e) { if (e && e.preventDefault) e.preventDefault(); return Promise.resolve(fn(e)).catch(function (err) { toast(err.message, true); }); }; }

  function renderShell() {
    var top = document.getElementById('top');
    var nav = document.getElementById('nav');
    clear(nav);
    if (!state.user) { top.hidden = true; return; }
    top.hidden = false;
    var links = [['#/', 'Documents'], ['#/shared', 'Shared with me'], ['#/trash', 'Trash']];
    if (state.user.role === 'owner') links.splice(1, 0, ['#/upload', 'Upload']);
    if (state.user.role === 'admin') links = [['#/admin', 'Overview'], ['#/admin/audit', 'Audit trail'], ['#/admin/users', 'Users'], ['#/admin/docs', 'Documents']];
    var cur = location.hash || '#/';
    links.forEach(function (l) { nav.appendChild(h('a', { href: l[0], class: cur === l[0] ? 'on' : '' }, l[1])); });
    var who = document.getElementById('who');
    who.textContent = state.user.name + ' ';
    who.appendChild(pill(state.user.role, 'owner'));
  }

  function route() {
    renderShell();
    if (!state.user) return show(loginView());
    var p = (location.hash || '#/').slice(1).split('?')[0];
    var m;
    var role = state.user.role;
    if (role === 'admin') {
      if (p === '/admin/audit') return adminAudit();
      if (p === '/admin/users') return adminUsers();
      if (p === '/admin/docs') return adminDocs();
      return adminOverview();
    }
    if (p === '/upload' && role === 'owner') return show(uploadView());
    if (p === '/trash') return listView('Trash', { trash: '1' });
    if (p === '/shared') return listView('Shared with me', { scope: 'shared' });
    if ((m = p.match(/^\/doc\/([0-9a-f-]{36})$/i))) return docView(m[1]);
    return listView(role === 'owner' ? 'My documents' : 'Documents', {}, true);
  }
  window.addEventListener('hashchange', route);

  function loginView() {
    var err = h('div', { class: 'err' });
    var email = h('input', { type: 'email', required: true, autocomplete: 'username' });
    var pw = h('input', { type: 'password', required: true, autocomplete: 'current-password' });
    var form = h('form', { class: 'card login login-card', onsubmit: function (e) {
      e.preventDefault(); err.textContent = '';
      api('POST', '/auth/login', { email: email.value, password: pw.value }).then(function (r) {
        state.user = r.user; state.csrf = r.csrfToken;
        location.hash = r.user.role === 'admin' ? '#/admin' : '#/'; route();
      }).catch(function (x) { err.textContent = x.message; });
    } }, h('p', { class: 'login-kicker' }, 'SECURE WORKSPACE'),
      h('h1', null, 'Welcome back'),
      h('p', { class: 'muted login-copy' }, 'Sign in to continue to your documents and shared workspace.'),
      h('label', null, 'Email address', email), h('label', null, 'Password', pw), err,
      h('button', { type: 'submit' }, 'Sign in'), h('p', { class: 'login-footnote' }, 'Protected by encrypted storage and an audited access trail.'));
    return h('section', { class: 'login-page' },
      h('div', { class: 'login-story' },
        h('div', { class: 'login-brand' }, h('img', { class: 'brand-logo', src: '/logo.svg', alt: '', 'aria-hidden': 'true' }), h('strong', null, 'TrustVault')),
        h('div', { class: 'login-story-copy' },
          h('p', { class: 'login-kicker' }, 'DOCUMENTS, WITH CONFIDENCE'),
          h('h2', null, 'Your work deserves a safer place.'),
          h('p', null, 'Share sensitive files with the right people, keep control of every permission, and know what happened at every step.')),
        h('div', { class: 'login-promise' }, h('span', { class: 'promise-dot' }), 'Private by design. Accountable by default.')),
      h('div', { class: 'login-form-wrap' }, form));
  }

  document.getElementById('logout').addEventListener('click', guarded(function () {
    return api('POST', '/auth/logout').then(function () { state.user = null; state.csrf = null; location.hash = '#/'; route(); });
  }));

  api('GET', '/auth/me').then(function (r) { state.user = r.user || null; state.csrf = r.csrfToken || null; }).catch(function () {}).then(route);
})();
