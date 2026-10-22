'use strict';
/* Vaultora single-page UI. Presentation only: every permission decision is made by the server,
   hiding a button here is a convenience, never a control. All dynamic text is inserted with
   textContent (never innerHTML), and the CSP forbids inline script. */
(function () {
  var state = { user: null, csrf: null };
  var $view = document.getElementById('view');

  // ---------- tiny DOM helper ----------
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

  // ---------- API ----------
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

  // ---------- shell / routing ----------
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

  // ---------- login ----------
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
        h('div', { class: 'login-brand' }, h('img', { class: 'brand-logo', src: '/logo.svg', alt: '', 'aria-hidden': 'true' }), h('strong', null, 'Vaultora')),
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

  // ---------- documents list ----------
  function listView(title, base, withFilters) {
    var box = h('div');
    var q = h('input', { placeholder: 'Name contains…' }), owner = h('input', { placeholder: 'Owner name/email' });
    var cat = h('select', null, h('option', { value: '' }, 'Any category'));
    var from = h('input', { type: 'date' }), to = h('input', { type: 'date' });
    var scope = h('select', null, h('option', { value: '' }, 'Mine + shared'), h('option', { value: 'mine' }, 'Mine only'), h('option', { value: 'shared' }, 'Shared with me'));
    var out = h('div', { class: 'card tbl' });
    function load() {
      var p = new URLSearchParams(base);
      if (withFilters) [['q', q], ['owner', owner], ['category', cat], ['from', from], ['to', to], ['scope', scope]].forEach(function (x) { if (x[1].value) p.set(x[0], x[1].value); });
      return api('GET', '/documents?' + p.toString()).then(function (r) { renderRows(r.documents); });
    }
    function renderRows(docs) {
      clear(out);
      if (!docs.length) return out.appendChild(h('p', { class: 'muted' }, 'Nothing here.'));
      var rows = docs.map(function (d) {
        return h('tr', { class: 'click', onclick: function () { location.hash = '#/doc/' + d.id; } },
          h('td', null, d.name), h('td', null, d.category), h('td', null, d.owner.name), h('td', null, pill(d.access)),
          h('td', null, 'v' + d.version), h('td', null, fmt(d.updatedAt)));
      });
      out.appendChild(h('table', null, h('thead', null, h('tr', null, ['Name', 'Category', 'Owner', 'Access', 'Ver', 'Updated'].map(function (c) { return h('th', null, c); }))), h('tbody', null, rows)));
    }
    if (withFilters) {
      api('GET', '/documents/categories').then(function (r) { r.categories.forEach(function (c) { cat.appendChild(h('option', { value: c }, c)); }); });
      box.appendChild(h('div', { class: 'card' }, h('div', { class: 'row' },
        h('label', null, 'Search', q), h('label', null, 'Owner', owner), h('label', null, 'Category', cat),
        h('label', null, 'From', from), h('label', null, 'To', to), h('label', null, 'Show', scope),
        h('button', { onclick: guarded(load) }, 'Search'))));
    }
    box.insertBefore(h('div', { class: 'page-intro' },
      h('p', { class: 'eyebrow' }, 'DOCUMENT WORKSPACE'),
      h('h1', null, title),
      h('p', null, 'Find and manage documents you own or have been given access to. Each document shows its owner, permission level, version, and latest update.')), box.firstChild);
    box.appendChild(out);
    show(box);
    guarded(load)();
  }

  // ---------- upload ----------
  function uploadView() {
    var file = h('input', { type: 'file', required: true });
    var name = h('input', { maxlength: 200, placeholder: 'Defaults to the file name' });
    var cat = h('input', { maxlength: 60, value: 'general' });
    var desc = h('textarea', { rows: 2, maxlength: 1000 });
    var form = h('form', { class: 'card', onsubmit: guarded(function () {
      var fd = new FormData();
      fd.append('name', name.value); fd.append('category', cat.value); fd.append('description', desc.value);
      fd.append('file', file.files[0]);
      return api('POST', '/documents', fd).then(function (r) { toast('Uploaded'); location.hash = '#/doc/' + r.id; });
    }) }, h('h1', null, 'Upload a document'),
      h('p', { class: 'muted' }, 'Add a document to your private workspace. Files are encrypted before storage and can be shared later with specific people using read or edit access.'),
      h('p', { class: 'muted' }, 'Supported formats: PDF, PNG, JPG, TXT, CSV, Markdown, DOCX, XLSX, and PPTX. Maximum size: 4 MB. The file content must match its file type.'),
      h('div', { class: 'grid2' }, h('label', null, 'File', file), h('label', null, 'Name', name), h('label', null, 'Category', cat), h('label', null, 'Description', desc)),
      h('p', null, h('button', { type: 'submit' }, 'Upload')));
    return form;
  }

  // ---------- document detail ----------
  function download(id, version, filename) {
    return api('GET', '/documents/' + id + '/download?version=' + version, undefined, true).then(function (res) { return res.blob(); }).then(function (b) {
      var a = h('a', { href: URL.createObjectURL(b), download: filename });
      document.body.appendChild(a); a.click(); a.remove();
    });
  }

  function docView(id) {
    var box = h('div');
    show(box);
    api('GET', '/documents/' + id).then(function (r) {
      var d = r.document, level = d.access;
      var canEdit = level === 'edit' || level === 'owner', isOwner = level === 'owner';
      clear(box);
      box.appendChild(h('p', null, h('a', { href: '#/' }, '← Back')));
      box.appendChild(h('h1', null, d.name, ' ', pill(level), d.deletedAt ? [' ', pill('in trash', 'denied')] : null));
      box.appendChild(h('p', { class: 'muted' }, 'Owner: ' + r.owner.name + ' · Category: ' + d.category + ' · Updated ' + fmt(d.updatedAt)));
      if (d.description) box.appendChild(h('p', null, d.description));

      if (isOwner && d.deletedAt) {
        box.appendChild(h('div', { class: 'card' }, h('button', { onclick: guarded(function () { return api('POST', '/documents/' + id + '/restore', {}).then(function () { toast('Restored'); route(); }); }) }, 'Restore from trash')));
        return;
      }

      // versions
      var vrows = r.versions.map(function (v) {
        return h('tr', null, h('td', null, 'v' + v.version), h('td', null, v.filename), h('td', null, fmtSize(v.size)), h('td', null, v.uploadedBy), h('td', null, fmt(v.createdAt)),
          h('td', { class: 'mono' }, v.sha256.slice(0, 12) + '…'),
          h('td', null, h('button', { class: 'ghost', onclick: guarded(function () { return download(id, v.version, v.filename); }) }, 'Download')));
      });
      box.appendChild(h('div', { class: 'card tbl' }, h('h2', null, 'Versions'),
        h('table', null, h('thead', null, h('tr', null, ['Ver', 'File', 'Size', 'By', 'When', 'SHA-256', ''].map(function (c) { return h('th', null, c); }))), h('tbody', null, vrows))));

      if (canEdit) {
        var nm = h('input', { value: d.name }), ct = h('input', { value: d.category }), ds = h('input', { value: d.description });
        var nv = h('input', { type: 'file' });
        box.appendChild(h('div', { class: 'card' }, h('h2', null, 'Edit'),
          h('div', { class: 'row' }, h('label', null, 'Name', nm), h('label', null, 'Category', ct), h('label', null, 'Description', ds),
            h('button', { onclick: guarded(function () { return api('PATCH', '/documents/' + id, { name: nm.value, category: ct.value, description: ds.value }).then(function () { toast('Saved'); route(); }); }) }, 'Save')),
          h('div', { class: 'row top' }, h('label', null, 'Upload a new version', nv),
            h('button', { class: 'ghost', onclick: guarded(function () {
              if (!nv.files[0]) return toast('Choose a file first', true);
              var fd = new FormData(); fd.append('file', nv.files[0]);
              return api('POST', '/documents/' + id + '/versions', fd).then(function (x) { toast('Version ' + x.version + ' uploaded'); route(); });
            }) }, 'Upload version'))));
      }

      if (isOwner) {
        var gbox = h('div', { class: 'card' }), abox = h('div', { class: 'card' });
        box.appendChild(gbox); box.appendChild(abox);
        loadGrants(id, gbox); loadActivity(id, abox);
        box.appendChild(h('div', { class: 'card' }, h('button', { class: 'danger', onclick: guarded(function () {
          if (!confirm('Move this document to the trash? Everyone you shared it with loses access immediately.')) return;
          return api('DELETE', '/documents/' + id).then(function () { toast('Moved to trash'); location.hash = '#/'; });
        }) }, 'Delete document')));
      }
    }).catch(function (e) { clear(box); box.appendChild(h('div', { class: 'card' }, h('p', { class: 'err' }, e.status === 404 ? 'Document not found.' : e.message), h('a', { href: '#/' }, '← Back'))); });
  }

  function loadGrants(id, box) {
    api('GET', '/documents/' + id + '/grants').then(function (r) {
      clear(box);
      box.appendChild(h('h2', null, 'Who has access'));
      if (!r.grants.length) box.appendChild(h('p', { class: 'muted' }, 'Only you.'));
      else box.appendChild(h('div', { class: 'tbl' }, h('table', null, h('tbody', null, r.grants.map(function (g) {
        return h('tr', null, h('td', null, g.name, h('div', { class: 'muted' }, g.email)), h('td', null, pill(g.permission)),
          h('td', null, g.expiresAt ? 'expires ' + fmt(g.expiresAt) : 'no expiry'),
          h('td', null, h('button', { class: 'danger', onclick: guarded(function () {
            return api('DELETE', '/documents/' + id + '/grants/' + g.userId).then(function () { toast('Access removed'); loadGrants(id, box); loadActivity(id, box.nextSibling); });
          }) }, 'Remove')));
      })))));
      // grant form
      var search = h('input', { placeholder: 'Find a person (3+ letters)…' }), results = h('div'), chosen = null, sugId = null;
      var perm = h('select', null, h('option', { value: 'read' }, 'Read'), h('option', { value: 'edit' }, 'Edit'));
      var days = h('input', { type: 'number', min: 1, max: 365, placeholder: 'days (optional)', class: 'narrow' });
      var sel = h('div', { class: 'muted' }, 'Nobody selected');
      function choose(u, suggested, sid) { chosen = u; sugId = sid || null; sel.textContent = 'Selected: ' + u.name + ' (' + u.email + ', ' + u.role + ')'; if (suggested) perm.value = suggested; }
      search.addEventListener('input', function () {
        if (search.value.length < 3) return clear(results);
        api('GET', '/users/directory?q=' + encodeURIComponent(search.value)).then(function (x) {
          clear(results);
          x.users.forEach(function (u) { results.appendChild(h('div', null, h('button', { type: 'button', class: 'ghost pick', onclick: function () { choose(u); } }, u.name + ' — ' + u.email + ' (' + u.role + ')'))); });
        }).catch(function () {});
      });
      var sugBox = h('div');
      box.appendChild(h('h2', null, 'Share'));
      box.appendChild(h('div', { class: 'row' }, h('label', null, 'Person', search), h('label', null, 'Permission', perm), h('label', null, 'Expires in', days),
        h('button', { onclick: guarded(function () {
          if (!chosen) return toast('Pick a person first', true);
          var body = { userId: chosen.id, permission: perm.value };
          if (days.value) body.expiresAt = new Date(Date.now() + Number(days.value) * 86400000).toISOString();
          if (sugId) body.suggestionId = sugId;
          return api('PUT', '/documents/' + id + '/grants', body).then(function () { toast('Access granted'); route(); });
        }) }, 'Grant access')));
      box.appendChild(results); box.appendChild(sel);
      box.appendChild(h('p', null, h('button', { class: 'ghost', onclick: guarded(function () {
        return api('POST', '/documents/' + id + '/suggest-access', {}).then(function (s) {
          clear(sugBox);
          sugBox.appendChild(h('p', { class: 'muted' }, s.note));
          if (!s.suggestions.length) sugBox.appendChild(h('p', null, 'No suggestions for this document yet.'));
          s.suggestions.forEach(function (x) {
            sugBox.appendChild(h('div', { class: 'sug' }, h('strong', null, x.name), ' ', pill('suggest: ' + x.suggestedPermission, 'read'),
              h('ul', null, x.reasons.map(function (r) { return h('li', null, r); })),
              h('button', { class: 'ghost', onclick: function () { choose(x, x.suggestedPermission, s.suggestionId); toast('Selected. Review it, then press "Grant access".'); } }, 'Use this suggestion')));
          });
        });
      }) }, 'Suggest who should have access')));
      box.appendChild(sugBox);
    }).catch(function (e) { toast(e.message, true); });
  }

  function activityTable(items) {
    return h('div', { class: 'tbl activity-log' }, h('table', { class: 'activity-table' }, h('thead', null, h('tr', null, ['#', 'When', 'Who', 'What', 'Result', 'Detail'].map(function (c) { return h('th', null, c); }))),
      h('tbody', null, items.map(function (a) {
        var detail = a.detail || {};
        var detailCell;
        if (a.action === 'admin.user_credentials_update' && detail.from && detail.to) {
          detailCell = h('td', { class: 'activity-detail' },
            h('div', null, h('strong', null, 'From '), detail.from.name, ' -> ', h('strong', null, 'To '), detail.to.name),
            h('div', { class: 'muted mono activity-meta' }, detail.from.email + ' -> ' + detail.to.email),
            h('div', { class: 'muted activity-meta' }, 'Sessions revoked: ' + detail.sessionsRevoked));
        } else {
          detailCell = h('td', { class: 'mono activity-detail' }, JSON.stringify(detail));
        }
        return h('tr', null, h('td', { class: 'activity-seq' }, a.seq), h('td', null, fmt(a.ts)), h('td', null, a.actor || 'system'), h('td', null, a.action), h('td', null, pill(a.outcome, a.outcome === 'denied' ? 'denied' : 'read')),
          detailCell);
      }))));
  }
  function loadActivity(id, box) {
    if (!box) return;
    api('GET', '/documents/' + id + '/activity').then(function (r) {
      clear(box); box.appendChild(h('h2', null, 'Activity on this document (incl. refused attempts)'));
      box.appendChild(r.activity.length ? activityTable(r.activity) : h('p', { class: 'muted' }, 'No activity yet.'));
    }).catch(function () {});
  }

  // ---------- admin ----------
  function adminOverview() {
    var box = h('div', null,
      h('div', { class: 'page-intro' },
        h('p', { class: 'eyebrow' }, 'TRUSTVAULT ADMINISTRATION'),
        h('h1', null, 'Security overview'),
        h('p', null, 'A clear view of document access, account activity, and audit integrity. Use the tools below to investigate events and manage the workspace.')));
    show(box);
    guarded(function () {
      return Promise.all([api('GET', '/admin/summary'), api('GET', '/admin/audit/verify')]).then(function (rs) {
        var s = rs[0], v = rs[1], c = s.counts;
        var stat = function (n, l, d) {
          return h('article', { class: 'card stat-card' },
            h('div', { class: 'stat' }, n),
            h('div', { class: 'stat-label' }, l),
            h('p', { class: 'stat-description' }, d));
        };
        box.appendChild(h('div', { class: 'verify overview-status ' + (v.ok ? 'good' : 'bad') },
          h('strong', null, v.ok ? 'Audit integrity verified' : 'Audit integrity check failed'),
          h('span', null, v.ok ? v.count + ' recorded events checked. The audit chain is intact.' : 'Problem at entry #' + v.brokenAt + ': ' + v.reason)));
        box.appendChild(h('section', { 'aria-label': 'Workspace metrics', class: 'dashboard-stats' },
          stat(c.documents, 'Documents', 'Files stored across all accounts.'),
          stat(c.activeGrants, 'Active grants', 'Current document-sharing permissions.'),
          stat(c.refusals24h, 'Refused requests · 24h', 'Document access attempts blocked in the last 24 hours.'),
          stat(c.failedLogins24h, 'Failed sign-ins · 24h', 'Unsuccessful sign-in attempts in the last 24 hours.'),
          stat(c.auditEvents, 'Audit events', 'Actions recorded in the tamper-evident audit trail.')));
        box.appendChild(h('section', { class: 'dashboard-section' },
          h('div', { class: 'section-heading' }, h('h2', null, 'Workspace tools'), h('p', null, 'Choose a tool to investigate activity or manage accounts and sharing.')),
          h('div', { class: 'feature-grid' },
            h('a', { class: 'feature-card', href: '#/admin/audit' },
              h('h3', null, 'Audit trail'),
              h('p', null, 'Review who did what and when. Filter events by person, document, action, date, or outcome—including refused requests—and verify the chain integrity.'),
              h('span', { class: 'feature-link' }, 'Review activity →')),
            h('a', { class: 'feature-card', href: '#/admin/users' },
              h('h3', null, 'User management'),
              h('p', null, 'Create accounts, assign roles, deactivate users, reset passwords, and revoke active sessions when access needs to change.'),
              h('span', { class: 'feature-link' }, 'Manage users →')),
            h('a', { class: 'feature-card', href: '#/admin/docs' },
              h('h3', null, 'Document access'),
              h('p', null, 'Review document metadata, owners, and active grants. Administrators can manage access, but cannot open file contents unless separately granted.'),
              h('span', { class: 'feature-link' }, 'Review documents →')))));
        box.appendChild(h('section', { class: 'dashboard-section' },
          h('div', { class: 'section-heading' }, h('h2', null, 'Worth noticing'), h('p', null, 'Security signals surfaced from recent workspace activity.')),
          s.alerts.length
            ? s.alerts.map(function (a) { return h('div', { class: 'alert ' + a.severity }, pill(a.severity), ' ', a.message); })
            : h('p', { class: 'empty-state' }, 'No unusual activity has been flagged. Check the audit trail for a complete event history.')));
        box.appendChild(h('section', { class: 'dashboard-section' },
          h('div', { class: 'section-heading' }, h('h2', null, 'Recent sensitive changes'), h('p', null, 'Account, permission, and document changes worth reviewing.')),
          h('div', { class: 'card overview-content' }, s.recentSensitive.length
            ? activityTable(s.recentSensitive.map(function (x) { return { seq: x.seq, ts: x.ts, actor: x.actor_email, action: x.action, outcome: 'allowed', detail: x.detail }; }))
            : h('p', { class: 'empty-state' }, 'No sensitive changes recorded recently.'))));
      });
    })();
  }

  function adminAudit() {
    var box = h('div', null, h('div', { class: 'page-intro' },
      h('p', { class: 'eyebrow' }, 'SECURITY & ACCOUNTABILITY'),
      h('h1', null, 'Audit trail'),
      h('p', null, 'Search the event history, including successful actions and refused requests. Verify the tamper-evident chain to confirm that recorded entries remain intact.')));
    var actor = h('input', { placeholder: 'actor email' }), action = h('input', { placeholder: 'action prefix e.g. doc.' }), doc = h('input', { placeholder: 'document id' });
    var outcome = h('select', null, h('option', { value: '' }, 'Any result'), h('option', { value: 'denied' }, 'Refused only'), h('option', { value: 'allowed' }, 'Allowed only'));
    var from = h('input', { type: 'date' }), to = h('input', { type: 'date' });
    var out = h('div', { class: 'card' }), vbox = h('div');
    function load() {
      var p = new URLSearchParams();
      [['actor', actor], ['action', action], ['doc', doc], ['outcome', outcome], ['from', from], ['to', to]].forEach(function (x) { if (x[1].value) p.set(x[0], x[1].value); });
      return api('GET', '/admin/audit?' + p.toString()).then(function (r) {
        clear(out);
        out.appendChild(h('div', { class: 'tbl' }, h('table', { class: 'admin-audit-table' }, h('thead', null, h('tr', null, ['#', 'When', 'Who', 'Action', 'Result', 'Doc', 'IP', 'Detail'].map(function (c) { return h('th', null, c); }))),
          h('tbody', null, r.entries.map(function (a) {
            return h('tr', null, h('td', null, a.seq), h('td', null, fmt(a.ts)), h('td', null, a.actor_email || 'system'), h('td', null, a.action), h('td', null, pill(a.outcome, a.outcome === 'denied' ? 'denied' : 'read')),
              h('td', { class: 'mono' }, a.doc_id ? a.doc_id.slice(0, 8) : ''), h('td', null, a.ip || ''), h('td', { class: 'mono admin-audit-detail' }, JSON.stringify(a.detail).slice(0, 140)));
          })))));
      });
    }
    box.appendChild(h('div', { class: 'card' }, h('div', { class: 'row' }, h('label', null, 'Actor', actor), h('label', null, 'Action', action), h('label', null, 'Document', doc), h('label', null, 'Result', outcome), h('label', null, 'From', from), h('label', null, 'To', to),
      h('button', { onclick: guarded(load) }, 'Filter'),
      h('button', { class: 'ghost', onclick: guarded(function () { return api('GET', '/admin/audit/verify').then(function (v) { clear(vbox); vbox.appendChild(h('div', { class: 'verify ' + (v.ok ? 'good' : 'bad') }, v.ok ? 'Chain intact: ' + v.count + ' entries.' : 'BROKEN at #' + v.brokenAt + ': ' + v.reason)); }); }) }, 'Verify integrity'))));
    box.appendChild(vbox); box.appendChild(out); show(box); guarded(load)();
  }

  function adminUsers() {
    var box = h('div', null, h('div', { class: 'page-intro' },
      h('p', { class: 'eyebrow' }, 'ACCOUNT ADMINISTRATION'),
      h('h1', null, 'Users'),
      h('p', null, 'Create accounts, assign roles, and manage sign-in access. Deactivation ends a user’s active sessions; password resets issue a temporary password shown once.')));
    var out = h('div', { class: 'card tbl' }), note = h('div');
    var email = h('input', { type: 'email' }), name = h('input'), role = h('select', null, ['viewer', 'owner', 'admin'].map(function (r) { return h('option', { value: r }, r); }));
    function load() {
      return api('GET', '/admin/users').then(function (r) {
        clear(out);
        out.appendChild(h('table', null, h('thead', null, h('tr', null, ['Name', 'Email', 'Role', 'Status', 'Sessions', ''].map(function (c) { return h('th', null, c); }))), h('tbody', null, r.users.map(function (u) {
          var self = u.id === state.user.id;
          var btn = function (label, fn, cls) { return h('button', { class: cls || 'ghost', onclick: guarded(fn) }, label); };
          var post = function (p, b) { return api('POST', '/admin/users/' + u.id + p, b || {}).then(function () { toast('Done'); load(); }); };
          return h('tr', null, h('td', null, u.name), h('td', null, u.email), h('td', null, pill(u.role, 'owner')), h('td', null, u.active ? 'active' : pill('deactivated', 'denied')), h('td', null, u.live_sessions),
            h('td', null, self ? h('span', { class: 'muted' }, 'you') : [
              u.active ? btn('Deactivate', function () { if (confirm('Deactivate ' + u.email + '? Their sessions end immediately.')) return post('/deactivate'); }, 'danger') : btn('Activate', function () { return post('/activate'); }),
              ' ', btn('Sign out everywhere', function () { return post('/revoke-sessions'); }),
              ' ', btn('Reset password', function () { return api('POST', '/admin/users/' + u.id + '/reset-password', {}).then(function (r) { clear(note); note.appendChild(h('div', { class: 'card' }, 'Temporary password for ' + u.email + ' (shown once): ', h('span', { class: 'mono' }, r.temporaryPassword))); load(); }); }),
              ' ', btn('Change role', function () { var r = prompt('New role for ' + u.email + ' (admin, owner, viewer):', u.role); if (r) return post('/role', { role: r }); })]));
        }))));
      });
    }
    box.appendChild(h('div', { class: 'card' }, h('h2', null, 'Create user'), h('div', { class: 'row' }, h('label', null, 'Email', email), h('label', null, 'Name', name), h('label', null, 'Role', role),
      h('button', { onclick: guarded(function () {
        return api('POST', '/admin/users', { email: email.value, name: name.value, role: role.value }).then(function (r) { clear(note); note.appendChild(h('div', { class: 'card' }, 'Temporary password for ' + r.user.email + ' (shown once): ', h('span', { class: 'mono' }, r.temporaryPassword))); email.value = ''; name.value = ''; load(); });
      }) }, 'Create'))));
    box.appendChild(note); box.appendChild(out); show(box); guarded(load)();
  }

  function adminDocs() {
    var box = h('div', null, h('div', { class: 'page-intro' },
      h('p', { class: 'eyebrow' }, 'WORKSPACE OVERSIGHT'),
      h('h1', null, 'Documents'),
      h('p', null, 'Review document owners, active grants, and status across the workspace. This view shows metadata only: administrators cannot read file contents unless they have been granted access.')));
    var out = h('div', { class: 'card tbl' }), detail = h('div');
    function load() {
      return api('GET', '/admin/documents').then(function (r) {
        clear(out);
        out.appendChild(h('table', null, h('thead', null, h('tr', null, ['Name', 'Owner', 'Grants', 'Status', 'Updated', ''].map(function (c) { return h('th', null, c); }))), h('tbody', null, r.documents.map(function (d) {
          return h('tr', null, h('td', null, d.name), h('td', null, d.owner_email, d.owner_active ? null : [' ', pill('deactivated', 'denied')]), h('td', null, d.active_grants), h('td', null, d.deleted_at ? 'in trash' : 'live'), h('td', null, fmt(d.updated_at)),
            h('td', null, h('button', { class: 'ghost', onclick: guarded(function () { return showGrants(d); }) }, 'Grants')));
        }))));
      });
    }
    function showGrants(d) {
      return api('GET', '/admin/documents/' + d.id + '/grants').then(function (r) {
        clear(detail);
        var c = h('div', { class: 'card tbl' }, h('h2', null, 'Grant history: ' + d.name),
          h('table', null, h('tbody', null, r.grants.map(function (g) {
            var live = !g.revoked_at && (!g.expires_at || new Date(g.expires_at) > new Date());
            return h('tr', null, h('td', null, g.email), h('td', null, pill(g.permission)), h('td', null, 'since ' + fmt(g.created_at)), h('td', null, g.revoked_at ? 'revoked ' + fmt(g.revoked_at) : live ? 'active' : 'expired'),
              h('td', null, live ? h('button', { class: 'danger', onclick: guarded(function () {
                var reason = prompt('Reason for emergency revoke (recorded in the audit trail):', ''); if (reason === null) return;
                return api('DELETE', '/admin/documents/' + d.id + '/grants/' + g.user_id, { reason: reason }).then(function () { toast('Revoked'); return showGrants(d); });
              }) }, 'Emergency revoke') : null));
          }))));
        detail.appendChild(c);
      });
    }
    box.appendChild(out); box.appendChild(detail); show(box); guarded(load)();
  }

  // ---------- boot ----------
  api('GET', '/auth/me').then(function (r) { state.user = r.user || null; state.csrf = r.csrfToken || null; }).catch(function () {}).then(route);
})();
