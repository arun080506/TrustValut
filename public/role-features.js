(function () {
  function make(tag, className, text) {
    var el = document.createElement(tag);
    if (className) el.className = className;
    if (text !== undefined && text !== null) el.textContent = String(text);
    return el;
  }

  function removePanels() {
    document.querySelectorAll('.role-quick-panel').forEach(function (panel) {
      panel.remove();
    });
  }

  function getRoleLabel(role) {
    if (role === 'admin') return 'Administrator';
    if (role === 'owner') return 'Document owner';
    return 'Viewer';
  }

  function renderAction(label, action, isSecondary) {
    var button = document.createElement('button');
    button.type = 'button';
    button.className = isSecondary ? 'role-action-btn secondary' : 'role-action-btn';
    button.textContent = label;
    button.addEventListener('click', function () {
      if (typeof action === 'function') action();
      else if (typeof action === 'string') location.hash = action;
    });
    return button;
  }

  function renderRoleSummary(user, docs, adminSummary) {
    var panel = make('section', 'role-quick-panel');
    var header = make('div', 'role-panel-header');
    header.appendChild(make('h2', '', 'Welcome back, ' + user.name));
    header.appendChild(make('span', 'role-badge', getRoleLabel(user.role)));
    panel.appendChild(header);

    var stats = make('div', 'role-metrics');
    var total = docs.length;
    var owned = docs.filter(function (d) { return d.access === 'owner'; }).length;
    var shared = docs.filter(function (d) { return d.access === 'read' || d.access === 'edit'; }).length;
    var adminTotal = adminSummary && adminSummary.counts ? adminSummary.counts.documents : total;

    stats.appendChild(makeStat(adminSummary ? adminTotal : total, adminSummary ? 'Documents in workspace' : 'Accessible documents', 'workspace'));
    stats.appendChild(makeStat(owned, 'Owned by you', 'ownership'));
    stats.appendChild(makeStat(shared, 'Shared access', 'access'));
    stats.appendChild(makeStat(user.role === 'admin' ? (adminSummary && adminSummary.counts ? adminSummary.counts.failedLogins24h : 0) : docs.filter(function (d) { return d.access === 'read' || d.access === 'edit'; }).length, user.role === 'admin' ? 'Failed sign-ins · 24h' : 'Editable documents', 'security'));
    panel.appendChild(stats);

    var grid = make('div', 'role-grid');

    var actionsCard = make('div', 'role-card');
    actionsCard.appendChild(make('h3', '', 'Quick actions'));
    var actionWrap = make('div', 'role-actions');
    if (user.role === 'owner') {
      actionWrap.appendChild(renderAction('Upload a document', '#/upload'));
      actionWrap.appendChild(renderAction('Open my documents', '#/docs'));
      actionWrap.appendChild(renderAction('Shared with me', '#/shared'));
    } else if (user.role === 'admin') {
      actionWrap.appendChild(renderAction('Security overview', '#/admin'));
      actionWrap.appendChild(renderAction('Audit trail', '#/admin/audit'));
      actionWrap.appendChild(renderAction('User management', '#/admin/users'));
    } else {
      actionWrap.appendChild(renderAction('My documents', '#/docs'));
      actionWrap.appendChild(renderAction('Shared with me', '#/shared'));
      actionWrap.appendChild(renderAction('Trash', '#/trash'));
    }
    actionsCard.appendChild(actionWrap);
    grid.appendChild(actionsCard);

    var activityCard = make('div', 'role-card');
    activityCard.appendChild(make('h3', '', 'Recent documents'));
    var list = make('ul', 'role-doc-list');
    if (!docs.length) {
      list.appendChild(make('li', '', 'No accessible documents yet.'));
    } else {
      docs.slice(0, 5).forEach(function (d) {
        var row = make('li', '');
        var meta = make('div', 'role-doc-meta');
        meta.appendChild(make('span', 'role-doc-name', d.name));
        meta.appendChild(make('span', 'role-doc-sub', d.category + ' • updated ' + formatDate(d.updatedAt)));
        row.appendChild(meta);
        var pill = make('span', 'role-pill ' + d.access, d.access);
        row.appendChild(pill);
        list.appendChild(row);
      });
    }
    activityCard.appendChild(list);
    grid.appendChild(activityCard);

    panel.appendChild(grid);
    return panel;
  }

  function makeStat(value, label, kind) {
    var stat = make('div', 'role-metric');
    stat.appendChild(make('strong', '', value));
    stat.appendChild(make('span', '', label));
    if (kind) stat.dataset.kind = kind;
    return stat;
  }

  function formatDate(value) {
    if (!value) return 'just now';
    var date = new Date(value);
    return date.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
  }

  async function refreshPanel() {
    var view = document.getElementById('view');
    if (!view) return;
    try {
      var who = await fetch('/api/auth/me', { credentials: 'same-origin' }).then(function (res) { return res.json(); }).catch(function () { return { user: null, csrfToken: null }; });
      if (!who.user) {
        removePanels();
        return;
      }
      var docsRes = await fetch('/api/documents?limit=5', { credentials: 'same-origin' });
      var docsData = await docsRes.json().catch(function () { return { documents: [] }; });
      var summary = null;
      if (who.user.role === 'admin') {
        summary = await fetch('/api/admin/summary', { credentials: 'same-origin' }).then(function (res) { return res.ok ? res.json() : null; }).catch(function () { return null; });
      }
      removePanels();
      var panel = renderRoleSummary(who.user, docsData.documents || [], summary);
      view.insertBefore(panel, view.firstChild);
    } catch (_) {
      removePanels();
    }
  }

  window.addEventListener('hashchange', refreshPanel);
  window.addEventListener('load', refreshPanel);
  var observer = new MutationObserver(function () {
    if (document.body && document.getElementById('view')) refreshPanel();
  });
  if (document.body) {
    observer.observe(document.body, { childList: true, subtree: true });
  }
})();
