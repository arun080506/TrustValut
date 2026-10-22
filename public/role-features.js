(function () {
  function removePanels() {
    document.querySelectorAll('.role-quick-panel').forEach(function (panel) {
      panel.remove();
    });
  }

  if (window.__trustVaultRoleFeaturesDisabled) return;
  window.__trustVaultRoleFeaturesDisabled = true;

  removePanels();
  document.addEventListener('DOMContentLoaded', removePanels, { once: true });
})();
