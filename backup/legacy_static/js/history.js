const historyModule = {
  currentPage: 1,

  async loadHistory(page = 1) {
    this.currentPage = page;
    const tbody = document.getElementById('history-tbody');
    tbody.innerHTML = '<tr><td colspan="6"><div class="loading-spinner"><div class="spinner"></div>Loading...</div></td></tr>';

    try {
      const data = await api.scans.list(page);
      this.renderHistory(data.scans, data.total);
    } catch (error) {
      tbody.innerHTML = `<tr><td colspan="6" class="alert alert-error">${error.message}</td></tr>`;
    }
  },

  renderHistory(scans, total) {
    const tbody = document.getElementById('history-tbody');

    if (!scans || scans.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" style="text-align: center; color: var(--text-muted);">No scans yet</td></tr>';
      return;
    }

    const rows = scans.map(scan => {
      const statusClass = scan.status === 'completed' ? 'completed' : scan.status === 'running' ? 'running' : scan.status === 'failed' ? 'failed' : 'pending';
      return `
        <tr data-scan-id="${scan.id}">
          <td><strong>${scan.target}</strong></td>
          <td><span class="badge badge-info">${scan.scan_type}</span></td>
          <td><span class="scan-status-dot ${statusClass}"></span> ${scan.status}</td>
          <td>-</td>
          <td>${new Date(scan.created_at).toLocaleDateString()}</td>
          <td>
            <button class="btn-secondary" onclick="historyModule.viewScan('${scan.id}')" style="padding: 4px 8px; font-size: 0.8rem;">
              <i class="fa-solid fa-eye"></i>
            </button>
            <button class="btn-danger" onclick="historyModule.deleteScan('${scan.id}')" style="padding: 4px 8px; font-size: 0.8rem;">
              <i class="fa-solid fa-trash"></i>
            </button>
          </td>
        </tr>
      `;
    }).join('');

    tbody.innerHTML = rows;
  },

  async viewScan(scanId) {
    try {
      const data = await api.scans.get(scanId);
      window.scannerModule?.displayResults(data);
      app.switchTab('scanner');
    } catch (error) {
      console.error('Failed to load scan:', error);
    }
  },

  async deleteScan(scanId) {
    if (!confirm('Are you sure you want to delete this scan?')) return;

    try {
      await api.scans.delete(scanId);
      this.loadHistory(this.currentPage);
      app.showToast('Scan deleted');
    } catch (error) {
      app.showToast('Failed to delete: ' + error.message, 3000);
    }
  },

  refresh() {
    this.loadHistory(this.currentPage);
  },
};

window.historyModule = historyModule;
