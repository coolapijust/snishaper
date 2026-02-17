import './style.css';

import {StartProxy, StopProxy, GetSiteGroups, AddSiteGroup, DeleteSiteGroup, UpdateSiteGroup, ExportConfig, ImportConfig, GetCAInstallStatus, OpenCAFile, GetCACertPEM, GetSystemProxyStatus, EnableSystemProxy, DisableSystemProxy, RegenerateCert, ExportCert, GetListenPort, SetListenPort, GetStats, SetProxyMode, GetProxyMode} from '../wailsjs/go/main/App';

let isRunning = false;
let systemProxyEnabled = false;
let statsInterval = null;
let startTime = null;
let bytesDown = 0;
let bytesUp = 0;
let connections = 0;
let editingGroupId = null;
let loggingEnabled = true;

function formatBytes(bytes) {
    if (!bytes || bytes < 1024) return bytes + ' B';
    if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + ' KB';
    if (bytes < 1024 * 1024 * 1024) return (bytes / (1024 * 1024)).toFixed(1) + ' MB';
    return (bytes / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

function formatUptime() {
    if (!startTime) return '00:00:00';
    const elapsed = Math.floor((Date.now() - startTime) / 1000);
    const h = Math.floor(elapsed / 3600).toString().padStart(2, '0');
    const m = Math.floor((elapsed % 3600) / 60).toString().padStart(2, '0');
    const s = (elapsed % 60).toString().padStart(2, '0');
    return `${h}:${m}:${s}`;
}

function updateStatus() {
    const statusEl = document.getElementById('proxy-status');
    const btnStart = document.getElementById('btn-start');
    const btnStop = document.getElementById('btn-stop');
    const btnSysProxy = document.getElementById('btn-sysproxy');
    const proxyMode = document.getElementById('proxy-mode');
    const mode = document.querySelector('input[name="mode"]:checked').value;
    
    proxyMode.textContent = mode === 'mitm' ? 'MITM' : '透传';
    
    if (isRunning) {
        statusEl.classList.add('running');
        statusEl.querySelector('.status-text').textContent = '运行中';
        btnStart.style.display = 'none';
        btnStop.style.display = 'inline-flex';
    } else {
        statusEl.classList.remove('running');
        statusEl.querySelector('.status-text').textContent = '已停止';
        btnStart.style.display = 'inline-flex';
        btnStop.style.display = 'none';
    }
    
    if (btnSysProxy) {
        btnSysProxy.textContent = `系统代理: ${systemProxyEnabled ? '开' : '关'}`;
        btnSysProxy.className = systemProxyEnabled ? 'btn btn-success' : 'btn btn-secondary';
    }
}

async function loadSystemProxyStatus() {
    try {
        const status = await GetSystemProxyStatus();
        systemProxyEnabled = status.enabled;
        updateStatus();
    } catch (err) {
        console.error('Load system proxy status error:', err);
    }
}

window.toggleSystemProxy = async function() {
    try {
        if (systemProxyEnabled) {
            await DisableSystemProxy();
            systemProxyEnabled = false;
            addLog('info', '系统代理已关闭');
        } else {
            const port = await GetListenPort();
            await EnableSystemProxy();
            systemProxyEnabled = true;
            addLog('info', `系统代理已开启 (127.0.0.1:${port})`);
        }
        updateStatus();
    } catch (err) {
        console.error('Toggle system proxy error:', err);
        addLog('error', '系统代理设置失败: ' + err);
    }
};

window.startProxy = async function() {
    const mode = document.querySelector('input[name="mode"]:checked').value;
    
    if (mode === 'mitm') {
        try {
            const status = await GetCAInstallStatus();
            if (!status.Installed) {
                showCertModal();
                return;
            }
        } catch (err) {
            console.error('Check cert status error:', err);
        }
    }
    
    try {
        await SetProxyMode(mode);
        await StartProxy();
        isRunning = true;
        startTime = Date.now();
        
        statsInterval = setInterval(async () => {
            document.getElementById('stat-uptime').textContent = formatUptime();
            try {
                const stats = await GetStats();
                document.getElementById('stat-downlink').textContent = formatBytes(stats[0]);
                document.getElementById('stat-uplink').textContent = formatBytes(stats[1]);
                document.getElementById('stat-connections').textContent = stats[2];
            } catch (err) {
                console.error('Get stats error:', err);
            }
        }, 1000);
        
        addLog('info', '代理已启动');
    } catch (err) {
        console.error('Start proxy error:', err);
        addLog('error', '启动失败: ' + err);
    }
    updateStatus();
};

window.stopProxy = async function() {
    try {
        await StopProxy();
        isRunning = false;
        if (statsInterval) {
            clearInterval(statsInterval);
            statsInterval = null;
        }
        addLog('info', '代理已停止');
    } catch (err) {
        console.error('Stop proxy error:', err);
        addLog('error', '停止失败: ' + err);
    }
    updateStatus();
};

function addLog(level, message) {
    if (!loggingEnabled) return;
    
    const container = document.getElementById('log-container');
    if (!container) return;
    
    const now = new Date();
    const timeStr = now.toTimeString().split(' ')[0];
    
    const entry = document.createElement('div');
    entry.className = 'log-entry';
    entry.innerHTML = `<span class="log-time">${timeStr}</span><span class="log-level ${level}">${level.toUpperCase()}</span><span>${message}</span>`;
    
    container.appendChild(entry);
    container.scrollTop = container.scrollHeight;
    
    if (container.children.length > 500) {
        container.removeChild(container.firstChild);
    }
}

function showPage(pageId) {
    document.querySelectorAll('.page').forEach(p => p.style.display = 'none');
    document.getElementById('page-' + pageId).style.display = 'block';
    
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
        if (item.dataset.page === pageId) {
            item.classList.add('active');
        }
    });

    if (pageId === 'rules') {
        loadSiteGroups();
    }
}

async function loadSiteGroups() {
    try {
        const groups = await GetSiteGroups();
        const container = document.getElementById('rules-list');
        
        if (!groups || groups.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">-</div>
                    <div class="empty-state-text">暂无规则</div>
                    <div class="empty-state-hint">点击上方按钮添加</div>
                </div>
            `;
            return;
        }
        
        container.innerHTML = '';
        
        groups.forEach(group => {
            const item = document.createElement('div');
            item.className = 'rule-item';
            item.innerHTML = `
                <div class="rule-info">
                    <div class="rule-name">${group.name || '未命名'}</div>
                    <div class="rule-domains">${(group.domains || []).join(', ')}</div>
                    <div class="rule-mode">${group.mode === 'mitm' ? 'MITM' : '透传'}${group.upstream ? ' → ' + group.upstream : ''}</div>
                </div>
                <div class="rule-actions">
                    <button class="btn btn-secondary" onclick="showEditRuleModal('${group.id}')">编辑</button>
                    <button class="btn btn-danger" onclick="deleteSiteGroup('${group.id}')">删除</button>
                </div>
            `;
            container.appendChild(item);
        });
    } catch (err) {
        console.error('Load site groups error:', err);
    }
}

window.deleteSiteGroup = async function(id) {
    try {
        await DeleteSiteGroup(id);
        addLog('info', '删除规则: ' + id);
        loadSiteGroups();
    } catch (err) {
        addLog('error', '删除失败: ' + err);
    }
};

window.showAddRuleModal = function() {
    editingGroupId = null;
    document.getElementById('modal-title').textContent = '添加规则';
    document.getElementById('input-name').value = '';
    document.getElementById('input-domains').value = '';
    document.getElementById('input-mode').value = 'mitm';
    document.getElementById('input-upstream').value = '';
    document.getElementById('input-snifake').value = '';
    document.getElementById('input-enabled').checked = true;
    document.getElementById('modal-overlay').style.display = 'flex';
};

window.showEditRuleModal = async function(id) {
    try {
        const groups = await GetSiteGroups();
        const group = groups.find(g => g.id === id);
        if (!group) {
            addLog('error', '找不到该规则');
            return;
        }

        editingGroupId = id;
        document.getElementById('modal-title').textContent = '编辑规则';
        document.getElementById('input-name').value = group.name || '';
        document.getElementById('input-domains').value = (group.domains || []).join('\n');
        document.getElementById('input-mode').value = group.mode || 'mitm';
        document.getElementById('input-upstream').value = group.upstream || '';
        document.getElementById('input-snifake').value = group.sni_fake || '';
        document.getElementById('input-enabled').checked = group.enabled !== false;
        document.getElementById('modal-overlay').style.display = 'flex';
    } catch (err) {
        console.error('Edit rule error:', err);
        addLog('error', '加载规则失败: ' + err);
    }
};

window.closeModal = function() {
    document.getElementById('modal-overlay').style.display = 'none';
};

window.confirmModal = async function() {
    const name = document.getElementById('input-name').value;
    const domains = document.getElementById('input-domains').value.split('\n').filter(d => d.trim());
    const mode = document.getElementById('input-mode').value;
    const upstream = document.getElementById('input-upstream').value;
    const snifake = document.getElementById('input-snifake').value;
    const enabled = document.getElementById('input-enabled').checked;
    
    if (!name || domains.length === 0) {
        addLog('warn', '请填写名称和域名');
        return;
    }
    
    if (mode === 'transparent' && !upstream) {
        addLog('warn', '透传模式需要填写上游服务器地址');
        return;
    }
    
    try {
        const groupData = {
            name,
            domains,
            mode,
            upstream,
            sni_fake: snifake,
            enabled
        };
        
        if (editingGroupId) {
            groupData.id = editingGroupId;
            await UpdateSiteGroup(groupData);
            addLog('info', '更新规则: ' + name);
        } else {
            groupData.id = 'sg-' + Date.now();
            await AddSiteGroup(groupData);
            addLog('info', '添加规则: ' + name);
        }
        
        loadSiteGroups();
        closeModal();
    } catch (err) {
        addLog('error', '操作失败: ' + err);
    }
};

window.clearLogs = function() {
    const container = document.getElementById('log-container');
    if (container) container.innerHTML = '';
    addLog('info', '日志已清空');
};

window.exportConfig = async function() {
    try {
        const config = await ExportConfig();
        const blob = new Blob([config], {type: 'application/json'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'snishaper-config.json';
        a.click();
        URL.revokeObjectURL(url);
        addLog('info', '配置已导出');
    } catch (err) {
        addLog('error', '导出失败: ' + err);
    }
};

window.importConfig = function() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = async (e) => {
        const file = e.target.files[0];
        const reader = new FileReader();
        reader.onload = async (ev) => {
            try {
                await ImportConfig(ev.target.result);
                addLog('info', '配置已导入');
                loadSiteGroups();
            } catch (err) {
                addLog('error', '导入失败: ' + err);
            }
        };
        reader.readAsText(file);
    };
    input.click();
};

window.regenerateCert = async function() {
    try {
        await RegenerateCert();
        addLog('info', '证书已重新生成，请重新安装到系统信任库');
    } catch (err) {
        addLog('error', '重新生成证书失败: ' + err);
    }
};

window.exportCert = async function() {
    try {
        const pem = await ExportCert();
        const blob = new Blob([pem], {type: 'application/x-pem-file'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'snishaper-ca.crt';
        a.click();
        URL.revokeObjectURL(url);
        addLog('info', '证书已导出');
    } catch (err) {
        addLog('error', '导出证书失败: ' + err);
    }
};

window.showCertModal = async function() {
    const modal = document.getElementById('cert-modal');
    const statusEl = document.getElementById('cert-install-status');
    const pathEl = document.getElementById('cert-path');
    const helpEl = document.getElementById('cert-help-text');
    
    try {
        const status = await GetCAInstallStatus();
        statusEl.textContent = status.Installed ? '已安装' : '未安装';
        statusEl.style.color = status.Installed ? 'var(--success)' : 'var(--danger)';
        pathEl.textContent = status.CertPath || 'N/A';
        helpEl.textContent = status.InstallHelp || '';
    } catch (err) {
        console.error('Get cert status error:', err);
        statusEl.textContent = '获取失败';
        pathEl.textContent = err.message;
    }
    
    modal.style.display = 'flex';
};

window.closeCertModal = function() {
    document.getElementById('cert-modal').style.display = 'none';
};

window.openCertFile = async function() {
    try {
        await OpenCAFile();
        addLog('info', '已打开证书文件');
    } catch (err) {
        console.error('Open cert file error:', err);
        addLog('error', '打开证书文件失败: ' + err);
    }
};

function updateThemeIcon(theme) {
    const toggleBtn = document.getElementById('theme-toggle');
    if (toggleBtn) {
        toggleBtn.textContent = theme === 'dark' ? '☀️' : '🌙';
    }
}

async function checkCertAndPrompt() {
    const mode = document.querySelector('input[name="mode"]:checked').value;
    if (mode !== 'mitm') return;
    
    try {
        const status = await GetCAInstallStatus();
        if (!status.Installed) {
            showCertModal();
        }
    } catch (err) {
        console.error('Check cert status error:', err);
    }
}

document.addEventListener('DOMContentLoaded', async () => {
    const theme = localStorage.getItem('theme') || 'light';
    document.documentElement.setAttribute('data-theme', theme);
    updateThemeIcon(theme);
    
    document.getElementById('theme-toggle').addEventListener('click', () => {
        const currentTheme = document.documentElement.getAttribute('data-theme');
        const nextTheme = currentTheme === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', nextTheme);
        localStorage.setItem('theme', nextTheme);
        updateThemeIcon(nextTheme);
    });
    
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', (e) => {
            if (item.id === 'theme-toggle') return;
            e.preventDefault();
            const page = item.dataset.page;
            showPage(page);
        });
    });

    document.querySelectorAll('input[name="mode"]').forEach(radio => {
        radio.addEventListener('change', async () => {
            updateStatus();
            try {
                await SetProxyMode(radio.value);
                addLog('info', '运行模式切换为: ' + (radio.value === 'mitm' ? 'MITM' : '透传'));
            } catch (err) {
                addLog('error', '模式切换失败: ' + err);
            }
            await checkCertAndPrompt();
        });
    });

    document.getElementById('modal-overlay').addEventListener('click', (e) => {
        if (e.target === document.getElementById('modal-overlay')) {
            closeModal();
        }
    });

    const portInput = document.getElementById('setting-port');
    if (portInput) {
        try {
            const port = await GetListenPort();
            portInput.value = port || 8080;
        } catch (err) {
            console.error('Get listen port error:', err);
        }
        portInput.addEventListener('change', async () => {
            const newPort = parseInt(portInput.value, 10);
            if (newPort >= 1 && newPort <= 65535) {
                try {
                    await SetListenPort(newPort);
                    document.getElementById('listen-port').textContent = newPort;
                    addLog('info', '监听端口已设置为 ' + newPort);
                } catch (err) {
                    addLog('error', '设置端口失败: ' + err);
                    portInput.value = await GetListenPort();
                }
            } else {
                addLog('error', '端口号无效 (1-65535)');
                portInput.value = await GetListenPort();
            }
        });
    }

    const logsCheckbox = document.getElementById('setting-logs');
    if (logsCheckbox) {
        logsCheckbox.checked = loggingEnabled;
        logsCheckbox.addEventListener('change', () => {
            loggingEnabled = logsCheckbox.checked;
            if (loggingEnabled) {
                addLog('info', '日志已启用');
            }
        });
    }

    addLog('info', 'SniShaper 已就绪');

    try {
        const backendMode = await GetProxyMode();
        if (backendMode === 'mitm' || backendMode === 'transparent') {
            const radio = document.querySelector(`input[name="mode"][value="${backendMode}"]`);
            if (radio) radio.checked = true;
        } else {
            const mode = document.querySelector('input[name="mode"]:checked').value;
            await SetProxyMode(mode);
        }
    } catch (err) {
        console.error('Init proxy mode error:', err);
    }

    updateStatus();
    
    await loadSystemProxyStatus();
    await checkCertAndPrompt();
});
