import './style.css';

import {StartProxy, StopProxy, IsProxyRunning, GetSiteGroups, AddSiteGroup, DeleteSiteGroup, UpdateSiteGroup, ExportConfig, ImportConfigWithSummary, GetCAInstallStatus, OpenCAFile, GetCACertPEM, GetSystemProxyStatus, EnableSystemProxy, DisableSystemProxy, RegenerateCert, ExportCert, GetListenPort, SetListenPort, GetStats, SetProxyMode, GetProxyMode, GetRecentLogs, ClearLogs, ProxySelfCheck, GetProxyDiagnostics, GetRuleHitCounts} from '../wailsjs/go/main/App';
import {WindowMinimise, WindowToggleMaximise, Quit} from '../wailsjs/runtime/runtime';

let isRunning = false;
let systemProxyEnabled = false;
let statsInterval = null;
let startTime = null;
let bytesDown = 0;
let bytesUp = 0;
let connections = 0;
let editingGroupId = null;
let loggingEnabled = true;
let backendLogPoll = null;
let rulesSearchQuery = '';
let rulesViewMode = 'mitm';

window.windowMinimise = function() {
    WindowMinimise();
};

window.windowToggleMaximise = function() {
    WindowToggleMaximise();
};

window.windowCloseApp = function() {
    Quit();
};

function getWebsiteKey(group) {
    const website = (group.website || '').trim();
    if (website) return website;
    const name = (group.name || '').trim();
    if (name) return name;
    const firstDomain = (group.domains || [])[0] || '';
    return firstDomain.trim() || '未分组';
}

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
            if (!isRunning) {
                addLog('warn', '系统代理依赖本地代理服务，正在先启动代理...');
                const mode = document.querySelector('input[name="mode"]:checked').value;
                await SetProxyMode(mode);
                await StartProxy();
                isRunning = true;
                startTime = Date.now();
                if (!statsInterval) {
                    statsInterval = setInterval(async () => {
                        document.getElementById('stat-uptime').textContent = formatUptime();
                        try {
                            const stats = await GetStats();
                            document.getElementById('stat-downlink').textContent = formatBytes(stats[0]);
                            document.getElementById('stat-uplink').textContent = formatBytes(stats[1]);
                            document.getElementById('stat-connections').textContent = stats[2];
                            const diag = await GetProxyDiagnostics();
                            const acceptedEl = document.getElementById('stat-accepted');
                            const connectsEl = document.getElementById('stat-connects');
                            if (acceptedEl) acceptedEl.textContent = String(diag.Accepted || 0);
                            if (connectsEl) connectsEl.textContent = String(diag.Connects || 0);
                        } catch (err) {
                            console.error('Get stats error:', err);
                        }
                    }, 1000);
                }
                updateStatus();
            }
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
                addLog('warn', '未检测到受信任 CA，仍尝试启动 MITM（浏览器可能证书告警）');
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
                const diag = await GetProxyDiagnostics();
                const acceptedEl = document.getElementById('stat-accepted');
                const connectsEl = document.getElementById('stat-connects');
                if (acceptedEl) acceptedEl.textContent = String(diag.Accepted || 0);
                if (connectsEl) connectsEl.textContent = String(diag.Connects || 0);
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
        if (systemProxyEnabled) {
            await DisableSystemProxy();
            systemProxyEnabled = false;
            addLog('warn', '已自动关闭系统代理，避免断网');
        }
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
    if (pageId === 'logs') {
        refreshBackendLogs();
        if (!backendLogPoll) {
            backendLogPoll = setInterval(refreshBackendLogs, 1200);
        }
    } else if (backendLogPoll) {
        clearInterval(backendLogPoll);
        backendLogPoll = null;
    }
}

function guessLogLevel(line) {
    const s = line.toLowerCase();
    if (s.includes('error') || s.includes('failed') || s.includes('panic')) return 'error';
    if (s.includes('warn')) return 'warn';
    return 'info';
}

async function refreshBackendLogs() {
    const container = document.getElementById('log-container');
    if (!container) return;
    try {
        const text = await GetRecentLogs(400);
        const lines = (text || '').split('\n').filter(Boolean);
        container.innerHTML = '';
        if (lines.length === 0) {
            const entry = document.createElement('div');
            entry.className = 'log-entry';
            entry.innerHTML = `<span class="log-time">--:--:--</span><span class="log-level warn">WARN</span><span>后端日志为空：请求可能未进入代理，或日志接口未返回内容。</span>`;
            container.appendChild(entry);
            return;
        }
        lines.forEach(line => {
            const level = guessLogLevel(line);
            const entry = document.createElement('div');
            entry.className = 'log-entry';

            const time = document.createElement('span');
            time.className = 'log-time';
            time.textContent = '--:--:--';

            const levelEl = document.createElement('span');
            levelEl.className = `log-level ${level}`;
            levelEl.textContent = level.toUpperCase();

            const msg = document.createElement('span');
            msg.style.whiteSpace = 'pre-wrap';
            msg.textContent = line;

            entry.appendChild(time);
            entry.appendChild(levelEl);
            entry.appendChild(msg);
            container.appendChild(entry);
        });
        container.scrollTop = container.scrollHeight;

        const diag = await GetProxyDiagnostics();
        const ingressEl = document.getElementById('ingress-list');
        if (ingressEl) {
            ingressEl.textContent = (diag.RecentIngress || []).length > 0
                ? diag.RecentIngress.join('  |  ')
                : '暂无';
        }
        const acceptedEl = document.getElementById('stat-accepted');
        const connectsEl = document.getElementById('stat-connects');
        if (acceptedEl) acceptedEl.textContent = String(diag.Accepted || 0);
        if (connectsEl) connectsEl.textContent = String(diag.Connects || 0);
    } catch (err) {
        console.error('Refresh backend logs error:', err);
        container.innerHTML = '';
        const entry = document.createElement('div');
        entry.className = 'log-entry';
        entry.innerHTML = `<span class="log-time">--:--:--</span><span class="log-level error">ERROR</span><span>读取后端日志失败: ${String(err)}</span>`;
        container.appendChild(entry);
    }
}

async function loadSiteGroups() {
    try {
        const [groups, hitMap] = await Promise.all([GetSiteGroups(), GetRuleHitCounts()]);
        const container = document.getElementById('rules-list');
        const query = rulesSearchQuery.trim().toLowerCase();
        
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

        const buildModeColumn = (mode, title) => {
            const modeGroups = groups
                .filter(g => (g.mode || '').toLowerCase() === mode)
                .filter(g => {
                    if (!query) return true;
                    const haystack = [
                        g.name || '',
                        g.website || '',
                        g.upstream || '',
                        ...(g.domains || [])
                    ].join(' ').toLowerCase();
                    return haystack.includes(query);
                });

            const modeColumn = document.createElement('div');
            modeColumn.className = 'rules-column';

            const modeBlock = document.createElement('div');
            modeBlock.className = 'website-group rules-mode-block';

            const modeHeader = document.createElement('div');
            modeHeader.className = 'website-group-header';
            modeHeader.innerHTML = `
                <div class="website-group-title">${title}</div>
                <div class="website-group-count">${modeGroups.length} 条规则</div>
            `;
            modeBlock.appendChild(modeHeader);

            if (modeGroups.length === 0) {
                const empty = document.createElement('div');
                empty.className = 'rule-item';
                empty.innerHTML = `<div class="rule-info"><div class="rule-domains">暂无${title}规则</div></div>`;
                modeBlock.appendChild(empty);
                modeColumn.appendChild(modeBlock);
                return modeColumn;
            }

            const websiteMap = new Map();
            modeGroups.forEach(group => {
                const key = getWebsiteKey(group);
                if (!websiteMap.has(key)) {
                    websiteMap.set(key, []);
                }
                websiteMap.get(key).push(group);
            });

            Array.from(websiteMap.entries())
                .sort((a, b) => a[0].localeCompare(b[0], 'zh-Hans-CN'))
                .forEach(([website, websiteRules]) => {
                    const section = document.createElement('div');
                    section.className = 'website-group';

                    const header = document.createElement('div');
                    header.className = 'website-group-header';
                    const titleEl = document.createElement('div');
                    titleEl.className = 'website-group-title';
                    titleEl.textContent = website;

                    const tools = document.createElement('div');
                    tools.className = 'website-group-tools';

                    const countEl = document.createElement('div');
                    countEl.className = 'website-group-count';
                    countEl.textContent = `${websiteRules.length} 条规则`;

                    const addBtn = document.createElement('button');
                    addBtn.className = 'btn btn-secondary';
                    addBtn.textContent = '+ 本网站规则';
                    addBtn.onclick = () => window.showAddRuleModal({website, mode});

                    tools.appendChild(countEl);
                    tools.appendChild(addBtn);
                    header.appendChild(titleEl);
                    header.appendChild(tools);
                    section.appendChild(header);

                    websiteRules.forEach(group => {
                        const item = document.createElement('div');
                        item.className = 'rule-item';
                        item.innerHTML = `
                            <div class="rule-info">
                                <div class="rule-name">${group.name || '未命名'}</div>
                                <div class="rule-domains">${(group.domains || []).join(', ')}</div>
                                <div class="rule-domains">命中: ${hitMap[group.id] || 0}</div>
                                <div class="rule-mode">${group.mode === 'mitm' ? 'MITM' : '透传'}${group.upstream ? ' → ' + group.upstream : ''}</div>
                            </div>
                            <div class="rule-actions">
                                <button class="btn btn-secondary" onclick="showEditRuleModal('${group.id}')">编辑</button>
                                <button class="btn btn-danger" onclick="deleteSiteGroup('${group.id}')">删除</button>
                            </div>
                        `;
                        section.appendChild(item);
                    });

                    modeBlock.appendChild(section);
                });

            modeColumn.appendChild(modeBlock);
            return modeColumn;
        };

        const title = rulesViewMode === 'transparent' ? '透传规则' : 'MITM 规则';
        container.appendChild(buildModeColumn(rulesViewMode, title));
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
    let defaults = {};
    if (arguments.length > 0 && typeof arguments[0] === 'object' && arguments[0] !== null) {
        defaults = arguments[0];
    }
    editingGroupId = null;
    document.getElementById('modal-title').textContent = '添加规则';
    document.getElementById('input-name').value = '';
    document.getElementById('input-website').value = defaults.website || '';
    document.getElementById('input-domains').value = '';
    document.getElementById('input-mode').value = defaults.mode || 'mitm';
    document.getElementById('input-upstream').value = '';
    document.getElementById('input-snifake').value = '';
    document.getElementById('input-utls-policy').value = '';
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
        document.getElementById('input-website').value = group.website || '';
        document.getElementById('input-domains').value = (group.domains || []).join('\n');
        document.getElementById('input-mode').value = group.mode || 'mitm';
        document.getElementById('input-upstream').value = group.upstream || '';
        document.getElementById('input-snifake').value = group.sni_fake || '';
        document.getElementById('input-utls-policy').value = group.utls_policy || '';
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
    const website = document.getElementById('input-website').value.trim();
    const domains = document.getElementById('input-domains').value.split('\n').filter(d => d.trim());
    const mode = document.getElementById('input-mode').value;
    const upstream = document.getElementById('input-upstream').value;
    const snifake = document.getElementById('input-snifake').value;
    const utlsPolicy = document.getElementById('input-utls-policy').value;
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
            website,
            domains,
            mode,
            upstream,
            sni_fake: snifake,
            utls_policy: utlsPolicy,
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

window.clearLogs = async function() {
    try {
        await ClearLogs();
        await refreshBackendLogs();
        addLog('info', '日志文件已清空');
    } catch (err) {
        addLog('error', '清空日志失败: ' + err);
    }
};

window.runProxySelfCheck = async function() {
    try {
        const result = await ProxySelfCheck();
        addLog('info', result || '自检完成');
        await refreshBackendLogs();
    } catch (err) {
        addLog('error', '代理自检失败: ' + err);
    }
};

window.exportConfig = async function() {
    try {
        const config = await ExportConfig();
        const blob = new Blob([config], {type: 'application/json'});
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        const now = new Date();
        const stamp = `${now.getFullYear()}${String(now.getMonth() + 1).padStart(2, '0')}${String(now.getDate()).padStart(2, '0')}-${String(now.getHours()).padStart(2, '0')}${String(now.getMinutes()).padStart(2, '0')}${String(now.getSeconds()).padStart(2, '0')}`;
        a.download = `snishaper-rules-${stamp}.json`;
        a.click();
        URL.revokeObjectURL(url);
        addLog('info', '规则配置已导出');
    } catch (err) {
        addLog('error', '导出规则失败: ' + err);
    }
};

window.importConfig = function() {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.json';
    input.onchange = async (e) => {
        const file = e.target.files && e.target.files[0];
        if (!file) {
            addLog('warn', '未选择文件，已取消导入');
            return;
        }
        const reader = new FileReader();
        reader.onload = async (ev) => {
            try {
                const summary = await ImportConfigWithSummary(String(ev.target?.result || ''));
                addLog('info', `规则配置已导入: ${file.name} (新增 ${summary.added || 0}, 覆盖 ${summary.overwritten || 0}, 跳过 ${summary.skipped || 0})`);
                await loadSiteGroups();
                window.alert(`导入成功\n文件: ${file.name}\n新增: ${summary.added || 0}\n覆盖: ${summary.overwritten || 0}\n跳过: ${summary.skipped || 0}`);
            } catch (err) {
                addLog('error', '导入规则失败: ' + err);
                window.alert('导入失败: ' + err);
            }
        };
        reader.onerror = () => {
            const msg = '读取文件失败';
            addLog('error', msg + ': ' + file.name);
            window.alert(msg);
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
        toggleBtn.setAttribute('aria-label', theme === 'dark' ? '切换到亮色' : '切换到暗色');
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

    const rulesSearch = document.getElementById('rules-search');
    if (rulesSearch) {
        rulesSearch.addEventListener('input', () => {
            rulesSearchQuery = rulesSearch.value || '';
            const rulesPage = document.getElementById('page-rules');
            if (rulesPage && rulesPage.style.display !== 'none') {
                loadSiteGroups();
            }
        });
    }

    const modeMitmBtn = document.getElementById('rules-mode-mitm');
    const modeTransBtn = document.getElementById('rules-mode-transparent');
    const updateRulesModeButtons = () => {
        if (modeMitmBtn) modeMitmBtn.classList.toggle('active', rulesViewMode === 'mitm');
        if (modeTransBtn) modeTransBtn.classList.toggle('active', rulesViewMode === 'transparent');
    };
    if (modeMitmBtn) {
        modeMitmBtn.addEventListener('click', () => {
            rulesViewMode = 'mitm';
            updateRulesModeButtons();
            loadSiteGroups();
        });
    }
    if (modeTransBtn) {
        modeTransBtn.addEventListener('click', () => {
            rulesViewMode = 'transparent';
            updateRulesModeButtons();
            loadSiteGroups();
        });
    }
    updateRulesModeButtons();

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
        isRunning = await IsProxyRunning();
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
