/* ==========================================================================
   DARK WEB BREACH SHIELD - DYNAMIC FRONT-END LOGIC & INTEGRATIONS
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
    // Global App Configuration / State
    let appStatus = {
        demo_mode: true,
        gemini_enabled: false,
        smtp_configured: false,
        smtp_host: 'smtp.gmail.com',
        smtp_port: 587
    };

    // Chart.js Instances (needed for resetting/destroying charts on refresh)
    let chartDataTypes = null;
    let chartSeverity = null;
    let chartTimeline = null;

    // Cache DOM Elements
    const tabButtons = document.querySelectorAll('.nav-item');
    const tabPanes = document.querySelectorAll('.tab-pane');
    
    // Status Dots
    const statusDemoDot = document.getElementById('status-demo-dot');
    const statusDemoText = document.getElementById('status-demo-text');
    const statusGeminiDot = document.getElementById('status-gemini-dot');
    const statusGeminiText = document.getElementById('status-gemini-text');
    const statusSmtpDot = document.getElementById('status-smtp-dot');
    const statusSmtpText = document.getElementById('status-smtp-text');

    // ==============================
    // SPA ROUTING / TAB CONTROL
    // ==============================
    tabButtons.forEach(button => {
        button.addEventListener('click', () => {
            const targetTab = button.getAttribute('data-tab');
            
            // Toggle Button Classes
            tabButtons.forEach(btn => btn.classList.remove('active'));
            button.classList.add('active');

            // Toggle Pane Classes
            tabPanes.forEach(pane => {
                if (pane.id === targetTab) {
                    pane.classList.add('active');
                } else {
                    pane.classList.remove('active');
                }
            });

            // Trigger dashboard reload if user opens the dashboard tab
            if (targetTab === 'tab-dashboard') {
                loadDashboardData();
            }
        });
    });

    // ==============================
    // INITIAL SYSTEM STATUS FETCH
    // ==============================
    async function fetchSystemStatus() {
        try {
            const res = await fetch('/api/status');
            const data = await res.json();
            appStatus = data;
            
            updateStatusUI();
            
            // Populate Config inputs
            document.getElementById('settings-smtp-host').value = data.smtp_host;
            document.getElementById('settings-smtp-port').value = data.smtp_port;
            document.getElementById('toggle-gemini').checked = data.gemini_enabled;
            
            if (data.smtp_configured) {
                document.getElementById('settings-smtp-user').value = data.email_user;
            }

            const geminiWarningBox = document.getElementById('gemini-key-status');
            if (data.gemini_available) {
                geminiWarningBox.classList.add('hidden');
                document.getElementById('toggle-gemini').disabled = false;
            } else {
                geminiWarningBox.classList.remove('hidden');
                document.getElementById('toggle-gemini').disabled = true;
                document.getElementById('toggle-gemini').checked = false;
            }
        } catch (err) {
            console.error("Failed to fetch status:", err);
        }
    }

    function updateStatusUI() {
        // Demo mode
        if (appStatus.demo_mode) {
            statusDemoDot.className = 'status-dot warning';
            statusDemoText.textContent = 'Active (Mock)';
        } else {
            statusDemoDot.className = 'status-dot success';
            statusDemoText.textContent = 'Live API';
        }

        // Gemini AI Threat Engine
        if (appStatus.gemini_enabled) {
            statusGeminiDot.className = 'status-dot success';
            statusGeminiText.textContent = 'Active';
        } else {
            statusGeminiDot.className = 'status-dot danger';
            statusGeminiText.textContent = 'Inactive';
        }

        // SMTP Alert Gateway
        if (appStatus.smtp_configured) {
            statusSmtpDot.className = 'status-dot success';
            statusSmtpText.textContent = 'Active';
        } else {
            statusSmtpDot.className = 'status-dot danger';
            statusSmtpText.textContent = 'Inactive';
        }
    }

    // ==============================
    // MONITORED ASSETS SYSTEM
    // ==============================
    async function loadMonitoredAssets() {
        try {
            const res = await fetch('/api/monitored');
            const list = await res.json();
            const container = document.getElementById('monitored-list-sidebar');
            container.innerHTML = '';

            if (list.length === 0) {
                container.innerHTML = `<p class="empty-list-text">No email accounts registered.</p>`;
                return;
            }

            list.forEach(item => {
                const element = document.createElement('div');
                element.className = 'monitored-item';
                
                const isSafe = item.breach_count === 0;
                const badgeStyle = isSafe ? 'color-safe' : 'color-critical';
                const countText = isSafe ? '0 Breaches' : `${item.breach_count} Breaches`;
                
                element.innerHTML = `
                    <div class="monitored-info">
                        <span class="monitored-email" title="${item.email}">${item.email}</span>
                        <span class="monitored-sub ${badgeStyle}">${countText}</span>
                    </div>
                    <button class="btn-delete-monitor" data-email="${item.email}" title="Stop Monitoring">🗑️</button>
                `;

                // Handle Delete Monitor Click
                element.querySelector('.btn-delete-monitor').addEventListener('click', async (e) => {
                    const email = e.target.getAttribute('data-email');
                    if (confirm(`Stop continuous threat monitoring for ${email}?`)) {
                        await deleteMonitoredAsset(email);
                    }
                });

                container.appendChild(element);
            });
        } catch (err) {
            console.error("Failed to load monitored assets:", err);
        }
    }

    async function deleteMonitoredAsset(email) {
        try {
            const res = await fetch('/api/monitor/delete', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });
            const data = await res.json();
            if (data.status === 'success') {
                loadMonitoredAssets();
                // If dashboard is open, reload stats
                if (document.getElementById('tab-dashboard').classList.contains('active')) {
                    loadDashboardData();
                }
            } else {
                alert("Failed to delete asset: " + data.message);
            }
        } catch (err) {
            console.error("Delete error:", err);
        }
    }

    // Sync button in sidebar
    const btnSidebarSync = document.getElementById('btn-sidebar-sync');
    const syncProgressContainer = document.getElementById('sync-progress-container');
    const syncProgressBar = document.getElementById('sync-progress-bar');
    const syncProgressText = document.getElementById('sync-progress-text');

    btnSidebarSync.addEventListener('click', async () => {
        btnSidebarSync.classList.add('spinning');
        btnSidebarSync.disabled = true;
        
        syncProgressContainer.classList.remove('hidden');
        syncProgressBar.style.width = '20%';
        syncProgressText.textContent = 'Connecting to threat servers...';

        try {
            const res = await fetch('/api/monitor/sync', { method: 'POST' });
            syncProgressBar.style.width = '80%';
            syncProgressText.textContent = 'Updating cache lists...';
            
            const data = await res.json();
            if (data.status === 'success') {
                syncProgressBar.style.width = '100%';
                syncProgressText.textContent = 'Database Synchronized!';
                setTimeout(() => {
                    syncProgressContainer.classList.add('hidden');
                    btnSidebarSync.classList.remove('spinning');
                    btnSidebarSync.disabled = false;
                    loadMonitoredAssets();
                    if (document.getElementById('tab-dashboard').classList.contains('active')) {
                        loadDashboardData();
                    }
                }, 1000);
            } else {
                throw new Error(data.message || 'Sync failed');
            }
        } catch (err) {
            console.error("Sync error:", err);
            syncProgressText.textContent = 'Sync Failure. Try again.';
            syncProgressBar.style.backgroundColor = '#ef4444';
            setTimeout(() => {
                syncProgressContainer.classList.add('hidden');
                btnSidebarSync.classList.remove('spinning');
                btnSidebarSync.disabled = false;
                syncProgressBar.style.backgroundColor = ''; // Reset
            }, 3000);
        }
    });

    // ==============================
    // TAB 1: ACTIVE EMAIL SCANNER
    // ==============================
    const btnRunScan = document.getElementById('btn-run-scan');
    const scanEmailInput = document.getElementById('scan-email');
    const scanLoader = document.getElementById('scan-loader');
    const scanResults = document.getElementById('scan-results');

    btnRunScan.addEventListener('click', executeIdentityScan);
    scanEmailInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') executeIdentityScan();
    });

    async function executeIdentityScan() {
        const email = scanEmailInput.value.trim();
        if (!email) {
            alert("Please input a valid target email address.");
            return;
        }

        // Show loading and reset display states
        scanResults.classList.add('hidden');
        scanResults.innerHTML = '';
        scanLoader.classList.remove('hidden');

        // Dynamic terminal logs simulating scanning operations
        const logLines = scanLoader.querySelectorAll('.log-line');
        logLines[0].textContent = "> Initializing breach verification payload...";
        logLines[1].textContent = "> Querying LeakCheck API data catalog...";
        logLines[2].textContent = "> Calculating credential hash signatures...";
        if (appStatus.gemini_enabled) {
            const aiLog = document.createElement('p');
            aiLog.className = 'log-line text-blue temp-log';
            aiLog.textContent = "> Dispatching intelligence logs to Gemini Threat Core...";
            scanLoader.querySelector('.scanner-log').appendChild(aiLog);
        }

        try {
            const res = await fetch('/api/scan', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email })
            });
            const data = await res.json();
            
            // Remove temp log
            const tempLog = scanLoader.querySelector('.temp-log');
            if (tempLog) tempLog.remove();

            if (res.status !== 200) {
                throw new Error(data.message || 'Identity assessment failed.');
            }

            renderScanResults(data);
        } catch (err) {
            console.error("Scan error:", err);
            alert("Error running identity check: " + err.message);
            scanLoader.classList.add('hidden');
        }
    }

    function renderScanResults(data) {
        scanLoader.classList.add('hidden');
        scanResults.classList.remove('hidden');

        const isCompromised = data.breaches.length > 0;
        const bannerClass = isCompromised ? 'critical' : 'safe';
        const bannerIcon = isCompromised ? '⚠️' : '✅';
        const bannerTitle = isCompromised ? `Compromise Detected! Found in ${data.breaches.length} leaks.` : `Status Clear: ${data.email}`;
        const bannerDesc = isCompromised 
            ? 'Credential leaks found. Action required to secure connected assets.' 
            : 'No exposures found in indexed public database records.';

        // Build HTML
        let html = `
            <div class="results-box">
                <div class="scan-alert-banner ${bannerClass}">
                    <span class="banner-icon">${bannerIcon}</span>
                    <div class="banner-text">
                        <h3>${bannerTitle}</h3>
                        <p>${bannerDesc}</p>
                    </div>
                </div>
        `;

        if (isCompromised) {
            // Render specific leak reports
            html += `
                <div class="cyber-card">
                    <h3 class="card-title">Detailed Exposure Reports</h3>
                    <div class="breach-detail-box">
            `;
            
            data.breaches.forEach(b => {
                const leaksList = b.leaks.map(l => `<span class="data-tag">${l}</span>`).join(' ');
                html += `
                    <div class="breach-item">
                        <div class="breach-header-row">
                            <span class="breach-source-name">${b.name}</span>
                            <span class="breach-year">Date: ${b.date}</span>
                        </div>
                        <div class="breach-types">
                            ${leaksList}
                        </div>
                    </div>
                `;
            });

            html += `
                    </div>
                </div>
            `;

            // Render AI Threat Intelligence Advisory
            const markedHtml = marked.parse(data.report);
            const aiHeaderTitle = appStatus.gemini_enabled ? '🤖 AI Threat Intelligence Advisory' : '🛡️ Local Threat Assessment Brief';
            html += `
                <div class="cyber-card ai-report-container">
                    <div class="ai-header">${aiHeaderTitle}</div>
                    <div class="ai-content">${markedHtml}</div>
                </div>
            `;

            // Render Remediation Checklist
            html += `
                <div class="cyber-card">
                    <h3 class="card-title">🛠️ Remediation Playbook Checklist</h3>
                    <div class="remediation-track">
            `;
            data.remediation.forEach(step => {
                html += `<div class="remediation-step">🔹 ${step}</div>`;
            });
            html += `
                    </div>
                </div>
            `;
        }

        // Option to add target to Continuous Monitoring
        html += `
            <div class="cyber-card">
                <h3 class="card-title">Continuous Background Monitoring</h3>
                <div class="switch-box">
                    <div class="switch-info">
                        <span class="switch-title">Register Identity Node</span>
                        <span class="switch-desc">Save email to local cache to run background synchronization checks and generate metrics.</span>
                    </div>
                    <button id="btn-add-monitoring" class="btn btn-secondary">➕ Monitor Email Address</button>
                </div>
            </div>
            </div>
        `;

        scanResults.innerHTML = html;

        // Register event listener for "Monitor Email Address" button
        document.getElementById('btn-add-monitoring').addEventListener('click', async () => {
            try {
                const res = await fetch('/api/monitor/add', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        email: data.email,
                        breach_count: data.breaches.length,
                        breaches: data.breaches
                    })
                });
                const resData = await res.json();
                if (resData.status === 'success') {
                    alert(`${data.email} registered for continuous monitoring.`);
                    loadMonitoredAssets();
                } else {
                    alert("Monitoring registration failed: " + resData.message);
                }
            } catch (err) {
                console.error("Monitor registration error:", err);
            }
        });
    }

    // ==============================
    // TAB 2: ANALYTICS CONSOLE (DASHBOARD)
    // ==============================
    async function loadDashboardData() {
        try {
            const res = await fetch('/api/dashboard/stats');
            const data = await res.json();
            
            // 1. Update Metrics
            document.getElementById('metric-assets').textContent = data.metrics.total_assets;
            document.getElementById('metric-breaches').textContent = data.metrics.total_breaches;
            
            const safeText = `${data.metrics.safe_assets} / ${data.metrics.total_assets}`;
            document.getElementById('metric-safe').textContent = safeText;
            document.getElementById('metric-critical').textContent = data.metrics.high_critical;

            // 2. Render Charts
            renderBarChart(data.data_types_distribution);
            renderPieChart(data.risk_distribution);
            renderTimelineChart(data.timeline);

            // 3. Render Inventory Table
            renderInventoryTable(data.inventory);
        } catch (err) {
            console.error("Dashboard load failed:", err);
        }
    }

    function renderBarChart(distribution) {
        const ctx = document.getElementById('chart-data-types').getContext('2d');
        
        // Destroy existing
        if (chartDataTypes) chartDataTypes.destroy();
        
        const sortedKeys = Object.keys(distribution).sort((a, b) => distribution[b] - distribution[a]);
        const counts = sortedKeys.map(k => distribution[k]);

        if (sortedKeys.length === 0) {
            // Render blank state message in canvas container
            return;
        }

        chartDataTypes = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: sortedKeys,
                datasets: [{
                    label: 'Incidences',
                    data: counts,
                    backgroundColor: 'rgba(59, 130, 246, 0.7)',
                    borderColor: 'rgb(59, 130, 246)',
                    borderWidth: 1,
                    borderRadius: 5
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#94a3b8' }
                    },
                    y: {
                        grid: { display: false },
                        ticks: { color: '#e2e8f0' }
                    }
                }
            }
        });
    }

    function renderPieChart(risks) {
        const ctx = document.getElementById('chart-severity').getContext('2d');
        
        if (chartSeverity) chartSeverity.destroy();

        const labels = ['Critical', 'High', 'Medium', 'Low'];
        const counts = labels.map(l => risks[l] || 0);
        const hasData = counts.some(c => c > 0);

        if (!hasData) {
            return;
        }

        chartSeverity = new Chart(ctx, {
            type: 'doughnut',
            data: {
                labels: labels,
                datasets: [{
                    data: counts,
                    backgroundColor: [
                        '#ef4444', // Critical
                        '#f97316', // High
                        '#eab308', // Medium
                        '#22c55e'  // Low
                    ],
                    borderColor: '#0d1220',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: { color: '#e2e8f0', font: { family: 'Outfit' } }
                    }
                },
                cutout: '55%'
            }
        });
    }

    function renderTimelineChart(timeline) {
        const ctx = document.getElementById('chart-timeline').getContext('2d');
        
        if (chartTimeline) chartTimeline.destroy();

        if (timeline.length === 0) {
            return;
        }

        const labels = timeline.map(t => t.year);
        const counts = timeline.map(t => t.count);

        chartTimeline = new Chart(ctx, {
            type: 'line',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Breaches Detected',
                    data: counts,
                    fill: true,
                    backgroundColor: 'rgba(59, 130, 246, 0.15)',
                    borderColor: '#3b82f6',
                    borderWidth: 2,
                    tension: 0.3,
                    pointBackgroundColor: '#ef4444',
                    pointBorderColor: '#0d1220',
                    pointHoverRadius: 7,
                    pointRadius: 5
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { display: false },
                        ticks: { color: '#94a3b8' }
                    },
                    y: {
                        grid: { color: 'rgba(255, 255, 255, 0.05)' },
                        ticks: { color: '#94a3b8', precision: 0 }
                    }
                }
            }
        });
    }

    let rawInventoryData = [];

    function renderInventoryTable(inventory) {
        rawInventoryData = inventory;
        filterAndRenderTable();
    }

    function filterAndRenderTable() {
        const tbody = document.getElementById('inventory-tbody');
        const query = document.getElementById('log-search').value.toLowerCase().trim();
        tbody.innerHTML = '';

        const filtered = rawInventoryData.filter(item => {
            return item.email.toLowerCase().includes(query) || 
                   item.source_name.toLowerCase().includes(query) ||
                   item.exposed_data.toLowerCase().includes(query) ||
                   item.risk_level.toLowerCase().includes(query);
        });

        if (filtered.length === 0) {
            tbody.innerHTML = `<tr><td colspan="6" class="center-text text-gray">No matching incidents found.</td></tr>`;
            return;
        }

        filtered.forEach(row => {
            const tr = document.createElement('tr');
            let riskClass = 'risk-badge ';
            switch (row.risk_level) {
                case 'Critical': riskClass += 'risk-critical'; break;
                case 'High': riskClass += 'risk-high'; break;
                case 'Medium': riskClass += 'risk-medium'; break;
                case 'Low': riskClass += 'risk-low'; break;
                default: riskClass += 'risk-safe';
            }

            // Expose split list tags
            const dataTags = row.exposed_data.split(',').map(d => `<span class="data-tag">${d.trim()}</span>`).join(' ');

            tr.innerHTML = `
                <td><strong>${row.email}</strong></td>
                <td><code>${row.source_name}</code></td>
                <td>${row.breach_date}</td>
                <td><div class="breach-types">${dataTags}</div></td>
                <td>${row.date_detected}</td>
                <td><span class="${riskClass}">${row.risk_level}</span></td>
            `;
            tbody.appendChild(tr);
        });
    }

    // Connect Search input to filtering
    document.getElementById('log-search').addEventListener('keyup', filterAndRenderTable);


    // ==============================
    // TAB 3: CREDENTIAL AUDIT
    // ==============================
    const auditPasswordInput = document.getElementById('audit-password');
    const btnTogglePassword = document.getElementById('btn-toggle-password');
    const strengthBox = document.getElementById('password-strength-box');
    const passwordRating = document.getElementById('password-rating');
    const passwordStrengthBar = document.getElementById('password-strength-bar');
    const passwordEntropy = document.getElementById('password-entropy');
    const passwordSuggestions = document.getElementById('password-suggestions');
    const auditResults = document.getElementById('password-audit-results');
    const hibpScannerStatus = document.getElementById('hibp-scanner-status');

    // Toggle Password Visibility
    btnTogglePassword.addEventListener('click', () => {
        const type = auditPasswordInput.getAttribute('type') === 'password' ? 'text' : 'password';
        auditPasswordInput.setAttribute('type', type);
        btnTogglePassword.textContent = type === 'password' ? '👁️' : '🔒';
    });

    // Real-time strength analyzer
    auditPasswordInput.addEventListener('input', async () => {
        const val = auditPasswordInput.value;
        if (!val) {
            strengthBox.classList.add('hidden');
            auditResults.classList.add('hidden');
            return;
        }

        strengthBox.classList.remove('hidden');

        try {
            // 1. Calculate entropy and strength rating from backend
            const res = await fetch('/api/password/strength', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ password: val })
            });
            const data = await res.json();

            // Render strength UI
            passwordRating.textContent = data.rating;
            passwordRating.style.color = data.color;
            passwordEntropy.textContent = data.entropy.toFixed(2);
            
            // Set Progressbar
            const percentage = Math.min(100, (data.entropy / 90) * 100);
            passwordStrengthBar.style.width = `${percentage}%`;
            passwordStrengthBar.style.backgroundColor = data.color;

            // Render suggestion guidelines
            if (data.feedback && data.feedback.length > 0) {
                passwordSuggestions.classList.remove('hidden');
                passwordSuggestions.innerHTML = `
                    <p>Suggestions to strengthen this credential:</p>
                    <ul>
                        ${data.feedback.map(f => `<li>${f}</li>`).join('')}
                    </ul>
                `;
            } else {
                passwordSuggestions.classList.add('hidden');
                passwordSuggestions.innerHTML = '';
            }

            // 2. Execute secure HIBP checking (k-Anonymity)
            auditResults.classList.remove('hidden');
            hibpScannerStatus.innerHTML = `
                <div class="status-indicator">
                    <span class="status-dot warning spinning"></span>
                    <span>Auditing global breach caches cryptographically...</span>
                </div>
            `;
            
            runSecureHIBPCheck(val);

        } catch (err) {
            console.error("Password check failure:", err);
        }
    });

    // k-Anonymity checker client-side
    async function runSecureHIBPCheck(password) {
        try {
            // Hashing using Subtles Crypto
            const hash = await calculateSHA1(password);
            const prefix = hash.substring(0, 5);
            const suffix = hash.substring(5);

            const res = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`);
            if (res.status !== 200) {
                throw new Error("Could not reach HIBP verification server.");
            }

            const bodyText = await res.text();
            const lines = bodyText.split('\n');
            
            let occurrences = 0;
            for (let line of lines) {
                const parts = line.split(':');
                if (parts[0].trim() === suffix) {
                    occurrences = parseInt(parts[1]);
                    break;
                }
            }

            if (occurrences > 0) {
                hibpScannerStatus.innerHTML = `
                    <div class="hibp-alert danger">
                        <h5>⚠️ Compromise Warning!</h5>
                        This password has been identified <strong>${occurrences.toLocaleString()}</strong> times in public data breaches. 
                        Using this credential puts you at extreme risk of <strong>Credential Stuffing attacks</strong>. Do not use this password on any account!
                    </div>
                `;
            } else {
                hibpScannerStatus.innerHTML = `
                    <div class="hibp-alert success">
                        <h5>✅ Zero Leak Detections</h5>
                        This password was not found in known exposed breaches indexed by HaveIBeenPwned.
                    </div>
                `;
            }
        } catch (err) {
            console.error("HIBP connection error:", err);
            hibpScannerStatus.innerHTML = `
                <div class="status-indicator text-orange">
                    ⚠️ HIBP API connection interrupted. Run locally or check network connectivity.
                </div>
            `;
        }
    }

    async function calculateSHA1(str) {
        const buffer = new TextEncoder().encode(str);
        const hashBuffer = await crypto.subtle.digest('SHA-1', buffer);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
    }

    // ==============================
    // TAB 4: SHIELD CONFIGURATION
    // ==============================
    
    // Save SMTP configurations
    const btnSaveSettings = document.getElementById('btn-save-settings');
    btnSaveSettings.addEventListener('click', async () => {
        const host = document.getElementById('settings-smtp-host').value.trim();
        const port = parseInt(document.getElementById('settings-smtp-port').value.trim());

        if (!host || !port) {
            alert("Please input SMTP Host and Port.");
            return;
        }

        try {
            const res = await fetch('/api/settings/update', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ smtp_host: host, smtp_port: port })
            });
            const data = await res.json();
            if (data.status === 'success') {
                alert("Outbound gateway details updated.");
                fetchSystemStatus();
            }
        } catch (err) {
            console.error("Save settings error:", err);
        }
    });

    // Send SMTP verification test email
    const btnSendTestMail = document.getElementById('btn-send-test-mail');
    const smtpTestFeedback = document.getElementById('smtp-test-feedback');

    btnSendTestMail.addEventListener('click', async () => {
        const recipient = document.getElementById('test-email-recipient').value.trim();
        if (!recipient) {
            alert("Recipient email is required for testing.");
            return;
        }

        smtpTestFeedback.className = 'smtp-feedback';
        smtpTestFeedback.classList.remove('hidden');
        smtpTestFeedback.textContent = 'Transmitting email verification payload...';
        btnSendTestMail.disabled = true;

        try {
            const res = await fetch('/api/settings/send_test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ recipient })
            });
            const data = await res.json();
            
            if (data.status === 'success') {
                smtpTestFeedback.className = 'smtp-feedback success';
                smtpTestFeedback.textContent = 'Test email dispatched successfully! Review your spam/junk folder if missing.';
            } else {
                throw new Error(data.message || 'Verification email transmission failed.');
            }
        } catch (err) {
            console.error("SMTP test fail:", err);
            smtpTestFeedback.className = 'smtp-feedback error';
            smtpTestFeedback.textContent = err.message;
        } finally {
            btnSendTestMail.disabled = false;
        }
    });

    // Toggle Gemini Threats Switch
    const toggleGemini = document.getElementById('toggle-gemini');
    toggleGemini.addEventListener('change', async () => {
        try {
            const res = await fetch('/api/settings/update', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ gemini_enabled: toggleGemini.checked })
            });
            const data = await res.json();
            if (data.status === 'success') {
                fetchSystemStatus();
            }
        } catch (err) {
            console.error("Toggle Gemini fail:", err);
        }
    });

    // Sandbox Operations: Populate
    const btnSandboxPopulate = document.getElementById('btn-sandbox-populate');
    const sandboxFeedback = document.getElementById('sandbox-feedback');

    btnSandboxPopulate.addEventListener('click', async () => {
        sandboxFeedback.className = 'smtp-feedback';
        sandboxFeedback.classList.remove('hidden');
        sandboxFeedback.textContent = 'Inserting developer sandbox assets...';
        btnSandboxPopulate.disabled = true;

        try {
            const res = await fetch('/api/sandbox/populate', { method: 'POST' });
            const data = await res.json();
            if (data.status === 'success') {
                sandboxFeedback.className = 'smtp-feedback success';
                sandboxFeedback.textContent = data.message;
                // Reload
                loadMonitoredAssets();
                fetchSystemStatus();
            } else {
                throw new Error(data.message);
            }
        } catch (err) {
            console.error("Sandbox Populate error:", err);
            sandboxFeedback.className = 'smtp-feedback error';
            sandboxFeedback.textContent = err.message;
        } finally {
            btnSandboxPopulate.disabled = false;
        }
    });

    // Sandbox Operations: Flush
    const btnSandboxReset = document.getElementById('btn-sandbox-reset');
    btnSandboxReset.addEventListener('click', async () => {
        if (!confirm("Flush all monitored addresses and registered logs? This flushes SQLite databases.")) {
            return;
        }

        sandboxFeedback.className = 'smtp-feedback';
        sandboxFeedback.classList.remove('hidden');
        sandboxFeedback.textContent = 'Clearing SQL data indexes...';
        btnSandboxReset.disabled = true;

        try {
            const res = await fetch('/api/sandbox/reset', { method: 'POST' });
            const data = await res.json();
            if (data.status === 'success') {
                sandboxFeedback.className = 'smtp-feedback success';
                sandboxFeedback.textContent = data.message;
                // Reload
                loadMonitoredAssets();
                fetchSystemStatus();
            } else {
                throw new Error(data.message);
            }
        } catch (err) {
            console.error("Sandbox Reset error:", err);
            sandboxFeedback.className = 'smtp-feedback error';
            sandboxFeedback.textContent = err.message;
        } finally {
            btnSandboxReset.disabled = false;
        }
    });


    // ==============================
    // PAGE BOOTSTRAP
    // ==============================
    fetchSystemStatus();
    loadMonitoredAssets();
});
