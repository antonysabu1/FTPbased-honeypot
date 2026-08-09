document.addEventListener("DOMContentLoaded", () => {
    let refreshCountdown = 5;
    let timerId = null;
    let activeTab = "tab-sessions";
    let cachedPayloadData = null;

    // Elements
    const refreshCounterEl = document.getElementById("refresh-counter");
    const syncIconEl = document.getElementById("sync-icon");
    const manualRefreshBtn = document.getElementById("btn-manual-refresh");
    const tableSearchInput = document.getElementById("table-search");

    // Modal Elements
    const fileModal = document.getElementById("file-modal");
    const modalCloseBtn = document.getElementById("modal-close-btn");
    const modalFilename = document.getElementById("modal-filename");
    const modalHash = document.getElementById("modal-hash");
    const modalSize = document.getElementById("modal-size");
    const modalIp = document.getElementById("modal-ip");
    const modalTime = document.getElementById("modal-time");
    const modalContentCode = document.getElementById("modal-content-code");
    const btnViewText = document.getElementById("btn-view-text");
    const btnViewHex = document.getElementById("btn-view-hex");
    const modalDownloadLink = document.getElementById("modal-download-link");

    // Tab Switching
    document.querySelectorAll(".tab-btn").forEach(btn => {
        btn.addEventListener("click", () => {
            document.querySelectorAll(".tab-btn").forEach(b => b.classList.remove("active"));
            document.querySelectorAll(".tab-panel").forEach(p => p.classList.remove("active"));

            btn.classList.add("active");
            activeTab = btn.getAttribute("data-tab");
            const panel = document.getElementById(activeTab);
            if (panel) panel.classList.add("active");
            
            filterCurrentTable();
        });
    });

    // Auto Refresh Loop
    function startAutoRefresh() {
        if (timerId) clearInterval(timerId);
        refreshCountdown = 5;
        refreshCounterEl.textContent = `${refreshCountdown}s`;

        timerId = setInterval(() => {
            refreshCountdown--;
            if (refreshCountdown <= 0) {
                refreshCountdown = 5;
                loadDashboardData();
            }
            refreshCounterEl.textContent = `${refreshCountdown}s`;
        }, 1000);
    }

    manualRefreshBtn.addEventListener("click", () => {
        syncIconEl.classList.add("fa-spin");
        loadDashboardData().then(() => {
            setTimeout(() => syncIconEl.classList.remove("fa-spin"), 500);
        });
        refreshCountdown = 5;
    });

    // Fetch and Populate All Data
    async function loadDashboardData() {
        try {
            await Promise.all([
                fetchStats(),
                fetchSessions(),
                fetchAuthAttempts(),
                fetchCommands(),
                fetchQuarantineFiles()
            ]);
            filterCurrentTable();
        } catch (err) {
            console.error("Dashboard fetch error:", err);
        }
    }

    async function fetchStats() {
        const res = await fetch("/api/stats");
        const data = await res.json();
        document.getElementById("stat-total-sessions").textContent = data.total_sessions || 0;
        document.getElementById("stat-active-sessions").textContent = data.active_sessions || 0;
        document.getElementById("stat-auth-attempts").textContent = data.total_auth_attempts || 0;
        document.getElementById("stat-total-commands").textContent = data.total_commands || 0;
        document.getElementById("stat-total-uploads").textContent = data.total_uploads || 0;
    }

    async function fetchSessions() {
        const res = await fetch("/api/sessions?limit=50");
        const data = await res.json();
        const tbody = document.querySelector("#table-sessions tbody");
        
        if (!data || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="7" class="loading-cell">No active or past sessions logged yet.</td></tr>';
            return;
        }

        tbody.innerHTML = data.map(s => `
            <tr>
                <td><span class="badge-status ${s.status === 'ACTIVE' ? 'badge-active' : 'badge-closed'}">${s.status}</span></td>
                <td><span class="code-span">${s.session_id.substring(0, 8)}...</span></td>
                <td><strong>${escapeHtml(s.client_ip)}</strong></td>
                <td>${s.client_port}</td>
                <td><span class="badge-status badge-failed">${s.failed_attempts}</span></td>
                <td>${s.authenticated_user ? `<span class="code-span">${escapeHtml(s.authenticated_user)}</span>` : '<span class="text-dim">Unauthenticated</span>'}</td>
                <td>${formatDate(s.start_time)}</td>
            </tr>
        `).join("");
    }

    async function fetchAuthAttempts() {
        const res = await fetch("/api/auth_attempts?limit=100");
        const data = await res.json();
        const tbody = document.querySelector("#table-auth tbody");

        if (!data || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="loading-cell">No login attempts recorded yet.</td></tr>';
            return;
        }

        tbody.innerHTML = data.map(a => `
            <tr>
                <td><span class="badge-status ${a.success ? 'badge-success' : 'badge-failed'}">${a.success ? 'ACCEPTED' : 'REJECTED'}</span></td>
                <td>#${a.attempt_number}</td>
                <td><strong>${escapeHtml(a.client_ip)}</strong></td>
                <td><span class="code-span">${escapeHtml(a.username)}</span></td>
                <td><span class="code-span">${escapeHtml(a.password)}</span></td>
                <td>${formatDate(a.timestamp)}</td>
            </tr>
        `).join("");
    }

    async function fetchCommands() {
        const res = await fetch("/api/commands?limit=100");
        const data = await res.json();
        const tbody = document.querySelector("#table-commands tbody");

        if (!data || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" class="loading-cell">No command interactions recorded yet.</td></tr>';
            return;
        }

        tbody.innerHTML = data.map(c => `
            <tr>
                <td><strong>${escapeHtml(c.client_ip)}</strong></td>
                <td><span class="code-span" style="color: var(--accent-blue);">${escapeHtml(c.command)}</span></td>
                <td><span class="code-span">${escapeHtml(c.arguments || '')}</span></td>
                <td><span class="badge-status ${c.response_code < 400 ? 'badge-success' : 'badge-failed'}">${c.response_code || 200}</span></td>
                <td>${formatDate(c.timestamp)}</td>
            </tr>
        `).join("");
    }

    async function fetchQuarantineFiles() {
        const res = await fetch("/api/quarantine?limit=50");
        const data = await res.json();
        const tbody = document.querySelector("#table-quarantine tbody");

        if (!data || data.length === 0) {
            tbody.innerHTML = '<tr><td colspan="6" class="loading-cell">No uploaded payload files captured yet.</td></tr>';
            return;
        }

        tbody.innerHTML = data.map(f => `
            <tr>
                <td><strong><i class="fa-solid fa-file-code"></i> ${escapeHtml(f.original_filename)}</strong></td>
                <td><strong>${escapeHtml(f.client_ip)}</strong></td>
                <td>${f.file_size} B</td>
                <td><span class="code-span">${f.sha256_hash.substring(0, 12)}...</span></td>
                <td>${formatDate(f.upload_timestamp)}</td>
                <td>
                    <button class="btn-inspect" data-id="${f.id}">
                        <i class="fa-solid fa-eye"></i> Inspect Payload
                    </button>
                </td>
            </tr>
        `).join("");

        // Attach click handlers to inspect buttons
        document.querySelectorAll(".btn-inspect").forEach(btn => {
            btn.addEventListener("click", () => inspectPayload(btn.getAttribute("data-id")));
        });
    }

    // Modal Payload Inspector
    async function inspectPayload(fileId) {
        try {
            const res = await fetch(`/api/quarantine/preview/${fileId}`);
            const data = await res.json();
            
            if (data.error) {
                alert(`Error: ${data.error}`);
                return;
            }

            cachedPayloadData = data;
            const meta = data.metadata;

            modalFilename.textContent = meta.original_filename;
            modalHash.textContent = meta.sha256_hash;
            modalSize.textContent = meta.file_size;
            modalIp.textContent = meta.client_ip;
            modalTime.textContent = formatDate(meta.upload_timestamp);
            modalDownloadLink.href = `/api/quarantine/download/${fileId}`;

            // Show Text view by default
            btnViewText.classList.add("active");
            btnViewHex.classList.remove("active");
            
            if (data.is_text && data.text_preview) {
                modalContentCode.textContent = data.text_preview;
            } else {
                modalContentCode.textContent = "[Binary Data / Non-UTF8 File - Switch to Hex Dump View]\n\n" + data.hex_preview;
            }

            fileModal.classList.add("active");
        } catch (err) {
            console.error("Payload inspect error:", err);
        }
    }

    btnViewText.addEventListener("click", () => {
        btnViewText.classList.add("active");
        btnViewHex.classList.remove("active");
        if (cachedPayloadData) {
            modalContentCode.textContent = cachedPayloadData.is_text && cachedPayloadData.text_preview 
                ? cachedPayloadData.text_preview 
                : "[Binary Data]\n" + cachedPayloadData.hex_preview;
        }
    });

    btnViewHex.addEventListener("click", () => {
        btnViewHex.classList.add("active");
        btnViewText.classList.remove("active");
        if (cachedPayloadData) {
            modalContentCode.textContent = cachedPayloadData.hex_preview;
        }
    });

    modalCloseBtn.addEventListener("click", () => fileModal.classList.remove("active"));
    fileModal.addEventListener("click", (e) => {
        if (e.target === fileModal) fileModal.classList.remove("active");
    });

    // Client-side Search / Filtering
    tableSearchInput.addEventListener("input", filterCurrentTable);

    function filterCurrentTable() {
        const query = tableSearchInput.value.toLowerCase().trim();
        const activePanel = document.getElementById(activeTab);
        if (!activePanel) return;

        const rows = activePanel.querySelectorAll("tbody tr");
        rows.forEach(row => {
            if (row.querySelector(".loading-cell")) return;
            const text = row.textContent.toLowerCase();
            row.style.display = text.includes(query) ? "" : "none";
        });
    }

    // Helper functions
    function formatDate(isoStr) {
        if (!isoStr) return "-";
        try {
            const d = new Date(isoStr);
            return d.toISOString().replace("T", " ").substring(0, 19);
        } catch {
            return isoStr;
        }
    }

    function escapeHtml(str) {
        if (!str) return "";
        return String(str)
            .replace(/&/g, "&amp;")
            .replace(/</g, "&lt;")
            .replace(/>/g, "&gt;")
            .replace(/"/g, "&quot;")
            .replace(/'/g, "&#039;");
    }

    // Initial Load & Start Refresh
    loadDashboardData();
    startAutoRefresh();
});
