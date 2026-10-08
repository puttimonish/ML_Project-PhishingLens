/* =========================================================
   PhishingLens frontend interactions
   URL analysis + local scan history + interface preferences
========================================================= */

const API_BASE_URL = "https://peripherals-mayor-brooklyn-neither.trycloudflare.com";

const urlInput = document.getElementById("urlInput");
const analyzeButton = document.getElementById("analyzeButton");
const buttonText = document.getElementById("buttonText");
const buttonSpinner = document.getElementById("buttonSpinner");
const errorMessage = document.getElementById("errorMessage");
const resultSection = document.getElementById("resultSection");
const resultUrl = document.getElementById("resultUrl");
const riskLevel = document.getElementById("riskLevel");
const riskScore = document.getElementById("riskScore");
const phishingProbability = document.getElementById("phishingProbability");
const legitimateProbability = document.getElementById("legitimateProbability");
const phishingBar = document.getElementById("phishingBar");
const legitimateBar = document.getElementById("legitimateBar");
const mlScore = document.getElementById("mlScore");
const explanations = document.getElementById("explanations");
const domainIndicators = document.getElementById("domainIndicators");
const securityIndicators = document.getElementById("securityIndicators");
const featureTable = document.getElementById("featureTable");

const HISTORY_KEY = "phishinglens-scan-history-v1";
const SETTINGS_KEY = "phishinglens-preferences-v1";
const MAX_HISTORY_ITEMS = 20;
let currentAnalysis = null;

function showError(message) {
    errorMessage.textContent = message;
    errorMessage.classList.remove("hidden");
}

function hideError() {
    errorMessage.classList.add("hidden");
    errorMessage.textContent = "";
}

function setLoading(isLoading) {
    analyzeButton.disabled = isLoading;
    if (isLoading) {
        buttonText.textContent = "Analyzing...";
        buttonSpinner.classList.remove("hidden");
    } else {
        buttonText.textContent = "Analyze URL";
        buttonSpinner.classList.add("hidden");
    }
}

function formatPercentage(value) {
    const number = Number(value);
    return `${(Number.isFinite(number) ? number : 0).toFixed(2)}%`;
}

function formatValue(value) {
    if (typeof value === "number") {
        return Number.isInteger(value) ? value : Number(value).toFixed(4);
    }
    if (value === null || value === undefined) return "—";
    if (typeof value === "boolean") return value ? "Yes" : "No";
    return String(value);
}

function createIndicator(label, value) {
    const item = document.createElement("div");
    item.className = "indicator";
    const labelElement = document.createElement("span");
    labelElement.className = "indicator-label";
    labelElement.textContent = label;
    const valueElement = document.createElement("span");
    valueElement.className = "indicator-value";
    valueElement.textContent = formatValue(value);
    item.append(labelElement, valueElement);
    return item;
}

function createSecurityIndicator(title, value) {
    const item = document.createElement("div");
    item.className = "security-indicator";
    const strong = document.createElement("strong");
    strong.textContent = title;
    const span = document.createElement("span");
    span.textContent = value;
    item.append(strong, span);
    return item;
}

function renderExplanations(items) {
    explanations.replaceChildren();
    if (!Array.isArray(items) || items.length === 0) {
        const item = document.createElement("div");
        item.className = "explanation-item";
        item.textContent = "No additional explanation was generated.";
        explanations.appendChild(item);
        return;
    }
    items.forEach((text) => {
        const item = document.createElement("div");
        item.className = "explanation-item";
        item.textContent = `• ${text}`;
        explanations.appendChild(item);
    });
}

function renderDomainIndicators(features = {}) {
    domainIndicators.replaceChildren();
    const indicators = [
        ["Registered domain", features.registered_domain || "Unknown"],
        ["Subdomains", features.subdomain_count ?? 0],
        ["Domain entropy", formatValue(features.domain_entropy ?? 0)],
        ["Hostname length", features.hostname_length ?? 0],
        ["Punycode", features.has_punycode ? "Detected" : "Not detected"],
        ["IP address", features.has_ip ? "Detected" : "Not detected"]
    ];
    indicators.forEach(([label, value]) => domainIndicators.appendChild(createIndicator(label, value)));
}

function renderSecurityIndicators(features = {}) {
    securityIndicators.replaceChildren();
    const items = [
        ["HTTPS", features.has_https ? "Present" : "Not present"],
        ["Brand match", features.brand_match ? "Detected" : "None"],
        ["Brand mismatch", features.brand_domain_mismatch ? "Detected" : "None"],
        ["Suspicious keywords", features.suspicious_keyword_count ?? 0],
        ["URL encoding", features.has_encoded_characters ? "Detected" : "None"],
        ["Punycode", features.has_punycode ? "Detected" : "None"],
        ["@ symbol", features.at_count ? "Detected" : "None"],
        ["Deep subdomains", Number(features.subdomain_count ?? 0) >= 3 ? "Detected" : "Normal"]
    ];
    items.forEach(([title, value]) => securityIndicators.appendChild(createSecurityIndicator(title, formatValue(value))));
}

function renderFeatures(features = {}) {
    featureTable.replaceChildren();
    Object.entries(features).forEach(([key, value]) => {
        const row = document.createElement("div");
        row.className = "feature-row";
        const keyElement = document.createElement("span");
        keyElement.textContent = key;
        const valueElement = document.createElement("span");
        valueElement.textContent = formatValue(value);
        row.append(keyElement, valueElement);
        featureTable.appendChild(row);
    });
}

function updateRiskStyle(level) {
    const levelUpper = String(level || "UNKNOWN").toUpperCase();
    riskLevel.style.color = levelUpper === "LOW"
        ? "#35d39a"
        : levelUpper === "SUSPICIOUS"
            ? "#ffca55"
            : "#ff6474";
}

function renderResult(data, options = {}) {
    currentAnalysis = data;
    resultSection.classList.remove("hidden");
    resultUrl.textContent = data.url || "Unknown URL";
    riskLevel.textContent = String(data.risk_level || "UNKNOWN").toUpperCase();
    riskScore.textContent = formatValue(data.risk_score ?? 0);
    updateRiskStyle(data.risk_level);
    phishingProbability.textContent = formatPercentage(data.phishing_probability);
    legitimateProbability.textContent = formatPercentage(data.legitimate_probability);
    mlScore.textContent = Number(data.ml_score ?? 0).toFixed(2);
    phishingBar.style.width = `${Math.max(0, Math.min(100, Number(data.phishing_probability) || 0))}%`;
    legitimateBar.style.width = `${Math.max(0, Math.min(100, Number(data.legitimate_probability) || 0))}%`;
    renderExplanations(data.explanations);
    renderDomainIndicators(data.features || {});
    renderSecurityIndicators(data.features || {});
    renderFeatures(data.features || {});
    ["downloadReportJson", "downloadReportText", "printReportButton"].forEach(id => { const button = document.getElementById(id); if (button) button.disabled = false; });
    if (!options.fromHistory) saveScanToHistory(data);
    if (options.scroll !== false) resultSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

async function analyzeURL() {
    const url = urlInput.value.trim();
    hideError();
    if (!url) {
        showError("Please enter a URL to analyze.");
        urlInput.focus();
        return;
    }

    let parsedURL;
    try {
        parsedURL = new URL(url);
    } catch {
        showError("Enter a complete URL, including https:// or http://.");
        urlInput.focus();
        return;
    }
    if (!['http:', 'https:'].includes(parsedURL.protocol)) {
        showError("Only HTTP and HTTPS URLs can be analyzed.");
        urlInput.focus();
        return;
    }

    setLoading(true);
    try {
        const response = await fetch(`${API_BASE_URL}/api/v1/analyze`, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url })
        });
        let data;
        try { data = await response.json(); }
        catch { throw new Error("The server returned an unreadable response."); }
        if (!response.ok) {
            throw new Error(data.detail || "The server could not analyze this URL.");
        }
        renderResult(data);
    } catch (error) {
        console.error("PhishingLens analysis error:", error);
        showError(error.message || "Unable to connect to the PhishingLens API. Check that the backend is running.");
    } finally {
        setLoading(false);
    }
}

/* ---------------------- Local scan history ---------------------- */
function readHistory() {
    try {
        const parsed = JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
        return Array.isArray(parsed) ? parsed : [];
    } catch {
        return [];
    }
}

function writeHistory(items) {
    try {
        localStorage.setItem(HISTORY_KEY, JSON.stringify(items.slice(0, MAX_HISTORY_ITEMS)));
        return true;
    } catch (error) {
        console.warn("Could not save PhishingLens history:", error);
        return false;
    }
}

function saveScanToHistory(data) {
    const item = {
        id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
        url: String(data.url || ""),
        risk_level: String(data.risk_level || "UNKNOWN"),
        risk_score: Number(data.risk_score) || 0,
        phishing_probability: Number(data.phishing_probability) || 0,
        legitimate_probability: Number(data.legitimate_probability) || 0,
        scanned_at: new Date().toISOString()
    };
    const items = readHistory().filter((entry) => entry.url !== item.url);
    items.unshift(item);
    writeHistory(items);
    renderHistory();
}

function renderHistory() {
    const list = document.getElementById("historyList");
    const count = document.getElementById("historyCount");
    if (!list || !count) return;
    const items = readHistory();
    count.textContent = `${items.length} saved scan${items.length === 1 ? "" : "s"}`;
    list.replaceChildren();
    if (items.length === 0) {
        const empty = document.createElement("div");
        empty.className = "history-empty";
        empty.textContent = "Your analyzed URLs will appear here after your first scan.";
        list.appendChild(empty);
        return;
    }
    items.forEach((entry) => {
        const card = document.createElement("article");
        card.className = "history-item";
        const main = document.createElement("div");
        main.className = "history-item-main";
        const url = document.createElement("div");
        url.className = "history-item-url";
        url.textContent = entry.url;
        const meta = document.createElement("div");
        meta.className = "history-item-meta";
        const score = document.createElement("span");
        score.textContent = `Risk score: ${entry.risk_score}/100`;
        const probability = document.createElement("span");
        probability.textContent = `Phishing probability: ${Number(entry.phishing_probability).toFixed(2)}%`;
        const time = document.createElement("span");
        const date = new Date(entry.scanned_at);
        time.textContent = Number.isNaN(date.getTime()) ? "Previously scanned" : date.toLocaleString();
        meta.append(score, probability, time);
        main.append(url, meta);
        const verdict = document.createElement("span");
        verdict.className = "history-verdict";
        verdict.textContent = String(entry.risk_level || "UNKNOWN").toUpperCase();
        verdict.style.color = String(entry.risk_level).toUpperCase() === "LOW" ? "#35d39a" : String(entry.risk_level).toUpperCase() === "SUSPICIOUS" ? "#ffca55" : "#ff6474";
        const openButton = document.createElement("button");
        openButton.className = "history-open";
        openButton.type = "button";
        openButton.textContent = "Analyze again";
        openButton.addEventListener("click", () => {
            urlInput.value = entry.url;
            document.getElementById("analyze").scrollIntoView({ behavior: "smooth", block: "start" });
            urlInput.focus({ preventScroll: true });
        });
        card.append(main, verdict, openButton);
        list.appendChild(card);
    });
}

const clearHistoryButton = document.getElementById("clearHistoryButton");
if (clearHistoryButton) {
    clearHistoryButton.addEventListener("click", () => {
        const items = readHistory();
        if (items.length === 0) return;
        if (window.confirm("Clear all scan history saved in this browser?")) {
            localStorage.removeItem(HISTORY_KEY);
            renderHistory();
        }
    });
}

/* ---------------------- Preferences and theme ---------------------- */
function readSettings() {
    const defaults = { theme: "dark", compact: false, motion: true };
    try {
        return { ...defaults, ...(JSON.parse(localStorage.getItem(SETTINGS_KEY) || "{}")) };
    } catch {
        return defaults;
    }
}

function saveSettings(settings) {
    try { localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings)); }
    catch (error) { console.warn("Could not save preferences:", error); }
}

function applyTheme(theme) {
    const resolved = theme === "system"
        ? (window.matchMedia && window.matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark")
        : theme;
    document.body.dataset.theme = resolved;
    const icon = document.getElementById("themeIcon");
    const toggle = document.getElementById("themeToggle");
    if (icon) icon.textContent = resolved === "dark" ? "☀" : "☾";
    if (toggle) {
        toggle.setAttribute("aria-label", resolved === "dark" ? "Switch to light theme" : "Switch to dark theme");
        toggle.title = resolved === "dark" ? "Switch to light theme" : "Switch to dark theme";
    }
}

function applySettings() {
    const settings = readSettings();
    applyTheme(settings.theme);
    document.body.classList.toggle("compact-layout", Boolean(settings.compact));
    document.body.classList.toggle("reduce-motion", !settings.motion);
    const themeSelect = document.getElementById("themeSelect");
    const compactToggle = document.getElementById("compactToggle");
    const motionToggle = document.getElementById("motionToggle");
    if (themeSelect) themeSelect.value = settings.theme;
    if (compactToggle) compactToggle.checked = Boolean(settings.compact);
    if (motionToggle) motionToggle.checked = Boolean(settings.motion);
}

const themeToggle = document.getElementById("themeToggle");
if (themeToggle) {
    themeToggle.addEventListener("click", () => {
        const settings = readSettings();
        settings.theme = document.body.dataset.theme === "dark" ? "light" : "dark";
        saveSettings(settings);
        applySettings();
    });
}

const toolsToggle = document.getElementById("toolsToggle");
const toolsMenu = document.getElementById("toolsMenu");
if (toolsToggle && toolsMenu) {
    toolsToggle.addEventListener("click", () => {
        const willOpen = toolsMenu.classList.contains("hidden");
        toolsMenu.classList.toggle("hidden", !willOpen);
        toolsToggle.setAttribute("aria-expanded", String(willOpen));
    });
    toolsMenu.querySelectorAll("a").forEach((link) => link.addEventListener("click", () => {
        toolsMenu.classList.add("hidden");
        toolsToggle.setAttribute("aria-expanded", "false");
    }));
    document.addEventListener("click", (event) => {
        if (!toolsMenu.contains(event.target) && !toolsToggle.contains(event.target)) {
            toolsMenu.classList.add("hidden");
            toolsToggle.setAttribute("aria-expanded", "false");
        }
    });
}

const settingsModal = document.getElementById("settingsModal");
const openSettings = document.getElementById("openSettings");
const closeSettings = document.getElementById("closeSettings");
function showSettings() {
    if (!settingsModal) return;
    applySettings();
    settingsModal.classList.remove("hidden");
    if (closeSettings) closeSettings.focus();
}
function hideSettings() {
    if (settingsModal) settingsModal.classList.add("hidden");
    if (openSettings) openSettings.focus();
}
if (openSettings) openSettings.addEventListener("click", () => {
    if (toolsMenu) toolsMenu.classList.add("hidden");
    if (toolsToggle) toolsToggle.setAttribute("aria-expanded", "false");
    showSettings();
});
if (closeSettings) closeSettings.addEventListener("click", hideSettings);
if (settingsModal) {
    settingsModal.addEventListener("click", (event) => { if (event.target === settingsModal) hideSettings(); });
}
document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
        if (settingsModal && !settingsModal.classList.contains("hidden")) hideSettings();
        if (toolsMenu) toolsMenu.classList.add("hidden");
        if (toolsToggle) toolsToggle.setAttribute("aria-expanded", "false");
    }
});

const themeSelect = document.getElementById("themeSelect");
const compactToggle = document.getElementById("compactToggle");
const motionToggle = document.getElementById("motionToggle");
if (themeSelect) themeSelect.addEventListener("change", () => {
    const settings = readSettings(); settings.theme = themeSelect.value; saveSettings(settings); applySettings();
});
if (compactToggle) compactToggle.addEventListener("change", () => {
    const settings = readSettings(); settings.compact = compactToggle.checked; saveSettings(settings); applySettings();
});
if (motionToggle) motionToggle.addEventListener("change", () => {
    const settings = readSettings(); settings.motion = motionToggle.checked; saveSettings(settings); applySettings();
});
if (window.matchMedia) {
    window.matchMedia("(prefers-color-scheme: light)").addEventListener?.("change", () => {
        if (readSettings().theme === "system") applySettings();
    });
}

/* ---------------------- Event wiring ---------------------- */
analyzeButton.addEventListener("click", analyzeURL);
urlInput.addEventListener("keydown", (event) => {
    if (event.key === "Enter") analyzeURL();
});

applySettings();
renderHistory();

/* ---------------- URL input utilities ---------------- */
const pasteUrlButton = document.getElementById("pasteUrlButton");
const clearUrlButton = document.getElementById("clearUrlButton");
const copyResultUrlButton = document.getElementById("copyResultUrlButton");

if (pasteUrlButton) {
    pasteUrlButton.addEventListener("click", async () => {
        try {
            if (!navigator.clipboard || !navigator.clipboard.readText) {
                throw new Error("Clipboard access is unavailable. Paste with Ctrl+V instead.");
            }
            const clipboardText = (await navigator.clipboard.readText()).trim();
            if (!clipboardText) throw new Error("Your clipboard is empty.");
            urlInput.value = clipboardText;
            urlInput.focus();
            hideError();
        } catch (error) {
            showError(error.message || "Could not read the clipboard. Paste with Ctrl+V instead.");
        }
    });
}
if (clearUrlButton) {
    clearUrlButton.addEventListener("click", () => {
        urlInput.value = "";
        hideError();
        urlInput.focus();
    });
}
document.querySelectorAll("[data-example-url]").forEach((button) => {
    button.addEventListener("click", () => {
        urlInput.value = button.dataset.exampleUrl || "";
        hideError();
        urlInput.focus();
    });
});
if (copyResultUrlButton) {
    copyResultUrlButton.addEventListener("click", async () => {
        const value = resultUrl ? resultUrl.textContent.trim() : "";
        if (!value) return;
        try {
            await navigator.clipboard.writeText(value);
            copyResultUrlButton.textContent = "Copied!";
            window.setTimeout(() => { copyResultUrlButton.textContent = "Copy URL"; }, 1400);
        } catch {
            showError("Could not access the clipboard. Select the analyzed URL and copy it manually.");
        }
    });
}


/* ===================== Extended security workspace ===================== */
const bulkScanButton = document.getElementById("bulkScanButton");
const bulkUrlsInput = document.getElementById("bulkUrls");
const bulkStatus = document.getElementById("bulkStatus");
const bulkResults = document.getElementById("bulkResults");
const downloadBulkCsv = document.getElementById("downloadBulkCsv");
const compareButton = document.getElementById("compareButton");
const compareResults = document.getElementById("compareResults");
const emailText = document.getElementById("emailText");
const emailLinksResults = document.getElementById("emailLinksResults");
const scanExtractedLinksButton = document.getElementById("scanExtractedLinksButton");
const extractedLinks = [];
let lastBulkResults = [];
const WATCHLIST_KEY = "phishinglens-domain-watchlist-v1";

function normalizeWebUrl(raw) {
    let value = String(raw || "").trim().replace(/[<>"']/g, "");
    if (!value) return null;
    if (!/^https?:\/\//i.test(value)) value = "https://" + value;
    try { const u = new URL(value); return ["http:", "https:"].includes(u.protocol) ? u.href : null; }
    catch { return null; }
}
function uniqueUrls(values) { return [...new Set(values.map(normalizeWebUrl).filter(Boolean))]; }
function extractUrls(text) {
    const matches = String(text || "").match(/(?:https?:\/\/|www\.)[^\s<>"'`]+/gi) || [];
    return uniqueUrls(matches.map(x => x.replace(/[),.;!?\]}]+$/g, "")));
}
async function requestAnalysis(url) {
    const response = await fetch(`${API_BASE_URL}/api/v1/analyze`, {method:"POST", headers:{"Content-Type":"application/json"}, body:JSON.stringify({url})});
    let data = {}; try { data = await response.json(); } catch {}
    if (!response.ok) throw new Error(data.detail || `Analysis failed (${response.status})`);
    return data;
}
function addToolRow(container, label, value) {
    const row = document.createElement("div"); row.className = "tool-result-row";
    const a = document.createElement("span"); a.textContent = label;
    const b = document.createElement("strong"); b.textContent = value == null || value === "" ? "Unknown" : String(value);
    row.append(a,b); container.appendChild(row);
}
function makeDownload(filename, content, type) {
    const blob = new Blob([content], {type}); const url = URL.createObjectURL(blob);
    const a = document.createElement("a"); a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
}
function csvEscape(v) { return '"' + String(v ?? "").replace(/"/g,'""') + '"'; }
function renderBulkResults(rows) {
    bulkResults.replaceChildren();
    rows.forEach(row => {
        const item = document.createElement("div"); item.className = "tool-result-row";
        const left = document.createElement("span"); left.className = "small-url"; left.textContent = row.url;
        const right = document.createElement("strong"); right.className = "mini-risk";
        right.textContent = row.error ? "ERROR" : `${String(row.risk_level || "Unknown").toUpperCase()} · ${Number(row.phishing_probability || 0).toFixed(1)}% phishing`;
        item.append(left,right); bulkResults.appendChild(item);
    });
}
if (bulkScanButton) bulkScanButton.addEventListener("click", async () => {
    const urls = uniqueUrls(bulkUrlsInput.value.split(/[\n,;\t]+/));
    if (!urls.length) { bulkStatus.textContent = "Paste at least one valid HTTP or HTTPS URL."; return; }
    if (urls.length > 50) { bulkStatus.textContent = "Maximum 50 unique URLs per batch. Please split your list."; return; }
    bulkScanButton.disabled = true; downloadBulkCsv.disabled = true; lastBulkResults = []; bulkResults.replaceChildren();
    for (let i=0; i<urls.length; i++) {
        bulkStatus.textContent = `Analyzing ${i+1} of ${urls.length}…`;
        try { const result = await requestAnalysis(urls[i]); lastBulkResults.push(result); saveScanToHistory(result); }
        catch (e) { lastBulkResults.push({url:urls[i],error:e.message}); }
        renderBulkResults(lastBulkResults);
    }
    bulkStatus.textContent = `Finished: ${lastBulkResults.filter(x=>!x.error).length} analyzed, ${lastBulkResults.filter(x=>x.error).length} errors.`;
    downloadBulkCsv.disabled = !lastBulkResults.length; bulkScanButton.disabled = false;
});
if (downloadBulkCsv) downloadBulkCsv.addEventListener("click", () => {
    const rows = [["url","risk_level","risk_score","phishing_probability","legitimate_probability","error"], ...lastBulkResults.map(x=>[x.url,x.risk_level,x.risk_score,x.phishing_probability,x.legitimate_probability,x.error])];
    makeDownload("phishinglens-bulk-scan.csv", rows.map(r=>r.map(csvEscape).join(",")).join("\r\n"), "text/csv;charset=utf-8");
});
if (compareButton) compareButton.addEventListener("click", async () => {
    const a = normalizeWebUrl(document.getElementById("compareUrlA").value), b = normalizeWebUrl(document.getElementById("compareUrlB").value);
    compareResults.replaceChildren();
    if (!a || !b) { addToolRow(compareResults,"Input","Enter two valid HTTP/HTTPS URLs."); return; }
    compareButton.disabled = true; addToolRow(compareResults,"Status","Analyzing both URLs…");
    try {
        const [ra,rb] = await Promise.all([requestAnalysis(a),requestAnalysis(b)]); compareResults.replaceChildren();
        [ ["First URL",ra], ["Second URL",rb] ].forEach(([label,r]) => {
            addToolRow(compareResults,label,r.url); addToolRow(compareResults,`${label} risk`,`${String(r.risk_level||"Unknown").toUpperCase()} · ${r.risk_score}/100`);
            addToolRow(compareResults,`${label} phishing probability`,`${Number(r.phishing_probability||0).toFixed(2)}%`);
            addToolRow(compareResults,`${label} legitimate probability`,`${Number(r.legitimate_probability||0).toFixed(2)}%`);
        });
    } catch(e) { compareResults.replaceChildren(); addToolRow(compareResults,"Error",e.message); }
    finally { compareButton.disabled = false; }
});
function showExtractedLinks(urls, statusNode, container) {
    extractedLinks.splice(0, extractedLinks.length, ...urls); container.replaceChildren();
    if (!urls.length) { statusNode.textContent = "No valid HTTP/HTTPS links found."; scanExtractedLinksButton.disabled = true; return; }
    statusNode.textContent = `Found ${urls.length} unique link(s).`; scanExtractedLinksButton.disabled = false;
    urls.forEach(url => { const row = document.createElement("div"); row.className="tool-result-row"; const span=document.createElement("span"); span.className="small-url"; span.textContent=url; const button=document.createElement("button"); button.type="button"; button.className="secondary-button"; button.textContent="Use URL"; button.addEventListener("click",()=>{urlInput.value=url;urlInput.focus();document.getElementById("analyze").scrollIntoView({behavior:"smooth"});}); row.append(span,button); container.appendChild(row); });
}
if (document.getElementById("extractEmailLinksButton")) document.getElementById("extractEmailLinksButton").addEventListener("click",()=>showExtractedLinks(extractUrls(emailText.value),document.getElementById("fileExtractStatus"),emailLinksResults));
if (document.getElementById("linkFileInput")) document.getElementById("linkFileInput").addEventListener("change",async e=>{
    const file=e.target.files?.[0]; if(!file)return; if(file.size>2*1024*1024){document.getElementById("fileExtractStatus").textContent="File is too large (maximum 2 MB).";return;}
    try { const text=await file.text(); emailText.value=text; showExtractedLinks(extractUrls(text),document.getElementById("fileExtractStatus"),emailLinksResults); }
    catch { document.getElementById("fileExtractStatus").textContent="Could not read this file."; }
});
if (scanExtractedLinksButton) scanExtractedLinksButton.addEventListener("click",()=>{bulkUrlsInput.value=extractedLinks.join("\n");document.getElementById("bulkScanButton").click();document.getElementById("bulkScanButton").scrollIntoView({behavior:"smooth",block:"center"});});
const qrImageInput=document.getElementById("qrImageInput"), readQrButton=document.getElementById("readQrButton");

async function decodeQrWithBackend(file) {
    const formData = new FormData();
    formData.append("image", file, file.name || "qr-image");
    const response = await fetch(`${API_BASE_URL}/api/v1/qr-decode`, {
        method: "POST",
        body: formData
    });
    let data = {};
    try { data = await response.json(); } catch {}
    if (!response.ok) {
        throw new Error(data.detail || `QR backend unavailable (${response.status}).`);
    }
    return data.content || "";
}

if (readQrButton) readQrButton.addEventListener("click",async()=>{
    const file=qrImageInput.files?.[0], status=document.getElementById("qrStatus"), out=document.getElementById("qrExtractedUrl"), use=document.getElementById("useQrUrlButton");
    if(!file){status.textContent="Choose a QR code image first.";return;}

    readQrButton.disabled = true;
    use.disabled = true;
    status.textContent = "Reading QR image…";

    try {
        let value = "";

        // Use native browser decoding when available.
        if ("BarcodeDetector" in window) {
            try {
                const detector=new BarcodeDetector({formats:["qr_code"]});
                const bitmap=await createImageBitmap(file);
                const codes=await detector.detect(bitmap);
                bitmap.close?.();
                value=codes.find(x=>x.rawValue)?.rawValue || "";
            } catch (nativeError) {
                console.warn("Native QR decoding failed; trying backend fallback.", nativeError);
            }
        }

        // Server-side OpenCV fallback for browsers without BarcodeDetector
        // or when native decoding fails.
        if (!value) {
            value = await decodeQrWithBackend(file);
        }

        if(!value) throw new Error("No QR code was detected in this image.");

        out.value=value;
        use.disabled=!normalizeWebUrl(value);
        status.textContent="QR content extracted. Verify the destination before opening it.";
    } catch(e) {
        status.textContent=e.message || "Could not decode this image.";
    } finally {
        readQrButton.disabled = false;
    }
});
if(document.getElementById("useQrUrlButton")) document.getElementById("useQrUrlButton").addEventListener("click",()=>{const value=normalizeWebUrl(document.getElementById("qrExtractedUrl").value);if(!value)return;urlInput.value=value;document.getElementById("analyze").scrollIntoView({behavior:"smooth"});urlInput.focus();});
async function inspectDomain(url) {
    const response=await fetch(`${API_BASE_URL}/api/v1/intelligence`,{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({url})});
    let data={};try{data=await response.json();}catch{}
    if(!response.ok)throw new Error(data.detail||`Live intelligence endpoint unavailable (${response.status}).`);return data;
}
if(document.getElementById("domainIntelButton")) document.getElementById("domainIntelButton").addEventListener("click",async()=>{
    const url=normalizeWebUrl(document.getElementById("intelligenceUrl").value)||normalizeWebUrl(urlInput.value), status=document.getElementById("domainIntelStatus"), grid=document.getElementById("domainIntelResults"), btn=document.getElementById("domainIntelButton");
    grid.replaceChildren(); if(!url){status.textContent="Enter a valid URL or scan one above first.";return;} btn.disabled=true;status.textContent="Checking registration, DNS and TLS…";
    try { const data=await inspectDomain(url); const values=data.checks||data; Object.entries(values).forEach(([key,val])=>{if(typeof val==="object"&&val!==null){const item=document.createElement("div");item.className="intel-result-item";const title=document.createElement("span");title.textContent=key.replace(/_/g," ");const body=document.createElement("strong");body.textContent=JSON.stringify(val);item.append(title,body);grid.appendChild(item);}else{const item=document.createElement("div");item.className="intel-result-item";const title=document.createElement("span");title.textContent=key.replace(/_/g," ");const body=document.createElement("strong");body.textContent=String(val);item.append(title,body);grid.appendChild(item);}});status.textContent=`Live check completed · ${data.checked_at||new Date().toLocaleString()}`; }
    catch(e){status.textContent=e.message.includes("Failed to fetch")?"Live domain intelligence is not connected yet. Follow BACKEND_INTEGRATION.md in the ZIP, restart FastAPI, and try again.":e.message;}
    finally{btn.disabled=false;}
});
if(document.getElementById("downloadReportJson")) document.getElementById("downloadReportJson").addEventListener("click",()=>{if(currentAnalysis)makeDownload("phishinglens-report.json",JSON.stringify({generated_at:new Date().toISOString(),analysis:currentAnalysis,notice:"Model estimates are not proof of safety or maliciousness. Live checks are separate."},null,2),"application/json");});
if(document.getElementById("downloadReportText")) document.getElementById("downloadReportText").addEventListener("click",()=>{if(currentAnalysis){const d=currentAnalysis;makeDownload("phishinglens-report.txt",[`PHISHINGLENS URL SECURITY REPORT`,`Generated: ${new Date().toLocaleString()}`,`URL: ${d.url}`,`Risk level: ${d.risk_level}`,`Risk score: ${d.risk_score}/100`,`Phishing probability: ${d.phishing_probability}%`,`Legitimate probability: ${d.legitimate_probability}%`,``,`Explanations:`,...(d.explanations||[]).map(x=>`- ${typeof x==="string"?x:JSON.stringify(x)}`),``,`Note: Probabilities are model estimates. HTTPS or a low score does not guarantee safety.`].join("\n"),"text/plain;charset=utf-8");}});
function getWatchlist(){try{return JSON.parse(localStorage.getItem(WATCHLIST_KEY)||"[]");}catch{return[];}}
function saveWatchlist(items){try{localStorage.setItem(WATCHLIST_KEY,JSON.stringify(items));}catch{}}
function renderWatchlist(){const box=document.getElementById("watchlistItems");if(!box)return;box.replaceChildren();const items=getWatchlist();if(!items.length){const p=document.createElement("p");p.className="tool-status";p.textContent="No saved URLs yet.";box.appendChild(p);return;}items.forEach((url,index)=>{const row=document.createElement("div");row.className="watchlist-item";const span=document.createElement("span");span.className="watch-url";span.textContent=url;const actions=document.createElement("div");actions.className="watch-actions";const scan=document.createElement("button");scan.type="button";scan.textContent="Recheck";scan.addEventListener("click",async()=>{urlInput.value=url;document.getElementById("analyze").scrollIntoView({behavior:"smooth"});try{await requestAnalysis(url).then(d=>renderResult(d));}catch(e){showError(e.message);}});const remove=document.createElement("button");remove.type="button";remove.textContent="Remove";remove.addEventListener("click",()=>{const next=getWatchlist();next.splice(index,1);saveWatchlist(next);renderWatchlist();});actions.append(scan,remove);row.append(span,actions);box.appendChild(row);});}
if(document.getElementById("addWatchlistButton"))document.getElementById("addWatchlistButton").addEventListener("click",()=>{const url=normalizeWebUrl(document.getElementById("watchlistUrl").value);if(!url){document.getElementById("watchlistUrl").focus();return;}const items=getWatchlist();if(!items.includes(url))items.unshift(url);saveWatchlist(items.slice(0,100));document.getElementById("watchlistUrl").value="";renderWatchlist();});
if(document.getElementById("clearWatchlistButton"))document.getElementById("clearWatchlistButton").addEventListener("click",()=>{if(confirm("Clear the locally saved domain watchlist?")){saveWatchlist([]);renderWatchlist();}});
renderWatchlist();


/* Optional known-breach lookup. Email is sent only after explicit user consent. */
const breachCheckButton = document.getElementById("breachCheckButton");
if (breachCheckButton) breachCheckButton.addEventListener("click", async () => {
    const email = document.getElementById("breachEmail").value.trim();
    const consent = document.getElementById("breachConsent").checked;
    const status = document.getElementById("breachStatus");
    const results = document.getElementById("breachResults");
    results.replaceChildren();
    if (!email) { status.textContent = "Enter an email address first."; return; }
    if (!consent) { status.textContent = "Please tick the consent checkbox before sending the email for a lookup."; return; }
    breachCheckButton.disabled = true; status.textContent = "Checking known breach records…";
    try {
        const response = await fetch(`${API_BASE_URL}/api/v1/breach-check`, {method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({email,consent:true})});
        let data={}; try { data=await response.json(); } catch {}
        if (!response.ok) throw new Error(data.detail || `Breach lookup unavailable (${response.status}).`);
        addToolRow(results,"Result",data.status === "found" ? `${data.breach_count} known breach record(s)` : "No matching records returned");
        (data.breaches || []).forEach(b => addToolRow(results,b.name || "Breach",`${b.breach_date || "Date unknown"} · ${(b.data_classes || []).join(", ") || "Data types unknown"}`));
        status.textContent = data.notice || "Known breach lookup completed. This is not a guarantee of account safety.";
    } catch(e) { status.textContent = e.message.includes("Failed to fetch") ? "Breach-check backend is not connected. See BACKEND_INTEGRATION.md; this also requires a provider API key." : e.message; }
    finally { breachCheckButton.disabled=false; }
});

if (document.getElementById("printReportButton")) document.getElementById("printReportButton").addEventListener("click", () => { if (currentAnalysis) window.print(); });


/* =========================================================
   SIDEBAR WORKSPACE NAVIGATION
   Uses the existing page sections and tool cards; it does not
   duplicate analysis logic or change the default landing page.
========================================================= */
(() => {
    const openButton = document.getElementById("openWorkspace");
    if (!openButton) return;

    const main = document.querySelector("main");
    const header = document.querySelector(".navbar");
    if (!main || !header) return;

    const toolCards = Array.from(document.querySelectorAll("#securityTools .tool-card"));
    const cardPages = ["bulk", "compare", "email", "qr", "domain", "breach", "report"];
    toolCards.forEach((card, index) => card.dataset.workspaceTool = cardPages[index] || "tool");

    const pageInfo = {
        scanner: {title:"URL Scanner", eyebrow:"ANALYSIS WORKSPACE", description:"Run the existing PhishingLens model and review phishing and legitimate probability estimates."},
        history: {title:"Scan History", eyebrow:"LOCAL WORKSPACE", description:"Revisit analyses saved in this browser."},
        bulk: {title:"Bulk URL Scanner", eyebrow:"BATCH ANALYSIS", description:"Analyze a list of URLs using the same existing analysis endpoint."},
        compare: {title:"Compare URLs", eyebrow:"SIDE-BY-SIDE ANALYSIS", description:"Compare model risk scores and probability estimates for two URLs."},
        email: {title:"Email & File Link Extractor", eyebrow:"LINK EXTRACTION", description:"Extract URLs from pasted text or supported files before scanning them."},
        qr: {title:"QR URL Extractor", eyebrow:"QR SECURITY", description:"Read a QR-code image and inspect the extracted destination with PhishingLens."},
        domain: {title:"Domain Intelligence", eyebrow:"LIVE CHECKS", description:"Check available registration, DNS, TLS and redirect information when the optional backend is connected."},
        breach: {title:"Known Breach Lookup", eyebrow:"ACCOUNT EXPOSURE", description:"Optional email breach lookup; only submit an address if you consent to the configured provider check."},
        report: {title:"Reports & Exports", eyebrow:"REPORTING", description:"Download a report for the current scan or export bulk results."},
        watchlist: {title:"Domain Watchlist", eyebrow:"SAVED DOMAINS", description:"Save URLs in this browser and manually recheck them later."},
        intelligence: {title:"Threat Intelligence", eyebrow:"HOW IT WORKS", description:"Explore the analysis layers used by PhishingLens."}
    };

    const navItems = [
        {group:"ANALYZE", key:"scanner", label:"URL Scanner", icon:"⌕"},
        {group:"ANALYZE", key:"bulk", label:"Bulk URL Scanner", icon:"▦"},
        {group:"ANALYZE", key:"compare", label:"Compare URLs", icon:"⇄"},
        {group:"TOOLS", key:"email", label:"Email & File Links", icon:"✉"},
        {group:"TOOLS", key:"qr", label:"QR Extractor", icon:"▣"},
        {group:"TOOLS", key:"domain", label:"Domain Intelligence", icon:"◎"},
        {group:"TOOLS", key:"breach", label:"Breach Lookup", icon:"♙"},
        {group:"WORKSPACE", key:"history", label:"Scan History", icon:"◷"},
        {group:"WORKSPACE", key:"watchlist", label:"Domain Watchlist", icon:"☆"},
        {group:"WORKSPACE", key:"report", label:"Reports & Exports", icon:"⇩"},
        {group:"LEARN", key:"intelligence", label:"Threat Intelligence", icon:"◈"}
    ];

    const sidebar = document.createElement("aside");
    sidebar.className = "workspace-sidebar";
    sidebar.id = "workspaceSidebar";
    sidebar.setAttribute("aria-label", "Workspace navigation");
    sidebar.innerHTML = '<div class="workspace-sidebar-header"><strong>PhishingLens</strong><span>Security workspace</span></div>';
    let lastGroup = "";
    navItems.forEach(item => {
        if (item.group !== lastGroup) {
            const group = document.createElement("div");
            group.className = "workspace-nav-group";
            group.textContent = item.group;
            sidebar.appendChild(group);
            lastGroup = item.group;
        }
        const button = document.createElement("button");
        button.type = "button";
        button.className = "workspace-nav-item";
        button.dataset.workspaceView = item.key;
        button.innerHTML = '<span class="workspace-nav-icon" aria-hidden="true"></span><span class="workspace-nav-label"></span>';
        button.querySelector(".workspace-nav-icon").textContent = item.icon;
        button.querySelector(".workspace-nav-label").textContent = item.label;
        button.addEventListener("click", () => showWorkspacePage(item.key));
        sidebar.appendChild(button);
    });
    document.body.insertBefore(sidebar, main);

    const heading = document.createElement("div");
    heading.className = "workspace-page-heading";
    heading.id = "workspacePageHeading";
    heading.innerHTML = '<div class="section-label"></div><h1></h1><p></p>';
    main.insertBefore(heading, main.firstChild);

    function clearCurrent() {
        document.querySelectorAll("main > .section").forEach(section => section.classList.remove("workspace-current-section"));
        toolCards.forEach(card => card.classList.remove("workspace-current-tool"));
        sidebar.querySelectorAll(".workspace-nav-item").forEach(button => button.classList.remove("active"));
    }

    function showWorkspacePage(key) {
        const info = pageInfo[key];
        if (!info) return;
        document.body.classList.add("workspace-mode");
        clearCurrent();
        const label = heading.querySelector(".section-label");
        heading.querySelector("h1").textContent = info.title;
        heading.querySelector("p").textContent = info.description;
        label.textContent = info.eyebrow;
        const nav = sidebar.querySelector(`[data-workspace-view="${key}"]`);
        if (nav) nav.classList.add("active");

        if (key === "scanner") document.getElementById("analyze")?.classList.add("workspace-current-section");
        else if (key === "history") document.getElementById("scanHistory")?.classList.add("workspace-current-section");
        else if (key === "watchlist") document.getElementById("watchlist")?.classList.add("workspace-current-section");
        else if (key === "intelligence") document.getElementById("intelligence")?.classList.add("workspace-current-section");
        else {
            document.getElementById("securityTools")?.classList.add("workspace-current-section");
            const card = toolCards.find(node => node.dataset.workspaceTool === key);
            if (card) card.classList.add("workspace-current-tool");
        }
        const toolsMenu = document.getElementById("toolsMenu");
        toolsMenu?.classList.add("hidden");
        document.getElementById("toolsToggle")?.setAttribute("aria-expanded", "false");
        window.scrollTo({top:0, behavior:"smooth"});
        history.replaceState(null, "", `#workspace-${key}`);
    }

    function exitWorkspace() {
        document.body.classList.remove("workspace-mode");
        clearCurrent();
        heading.querySelector("h1").textContent = "";
        history.replaceState(null, "", "#home");
        document.getElementById("home")?.scrollIntoView({behavior:"smooth", block:"start"});
    }

    openButton.addEventListener("click", () => showWorkspacePage("scanner"));
    const homeLink = document.querySelector('.nav-links a[href="#home"]');
    if (homeLink) homeLink.addEventListener("click", event => {
        if (document.body.classList.contains("workspace-mode")) { event.preventDefault(); exitWorkspace(); }
    });
    const analyzeLink = document.querySelector('.nav-links a[href="#analyze"]');
    if (analyzeLink) analyzeLink.addEventListener("click", event => {
        if (document.body.classList.contains("workspace-mode")) { event.preventDefault(); showWorkspacePage("scanner"); }
    });
    const toolsToggle = document.getElementById("toolsToggle");
    if (toolsToggle) toolsToggle.addEventListener("click", () => {
        if (document.body.classList.contains("workspace-mode")) showWorkspacePage("scanner");
    });
})();
