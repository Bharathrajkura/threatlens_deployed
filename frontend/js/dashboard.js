// ── Tab navigation ────────────────────────────────────────────────────────────
function showTab(name, btn) {
  document.querySelectorAll('.tab-pane').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav-tab').forEach(t => t.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  if (btn) btn.classList.add('active');
  if (name === 'history') loadHistory();
}

// ── Load stats on page load ────────────────────────────────────────────────────
window.addEventListener('DOMContentLoaded', () => {
  loadStats();
  loadKeys();
});

async function loadStats() {
  try {
    const res  = await fetch('/api/stats');
    const data = await res.json();
    document.getElementById('statTotal').textContent  = data.total;
    document.getElementById('statSafe').textContent   = data.safe;
    document.getElementById('statRisky').textContent  = data.risky;
    document.getElementById('statDanger').textContent = data.dangerous;
  } catch(e) {}
}

// ── API Keys (stored in localStorage) ────────────────────────────────────────
function saveKeys() {
  const vt    = document.getElementById('vtKey').value.trim();
  const abuse = document.getElementById('abuseKey').value.trim();
  localStorage.setItem('tl_vt_key', vt);
  localStorage.setItem('tl_abuse_key', abuse);
  const el = document.getElementById('saveAlert');
  el.textContent = '✓ Keys saved locally in your browser.';
  el.className   = 'alert success';
  setTimeout(() => el.className = 'alert hidden', 3000);
}

function loadKeys() {
  const vt    = localStorage.getItem('tl_vt_key')    || '';
  const abuse = localStorage.getItem('tl_abuse_key') || '';
  if (vt)    document.getElementById('vtKey').value    = vt;
  if (abuse) document.getElementById('abuseKey').value = abuse;
}

function getKeys() {
  return {
    virustotal_key: localStorage.getItem('tl_vt_key')    || '',
    abuseipdb_key:  localStorage.getItem('tl_abuse_key') || '',
  };
}

// ── Main scan ─────────────────────────────────────────────────────────────────
async function scanURL() {
  const urlInput = document.getElementById('urlInput').value.trim();
  hideScanAlert();
  if (!urlInput) { showScanAlert('Please enter a URL to scan.'); return; }
  if (!isValidScanInput(urlInput)) {
    showScanAlert('Enter a valid URL like example.com or https://example.com');
    return;
  }

  const btn = document.getElementById('scanBtn');
  btn.textContent = 'SCANNING...';
  btn.disabled    = true;

  // Show pipeline
  document.getElementById('pipeline').style.display = 'flex';
  document.getElementById('results').style.display  = 'none';
  resetPipeline();

  // Animate stages
  setStage(1, 'active', 'RUNNING');
  await delay(400);
  setStage(2, 'active', 'QUEUED');
  await delay(300);
  setStage(3, 'active', 'QUEUED');

  try {
    const res  = await fetch('/api/analyze', {
      method:  'POST',
      headers: {'Content-Type': 'application/json'},
      body:    JSON.stringify({ url: urlInput, ...getKeys() })
    });
    const data = await res.json();

    if (!res.ok || data.error) throw new Error(data.error || 'Scan failed.');

    // Mark all done
    setStage(1, 'done', 'DONE');
    setStage(2, 'done', 'DONE');
    setStage(3, 'done', 'DONE');

    await delay(300);
    renderResults(data);
    document.getElementById('results').style.display = 'block';
    loadStats();
  } catch(e) {
    setStage(1, 'error', 'ERROR');
    setStage(2, 'error', 'ERROR');
    setStage(3, 'error', 'ERROR');
    showScanAlert('Analysis failed: ' + e.message);
  } finally {
    btn.textContent = 'SCAN';
    btn.disabled    = false;
  }
}

// ── Render results ────────────────────────────────────────────────────────────
function renderResults(data) {
  const { ml_analysis: ml, nlp_analysis: nlp, api_analysis: api, final_result: final, url } = data;

  // Verdict card
  const color = final.verdict_color || '#00ffe7';
  document.getElementById('verdictCard').style.setProperty('--verdict-color', color);
  document.getElementById('verdictBadge').textContent = final.verdict;
  document.getElementById('verdictBadge').style.color = color;
  document.getElementById('verdictUrl').textContent   = url;
  document.getElementById('verdictMsg').textContent   = final.message;
  document.getElementById('confidenceVal').textContent = (final.confidence * 100).toFixed(0) + '%';

  // Gauge
  const pct = final.normalized_score;
  const gaugeEl = document.getElementById('gaugePath');
  const gaugeScore = document.getElementById('gaugeScore');
  const dashLen = 157;
  gaugeEl.style.strokeDashoffset = dashLen - (dashLen * pct);
  gaugeEl.style.stroke = scoreToColor(pct);
  gaugeScore.textContent = (pct * 100).toFixed(0) + '%';
  gaugeScore.style.color = scoreToColor(pct);

  renderScoreLegend(final.score_bands || [], pct);
  renderWeights(final.score_breakdown.weights_used || {});

  // ML section
  renderSection('ml', ml, final.score_breakdown.ml_score);
  // NLP section
  renderSection('nlp', nlp, final.score_breakdown.nlp_score);
  // API section
  renderSection('api', api, final.score_breakdown.api_score);

  // ML features detail
  const feats = ml.features || {};
  const featData = [
    ['URL Length',        feats.url_length, feats.url_length > 75 ? 'bad' : 'good'],
    ['Has HTTPS',         feats.has_https ? 'YES' : 'NO', feats.has_https ? 'good' : 'bad'],
    ['IP Address',        feats.has_ip_address ? 'YES' : 'NO', feats.has_ip_address ? 'bad' : 'good'],
    ['Suspicious TLD',    feats.suspicious_tld ? feats.tld : 'NO', feats.suspicious_tld ? 'bad' : 'good'],
    ['Subdomain Count',   feats.subdomain_count, feats.subdomain_count >= 3 ? 'bad' : 'good'],
    ['Phishing Keywords', feats.phishing_kw_count, feats.phishing_kw_count > 0 ? 'bad' : 'good'],
    ['Entropy',           feats.entropy, feats.entropy > 3.8 ? 'bad' : 'good'],
    ['Hyphen Count',      feats.hyphen_count, feats.hyphen_count >= 3 ? 'bad' : 'good'],
    ['@ Symbol',          feats.at_symbol ? 'YES' : 'NO', feats.at_symbol ? 'bad' : 'good'],
    ['Hex Encoding',      feats.hex_encoding ? 'YES' : 'NO', feats.hex_encoding ? 'warn' : 'good'],
  ];
  renderKV('mlFeatures', featData);

  // NLP page info
  const pi = nlp.page_info || {};
  const pageData = [
    ['Page Fetched',      pi.success ? 'YES' : 'NO', pi.success ? 'good' : 'warn'],
    ['Page Title',        pi.title || '—', ''],
    ['Status Code',       pi.status_code || '—', ''],
    ['Form Count',        pi.form_count != null ? pi.form_count : '—', pi.form_count > 3 ? 'bad' : 'good'],
    ['Password Field',    pi.has_password_field ? 'FOUND' : 'NO', pi.has_password_field ? 'bad' : 'good'],
    ['Credit Card Field', pi.has_credit_card_field ? 'FOUND' : 'NO', pi.has_credit_card_field ? 'bad' : 'good'],
    ['Hidden iFrames',    pi.hidden_iframe_count != null ? pi.hidden_iframe_count : '—', pi.hidden_iframe_count > 0 ? 'bad' : 'good'],
    ['External Scripts',  pi.external_script_count != null ? pi.external_script_count : '—', pi.external_script_count > 5 ? 'warn' : 'good'],
    ['Redirects',         pi.redirect_count != null ? pi.redirect_count : '—', pi.redirect_count > 2 ? 'warn' : 'good'],
    ['Content Length',    pi.content_length ? pi.content_length + ' chars' : '—', ''],
  ];
  renderKV('nlpPageInfo', pageData);

  // API details
  const vt    = api.virustotal    || {};
  const abuse = api.abuseipdb     || {};
  const apiData = [
    ['Resolved IP',       api.resolved_ip || '—', ''],
    ['VT Available',      vt.available    ? 'YES' : 'NO', ''],
    ['VT Malicious',      vt.available && vt.malicious != null ? vt.malicious : '—', vt.malicious > 0 ? 'bad' : 'good'],
    ['VT Suspicious',     vt.available && vt.suspicious != null ? vt.suspicious : '—', vt.suspicious > 0 ? 'warn' : 'good'],
    ['VT Engines Total',  vt.available && vt.total_engines ? vt.total_engines : '—', ''],
    ['AbuseIPDB',         abuse.available ? 'YES' : 'NO', ''],
    ['Abuse Confidence',  abuse.available && abuse.confidence_score != null ? abuse.confidence_score + '%' : '—',
                          abuse.confidence_score > 50 ? 'bad' : abuse.confidence_score > 0 ? 'warn' : 'good'],
    ['Total Reports',     abuse.available && abuse.total_reports != null ? abuse.total_reports : '—', ''],
    ['Country',           abuse.country || '—', ''],
    ['ISP',               abuse.isp || '—', ''],
  ];
  renderKV('apiDetails', apiData);

  // All flags
  const allFlags = final.all_flags || [];
  if (allFlags.length > 0) {
    document.getElementById('allFlagsCard').style.display = 'block';
    const list = document.getElementById('allFlagsList');
    list.innerHTML = allFlags.map(f => `<div class="flag-all">⚠ ${f}</div>`).join('');
  } else {
    document.getElementById('allFlagsCard').style.display = 'none';
  }
}

function renderSection(prefix, analysis, score) {
  const barEl   = document.getElementById(prefix + 'Bar');
  const scoreEl = document.getElementById(prefix + 'Score');
  const riskEl  = document.getElementById(prefix + 'Risk');
  const summEl  = document.getElementById(prefix + 'Summary');
  const flagsEl = document.getElementById(prefix + 'Flags');

  const pct = Math.round(score * 100);
  barEl.style.width = pct + '%';
  barEl.style.background = scoreToColor(score);
  scoreEl.textContent = pct + '%';
  scoreEl.style.color = scoreToColor(score);

  const level = analysis.risk_level || 'UNKNOWN';
  riskEl.textContent  = level;
  riskEl.className    = 'risk-badge risk-' + level;

  summEl.textContent = analysis.summary || '';

  const flags = analysis.flags || [];
  flagsEl.innerHTML = flags.slice(0, 5).map(f => `<div class="flag-item">⚠ ${f}</div>`).join('');
}

function renderScoreLegend(bands, currentScore) {
  const el = document.getElementById('scoreLegend');
  el.innerHTML = bands.map(b => `
    <div class="legend-row ${currentScore >= b.min && currentScore < (b.max + 0.0001) ? 'active' : ''}">
      <span class="legend-swatch" style="background:${b.color}"></span>
      <span class="legend-label">${b.label}</span>
      <span class="legend-range">${Math.round(b.min * 100)}% - ${Math.round(b.max * 100)}%</span>
    </div>
  `).join('');
}

function renderWeights(weights) {
  const grid = document.getElementById('weightsGrid');
  const note = document.getElementById('weightsNote');
  const items = [
    ['ML', weights.ml || 0],
    ['NLP', weights.nlp || 0],
    ['API', weights.api || 0],
  ];

  grid.innerHTML = items.map(([label, value]) => `
    <div class="weight-pill">
      <span class="weight-name">${label}</span>
      <span class="weight-value">${Math.round(value * 100)}%</span>
    </div>
  `).join('');

  note.textContent = `Mode: ${(weights.note || 'standard').toUpperCase()}`;
}

function renderKV(containerId, rows) {
  const el = document.getElementById(containerId);
  el.innerHTML = rows.map(([k, v, cls]) => `
    <div class="kv-row">
      <span class="kv-key">${k}</span>
      <span class="kv-val ${cls || ''}">${v}</span>
    </div>
  `).join('');
}

// ── History ────────────────────────────────────────────────────────────────────
async function loadHistory() {
  const container = document.getElementById('historyTable');
  container.innerHTML = '<div class="empty-state">Loading...</div>';
  try {
    const res  = await fetch('/api/history');
    const data = await res.json();
    if (!data.length) {
      container.innerHTML = '<div class="empty-state">No scans yet. Start by analyzing a URL.</div>';
      return;
    }
    container.innerHTML = `
      <table class="htable">
        <thead>
          <tr>
            <th>#</th>
            <th>URL</th>
            <th>VERDICT</th>
            <th>SCORE</th>
            <th>ML</th>
            <th>NLP</th>
            <th>API</th>
            <th>DATE</th>
            <th></th>
          </tr>
        </thead>
        <tbody>
          ${data.map((r, i) => `
            <tr>
              <td style="color:var(--muted);font-family:'Share Tech Mono',monospace;font-size:11px">${i+1}</td>
              <td class="url-cell" title="${r.url}">${r.url}</td>
              <td><span class="risk-badge risk-${mapVerdict(r.verdict)}">${r.verdict}</span></td>
              <td style="font-family:'Share Tech Mono',monospace;color:${scoreToColor((r.final_score||0))}">
                ${((r.final_score||0)*100).toFixed(0)}%
              </td>
              <td style="font-family:'Share Tech Mono',monospace;font-size:12px">${((r.ml_score||0)*100).toFixed(0)}%</td>
              <td style="font-family:'Share Tech Mono',monospace;font-size:12px">${((r.nlp_score||0)*100).toFixed(0)}%</td>
              <td style="font-family:'Share Tech Mono',monospace;font-size:12px">${((r.api_score||0)*100).toFixed(0)}%</td>
              <td style="color:var(--muted);font-size:12px">${r.searched_at}</td>
              <td><button class="del-btn" onclick="deleteHistory(${r.id}, this)">✕</button></td>
            </tr>
          `).join('')}
        </tbody>
      </table>
    `;
  } catch(e) {
    container.innerHTML = '<div class="empty-state">Failed to load history.</div>';
  }
}

async function deleteHistory(id, btn) {
  btn.disabled = true;
  await fetch(`/api/history/${id}`, { method: 'DELETE' });
  btn.closest('tr').remove();
  loadStats();
}

// ── Helpers ───────────────────────────────────────────────────────────────────
function resetPipeline() {
  [1,2,3].forEach(i => setStage(i, '', 'WAITING'));
}

function setStage(num, cls, status) {
  const el = document.getElementById('stage' + num);
  el.className = 'pipe-stage' + (cls ? ' ' + cls : '');
  document.getElementById('st' + num).textContent = status;
}

function delay(ms) { return new Promise(r => setTimeout(r, ms)); }

function isValidScanInput(value) {
  const raw = (value || '').trim();
  if (!raw || raw.length < 4 || /\s/.test(raw)) return false;

  try {
    const normalized = raw.startsWith('http://') || raw.startsWith('https://')
      ? raw
      : `https://${raw}`;
    const parsed = new URL(normalized);
    const host = (parsed.hostname || '').toLowerCase();
    if (!host || !host.includes('.')) return false;
    if (host.startsWith('.') || host.endsWith('.') || host.includes('..')) return false;
    return /^[a-z0-9.-]+$/i.test(host);
  } catch {
    return false;
  }
}

function showScanAlert(message) {
  const el = document.getElementById('scanAlert');
  el.textContent = message;
  el.className = 'alert error';
}

function hideScanAlert() {
  const el = document.getElementById('scanAlert');
  if (el) {
    el.textContent = '';
    el.className = 'alert hidden';
  }
}

function scoreToColor(score) {
  if (score < 0.2)  return '#22c55e';
  if (score < 0.4)  return '#84cc16';
  if (score < 0.6)  return '#f59e0b';
  if (score < 0.8)  return '#f97316';
  return '#ef4444';
}

function mapVerdict(v) {
  const m = {
    'SAFE': 'LOW', 'LOW RISK': 'LOW', 'SUSPICIOUS': 'MEDIUM',
    'HIGH RISK': 'HIGH', 'MALICIOUS': 'CRITICAL'
  };
  return m[v] || 'UNKNOWN';
}

// Enter key to scan
document.addEventListener('keydown', e => {
  if (e.key === 'Enter' && document.activeElement.id === 'urlInput') scanURL();
});
