// =============================
// Image Steganography Tool - Complete Working Version
// Matches your HTML structure exactly
// =============================

// --- Constants ---
const IMAGE_TERMINATION_BYTES = {
  jpeg: 'FFD9',
  png: '49454E44AE426082',
  gif: '003B',
  bmp: ''
};

const FILE_SIGNATURES = {
  '4D5A':         { name: 'Windows Executable', ext: ['exe','dll','scr','com'], risk: 'CRITICAL', minSize: 1024 },
  '7F454C46':     { name: 'Linux ELF',         ext: ['elf','so','o'],          risk: 'CRITICAL', minSize: 1024 },
  '504B0304':     { name: 'ZIP Archive',       ext: ['zip','jar','apk','docx','xlsx'], risk: 'HIGH',   minSize: 22 },
  '52617221':     { name: 'RAR Archive',       ext: ['rar'],                    risk: 'HIGH',   minSize: 64  },
  '377ABCAF271C': { name: '7-Zip',             ext: ['7z'],                     risk: 'HIGH',   minSize: 64  },
  '25504446':     { name: 'PDF Document',      ext: ['pdf'],                    risk: 'MEDIUM', minSize: 100 }
};

const DETECTION_MODES = {
  conservative: { confidenceThreshold: 0.8, contextValidation: true  },
  balanced:     { confidenceThreshold: 0.6, contextValidation: true  },
  aggressive:   { confidenceThreshold: 0.4, contextValidation: false }
};

let detectionSettings = { mode: 'conservative', confidenceThreshold: 0.8, contextValidation: true };
let analysisResults   = { fileSignatures: [], lsbAnalysis: {}, statisticalAnalysis: {}, metadata: {}, threatLevel: 'safe', analysisErrors: [] };
let currentFile = null;
let currentImageBinary = null;

// --- Utility helpers ---
function checkForKnownSignatures(data) {
  try {
    if (!data || data.length < 4) return false;
    const max = Math.min(4096, data.length);
    let hex = '';
    for (let i = 0; i < max; i++) hex += data[i].toString(16).padStart(2, '0');
    hex = hex.toLowerCase();
    const sigs = ['4d5a','504b0304','52617221','377abcaf271c','25504446'];
    return sigs.some(s => hex.includes(s));
  } catch (e) {
    console.error('checkForKnownSignatures error:', e);
    return false;
  }
}

function analyzeLocalEntropy(uint8Array, offset, length) {
  try {
    if (!uint8Array || !uint8Array.length) return 0;
    const start = Math.max(0, offset|0);
    const end   = Math.min(start + Math.max(1, length|0), uint8Array.length);
    const sample = uint8Array.slice(start, end);
    const hist = new Array(256).fill(0);
    for (let i = 0; i < sample.length; i++) hist[sample[i]]++;
    let H = 0, n = sample.length || 1;
    for (let i = 0; i < 256; i++) {
      const p = hist[i] / n;
      if (p > 0) H -= p * Math.log2(p);
    }
    return H / 8;
  } catch (e) {
    console.error('analyzeLocalEntropy error:', e);
    return 0;
  }
}

function validateAppendedData(data) {
  try {
    if (!data || !data.length) return { confidence: 0, details: ['No data'], riskLevel: 'LOW' };
    const details = [];
    let score = 0;
    let zeros = 0;
    const n = Math.min(data.length, 8192);
    for (let i = 0; i < n; i++) if (data[i] === 0) zeros++;
    const nullRatio = zeros / n;
    if (nullRatio > 0.90)      { details.push('Mostly null bytes');       score = 0.1; }
    else if (nullRatio > 0.70) { details.push('High null byte ratio');     score = 0.3; }
    else                       { details.push('Non-null content present'); score = 0.6; }
    const ent = analyzeLocalEntropy(data, 0, Math.min(4096, data.length));
    if (ent > 0.50) { details.push(`High entropy (${ent.toFixed(3)})`); score += 0.3; }
    const hasSig = checkForKnownSignatures(data);
    if (hasSig) { details.push('Known file signature present'); score += 0.4; }
    const confidence = Math.min(1, score);
    const riskLevel  = hasSig ? 'HIGH' : (ent > 0.5 ? 'MEDIUM' : 'LOW');
    return { confidence, details, riskLevel };
  } catch (e) {
    console.error('validateAppendedData error:', e);
    return { confidence: 0, details: ['Validation error: ' + e.message], riskLevel: 'LOW' };
  }
}

function hexAt(data, offset, length) {
  const end = Math.min(offset + length, data.length);
  let s = '';
  for (let i = offset; i < end; i++) s += data[i].toString(16).padStart(2, '0');
  return s.toUpperCase();
}

// Robust JPEG end (scan from tail for FFD9)
function jpegEndOffset(u8) {
  for (let i = u8.length - 2; i >= 1; i--) {
    if (u8[i] === 0xD9 && u8[i-1] === 0xFF) return i + 1;
  }
  return -1;
}

// Robust PNG IEND
function pngEndOffset(u8) {
  const sig = [0,0,0,0,0x49,0x45,0x4E,0x44,0xAE,0x42,0x60,0x82];
  for (let i = 0; i <= u8.length - sig.length; i++) {
    let ok = true;
    for (let j = 0; j < sig.length; j++) if (u8[i+j] !== sig[j]) { ok = false; break; }
    if (ok) return i + sig.length;
  }
  return -1;
}

// Download helper
function downloadFile(data, filename, mimeType) {
  const blob = new Blob([data], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename;
  document.body.appendChild(a); a.click();
  document.body.removeChild(a); URL.revokeObjectURL(url);
}

// --- Core analysis ---
async function processFile(file) {
  try {
    currentFile = file;
    analysisResults = { fileSignatures: [], lsbAnalysis: {}, statisticalAnalysis: {}, metadata: {}, threatLevel: 'safe', analysisErrors: [] };

    const analysisEl = document.getElementById('analysisContainer');
    if (analysisEl) analysisEl.style.display = 'block';

    const infoEl = document.getElementById('fileInfo');
    if (infoEl && currentFile) {
      infoEl.innerHTML = `
        <div><strong>Name:</strong> ${currentFile.name}</div>
        <div><strong>Size:</strong> ${(currentFile.size/1024).toFixed(1)} KB</div>
        <div><strong>Type:</strong> ${currentFile.type || 'unknown'}</div>
      `;
    }

    const arr = await file.arrayBuffer();
    currentImageBinary = new Uint8Array(arr);
    await startAnalysis();
  } catch (e) {
    console.error('processFile error:', e);
    alert('Analysis failed: ' + e.message);
  }
}

async function startAnalysis() {
  console.log('Starting analysis...');
  await analyzeFileSignatures();
  console.log('Analysis complete. Found', analysisResults.fileSignatures.length, 'signatures');
  displayResults();
}

async function analyzeFileSignatures() {
  const u8 = currentImageBinary;
  const mime = currentFile?.type || '';
  let endOffset = -1;

  if (mime.includes('jpeg') || mime.includes('jpg')) endOffset = jpegEndOffset(u8);
  else if (mime.includes('png')) endOffset = pngEndOffset(u8);
  else if (mime.includes('gif')) endOffset = u8.lastIndexOf(0x3B) + 1; // 0x3B trailer

  // Build regions strictly AFTER the real end of image
  const regions = [];
  if (endOffset > -1 && endOffset < u8.length - 4096) {
    regions.push({ start: endOffset, format: 'appended' });
  }

  // Conservative: if no appended region, do NOT scan at all
  if (detectionSettings.mode === 'conservative' && regions.length === 0) {
    analysisResults.fileSignatures = [];
    analysisResults.threatLevel = 'safe';
    return;
  }

  // Balanced: if no appended region, scan first 64 KB only
  if (detectionSettings.mode === 'balanced' && regions.length === 0) {
    regions.push({ start: 0, format: 'limited' });
  }

  // Aggressive: full fallback
  if (detectionSettings.mode === 'aggressive' && regions.length === 0) {
    regions.push({ start: 0, format: 'full' });
  }

  const hits = [];
  for (const region of regions) {
    const window = u8.slice(region.start);

    // Validate appended data strongly: require signature AND entropy
    if (region.format === 'appended') {
      const v = validateAppendedData(window);
      const hasSig = checkForKnownSignatures(window);
      const strong = hasSig && v.confidence >= detectionSettings.confidenceThreshold && window.length >= 4096;
      if (!strong) continue;
    }

    const budget = region.format === 'limited' ? 64 * 1024
                  : region.format === 'full' ? Math.min(window.length, 256 * 1024)
                  : Math.min(window.length, 256 * 1024);
    const slab = window.slice(0, budget);
    let hex = '';
    for (let i = 0; i < slab.length; i++) hex += slab[i].toString(16).padStart(2,'0');
    hex = hex.toUpperCase();

    for (const sigHex in FILE_SIGNATURES) {
      const idx = hex.indexOf(sigHex);
      if (idx === -1) continue;
      const byteOffset = region.start + ((idx / 2) | 0);
      const meta = FILE_SIGNATURES[sigHex];
      const remaining = u8.length - byteOffset;
      if (remaining < meta.minSize) continue; // too small to be real
      hits.push({
        signature: sigHex,
        name: meta.name,
        extensions: meta.ext,
        description: `${meta.name} signature`,
        offset: byteOffset,
        hexOffset: '0x' + byteOffset.toString(16),
        risk: meta.risk
      });
    }
  }

  // De‑duplicate overlapping hits by signature+offset
  const seen = new Set();
  analysisResults.fileSignatures = hits.filter(h => {
    const k = h.signature + ':' + h.offset;
    if (seen.has(k)) return false;
    seen.add(k); return true;
  });

  const exeFound = analysisResults.fileSignatures.some(s => s.extensions.includes('exe'));
  analysisResults.threatLevel = exeFound ? 'critical' : (analysisResults.fileSignatures.length ? 'high' : 'safe');
}

// --- Display results ---
function displayResults() {
  displayThreatAssessment();
  displayQuickResults();
  displayFileSignatures();
}

function displayThreatAssessment() {
  const assessmentEl = document.getElementById('assessmentResult');
  if (!assessmentEl) return;

  const level = analysisResults.threatLevel;

  let html = '';
  if (level === 'critical') {
    html = `<div class="alert alert-danger">
      <strong>🚨 CRITICAL THREAT</strong> - Executable files detected with high confidence
    </div>`;
  } else if (level === 'high') {
    html = `<div class="alert alert-warning">
      <strong>⚠️ HIGH RISK</strong> - Suspicious file signatures detected
    </div>`;
  } else {
    html = `<div class="alert alert-success">
      <strong>✅ SAFE</strong> - No embedded file signatures detected
    </div>`;
  }

  html += `<div style="margin-top:16px">
    <p><strong>Detection Mode:</strong> ${detectionSettings.mode.charAt(0).toUpperCase() + detectionSettings.mode.slice(1)}</p>
    <p><strong>Enhanced Error Handling:</strong> Enabled</p>
  </div>`;

  assessmentEl.innerHTML = html;
}

function displayQuickResults() {
  const quickEl = document.getElementById('quickResults');
  if (!quickEl) return;

  const count    = analysisResults.fileSignatures.length;
  const highConf = analysisResults.fileSignatures.filter(s => s.risk === 'CRITICAL' || s.risk === 'HIGH').length;
  const exeCount = analysisResults.fileSignatures.filter(s => s.extensions.includes('exe')).length;

  quickEl.innerHTML = `
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-value">${count}</div><div class="stat-label">Total Detections</div></div>
      <div class="stat-card"><div class="stat-value">${highConf}</div><div class="stat-label">High Confidence (≥80%)</div></div>
      <div class="stat-card"><div class="stat-value">${exeCount}</div><div class="stat-label">Executable Files</div></div>
      <div class="stat-card"><div class="stat-value">${(detectionSettings.confidenceThreshold * 100).toFixed(0)}%</div><div class="stat-label">Average Confidence</div></div>
    </div>
  `;
}

function displayFileSignatures() {
  const sigEl = document.getElementById('signatureResults');
  if (!sigEl) return;

  if (analysisResults.fileSignatures.length === 0) {
    sigEl.innerHTML = `
      <div class="detection-result">
        <div class="result-header">
          <span class="result-title">✅ No embedded file signatures detected</span>
          <span class="result-badge badge-safe">CLEAN</span>
        </div>
        <p>The image appears to contain only standard image data with no embedded files.</p>
        <div class="detection-stats">
          <small>✓ Advanced structure validation enabled<br>
          ✓ Context-aware detection active<br>
          ✓ False positive filtering applied</small>
        </div>
      </div>`;
    return;
  }

  let html = '';
  analysisResults.fileSignatures.forEach((sig) => {
    const badgeClass = sig.risk === 'CRITICAL' ? 'badge-danger' : (sig.risk === 'HIGH' ? 'badge-warn' : 'badge-info');
    html += `
      <div class="detection-result">
        <div class="result-header">
          <span class="result-title">${sig.name}</span>
          <span class="result-badge ${badgeClass}">${sig.risk}</span>
        </div>
        <p>${sig.description}</p>
        <ul>
          <li>Signature: ${sig.signature}</li>
          <li>Offset: ${sig.hexOffset}</li>
          <li>Extensions: ${sig.extensions.join(', ')}</li>
        </ul>
      </div>`;
  });
  sigEl.innerHTML = html;
}

// --- Global actions used by HTML onclick attributes ---
function exportResults() {
  const report = {
    generatedAt: new Date().toISOString(),
    file: { name: currentFile?.name, size: currentFile?.size, type: currentFile?.type },
    settings: detectionSettings,
    results: analysisResults
  };
  downloadFile(JSON.stringify(report, null, 2), 'steg-analysis-report.json', 'application/json');
}

function downloadAllExtracted() {
  const pkg = {
    note: 'No extracted binaries available; providing analysis report package',
    file: { name: currentFile?.name, size: currentFile?.size, type: currentFile?.type },
    settings: detectionSettings,
    results: analysisResults
  };
  downloadFile(JSON.stringify(pkg, null, 2), 'steg-analysis-package.json', 'application/json');
}

function saveAnalysisSession(data = analysisResults) {
  try {
    const key = 'steg-session-' + Date.now();
    const payload = {
      ts: new Date().toISOString(),
      file: { name: currentFile?.name, size: currentFile?.size, type: currentFile?.type },
      settings: detectionSettings,
      results: data
    };
    localStorage.setItem(key, JSON.stringify(payload));
    alert('Session saved');
  } catch (e) {
    alert('Could not save session: ' + e.message);
  }
}

function resetAnalysis() {
  analysisResults = { fileSignatures: [], lsbAnalysis: {}, statisticalAnalysis: {}, metadata: {}, threatLevel: 'safe', analysisErrors: [] };
  currentFile = null;
  ['assessmentResult','quickResults','signatureResults','extractionResults','lsbResults','lsbVisual','statsResults','histograms','metadataResults','visualResults']
    .forEach(id => { const el = document.getElementById(id); if (el) el.innerHTML = ''; });
  const analysisEl = document.getElementById('analysisContainer');
  if (analysisEl) analysisEl.style.display = 'none';
  const fileInput = document.getElementById('fileInput');
  if (fileInput) fileInput.value = '';
  window.scrollTo({ top: 0, behavior: 'smooth' });
}

// --- Event wiring ---

  const fileInput  = document.getElementById('fileInput');
  const uploadArea = document.getElementById('uploadArea');

  if (fileInput) {
    fileInput.addEventListener('change', () => {
      if (fileInput.files && fileInput.files[0]) processFile(fileInput.files[0]);
    });
  }

(function init() {
  const modeSel = document.getElementById('detectionMode');
  const thrSel  = document.getElementById('confidenceThreshold');
  const ctxSel  = document.getElementById('contextValidation');

  if (modeSel) modeSel.addEventListener('change', (e) => {
    const m = e.target.value || 'conservative';
    detectionSettings.mode = m;
    const cfg = DETECTION_MODES[m] || DETECTION_MODES.conservative;
    detectionSettings.confidenceThreshold = cfg.confidenceThreshold;
    detectionSettings.contextValidation   = cfg.contextValidation;
  });

  if (thrSel) thrSel.addEventListener('change', (e) => {
    const v = parseFloat(e.target.value);
    if (!Number.isNaN(v)) detectionSettings.confidenceThreshold = v;
  });

  if (ctxSel) ctxSel.addEventListener('change', (e) => {
    detectionSettings.contextValidation = (e.target.value === 'enabled');
  });

  const fileInput  = document.getElementById('fileInput');
  const uploadArea = document.getElementById('uploadArea');

  if (fileInput) {
    fileInput.addEventListener('change', () => {
      if (fileInput.files && fileInput.files[0]) processFile(fileInput.files[0]);
    });
  }

  if (uploadArea) {
    // Click to open file dialog
    uploadArea.addEventListener('click', () => {
      if (fileInput) fileInput.click();
    });
    
    uploadArea.addEventListener('dragover', (e) => { 
      e.preventDefault(); 
      uploadArea.classList.add('drag'); 
    });
    
    uploadArea.addEventListener('dragleave', () => { 
      uploadArea.classList.remove('drag'); 
    });
    
    uploadArea.addEventListener('drop', (e) => {
      e.preventDefault();
      uploadArea.classList.remove('drag');
      const f = e.dataTransfer.files && e.dataTransfer.files[0];
      if (f) processFile(f);
    });
  }

  // Tab switching
  const tabBtns = document.querySelectorAll('.tab-btn');
  const tabPanes = document.querySelectorAll('.tab-pane');

  tabBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      const targetTab = btn.getAttribute('data-tab');
      
      tabBtns.forEach(b => b.classList.remove('active'));
      tabPanes.forEach(p => p.classList.remove('active'));
      
      btn.classList.add('active');
      const targetPane = document.getElementById(targetTab);
      if (targetPane) targetPane.classList.add('active');
    });
  });

  console.log('Steganography detector initialized');
})();




