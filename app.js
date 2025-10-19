// =============================
// Image Steganography Tool - Corrected & Enhanced Version
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
let currentImageSrc = null; // Store the Data URL for canvas operations

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

    // Create a Data URL to be used by canvas operations
    const reader = new FileReader();
    reader.onload = (e) => {
      currentImageSrc = e.target.result;
    };
    reader.readAsDataURL(file);
    
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
  // Clear old results
  resetAnalysisResults();
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

  const regions = [];
  
  // Region 1: Appended data (if any)
  // We check for a reasonable amount of data (4KB) after the end marker
  if (endOffset > -1 && endOffset < u8.length - 4096) {
    regions.push({ start: endOffset, format: 'appended' });
  }

  // Region 2: Balanced mode - scan file *after* a 64KB header
  if (detectionSettings.mode === 'balanced') {
    regions.push({ start: 64 * 1024, format: 'full_skip_header' });
  }
  
  // Region 3: Aggressive mode - scan *entire* file
  if (detectionSettings.mode === 'aggressive') {
    regions.push({ start: 0, format: 'full' });
  }
  
  // Conservative mode will only run if the 'appended' region was added.

  const hits = [];
  for (const region of regions) {
    // Skip this region if it's outside the file bounds
    if (region.start >= u8.length) continue;

    const window = u8.slice(region.start);

    // Validate appended data strongly: require signature AND entropy
    if (region.format === 'appended') {
      const v = validateAppendedData(window);
      const hasSig = checkForKnownSignatures(window);
      // Check if validation meets the mode's confidence threshold
      const strong = hasSig && v.confidence >= detectionSettings.confidenceThreshold && window.length >= 4096;
      if (!strong) continue; // Skip this appended region if validation fails
    }

    // Set a performance budget for scanning
    const budget = (region.format === 'full' || region.format === 'full_skip_header')
                 ? Math.min(window.length, 256 * 1024) // Scan up to 256KB for full scans
                 : Math.min(window.length, 256 * 1024); // Scan up to 256KB for appended
                 
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
        description: `${meta.name} signature (found via ${region.format} scan)`,
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

// === FULL LSB TEXT EXTRACTION ===
async function extractLSBText() {
  if (!currentFile || !currentImageSrc) {
    alert('Please upload an image first');
    return;
  }

  const extractionResults = document.getElementById('extractionResults');
  if (!extractionResults) return;

  // Show progress
  extractionResults.innerHTML = '<div class="progress-text" style="padding: 16px;">🔍 Extracting LSB data from image...</div>';

  try {
    // Load image into canvas
    const img = new Image();
    
    img.onload = function() {
      // Create canvas
      const canvas = document.createElement('canvas');
      const ctx = canvas.getContext('2d');
      canvas.width = img.width;
      canvas.height = img.height;
      ctx.drawImage(img, 0, 0);
      
      // Get pixel data
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const pixels = imageData.data;
      
      // Get LSB extraction method
      const method = document.getElementById('lsbMethod')?.value || 'standard';
      
      // Extract LSBs based on method
      let extractedBits = [];
      
      switch(method) {
        case 'standard': // 1-bit LSB from RGB
          for (let i = 0; i < pixels.length; i += 4) {
            extractedBits.push(pixels[i] & 1);     // R
            extractedBits.push(pixels[i+1] & 1);   // G
            extractedBits.push(pixels[i+2] & 1);   // B
          }
          break;
          
        case '2bit': // 2-bit LSB from RGB
          for (let i = 0; i < pixels.length; i += 4) {
            extractedBits.push((pixels[i] & 2) >> 1);
            extractedBits.push(pixels[i] & 1);
            extractedBits.push((pixels[i+1] & 2) >> 1);
            extractedBits.push(pixels[i+1] & 1);
            extractedBits.push((pixels[i+2] & 2) >> 1);
            extractedBits.push(pixels[i+2] & 1);
          }
          break;
          
        case 'red-only': // Red channel only
          for (let i = 0; i < pixels.length; i += 4) {
            extractedBits.push(pixels[i] & 1);
          }
          break;
          
        case 'sequential': // Sequential RGB
          for (let i = 0; i < pixels.length; i++) {
            if (i % 4 !== 3) extractedBits.push(pixels[i] & 1);
          }
          break;
      }
      
      // Convert bits to bytes
      let bytes = [];
      for (let i = 0; i < extractedBits.length; i += 8) {
        if (i + 7 < extractedBits.length) {
          let byte = 0;
          for (let j = 0; j < 8; j++) {
            byte = (byte << 1) | extractedBits[i + j];
          }
          bytes.push(byte);
        }
      }
      
      // Try to decode as text
      let extractedText = '';
      let validTextFound = false;
      
      // Method 1: Look for null-terminated string
      for (let i = 0; i < Math.min(bytes.length, 10000); i++) {
        if (bytes[i] === 0) {
          if (i > 10) { // At least 10 chars
            const potentialText = String.fromCharCode(...bytes.slice(0, i));
            if (/^[\x20-\x7E\n\r\t]+$/.test(potentialText)) {
              extractedText = potentialText;
              validTextFound = true;
              break;
            }
          }
        }
      }
      
      // Method 2: Extract all printable ASCII
      if (!validTextFound) {
        const printable = bytes.filter(b => (b >= 32 && b <= 126) || b === 10 || b === 13);
        if (printable.length > 20) {
          extractedText = String.fromCharCode(...printable.slice(0, 5000));
          validTextFound = true;
        }
      }
      
      // Display results
      if (validTextFound && extractedText.length > 10) {
        extractionResults.innerHTML = `
          <div class="detection-result" style="border-left-color: #4CAF50;">
            <div class="result-header">
              <span class="result-title">✅ LSB Text Extracted</span>
              <span class="result-badge badge-safe">SUCCESS</span>
            </div>
            <p><strong>Method:</strong> ${method}</p>
            <p><strong>Length:</strong> ${extractedText.length} characters</p>
            <p><strong>Total Bits:</strong> ${extractedBits.length.toLocaleString()}</p>
            
            <div style="margin-top: 16px; padding: 16px; background: #f5f5f5; border-radius: 8px; max-height: 300px; overflow-y: auto;">
              <strong>Extracted Text:</strong>
              <pre style="margin-top: 8px; white-space: pre-wrap; word-wrap: break-word; font-family: monospace; font-size: 0.9rem;">${extractedText.replace(/</g, '&lt;').replace(/>/g, '&gt;')}</pre>
            </div>
            
            <button class="btn btn--primary" id="downloadLsbTextBtn" style="margin-top: 16px;">
              💾 Download Extracted Text
            </button>
          </div>
        `;
        // Add event listener to the new button
        document.getElementById('downloadLsbTextBtn').onclick = () => {
          downloadExtractedText(extractedText, currentFile.name);
        };

      } else {
        extractionResults.innerHTML = `
          <div class="detection-result" style="border-left-color: #FF9800;">
            <div class="result-header">
              <span class="result-title">⚠️ No Clear Text Found</span>
              <span class="result-badge badge-warn">NO DATA</span>
            </div>
            <p>No readable text detected in LSB data using the <strong>${method}</strong> method.</p>
            <p><strong>Extracted Bits:</strong> ${extractedBits.length.toLocaleString()}</p>
            <p><strong>Possible Reasons:</strong></p>
            <ul style="margin-left: 20px; margin-top: 8px;">
              <li>Image doesn't contain LSB steganography</li>
              <li>Wrong extraction method selected</li>
              <li>Data is encrypted or compressed</li>
              <li>Using different bit-plane encoding</li>
            </ul>
            <p style="margin-top: 12px;"><em>💡 Try different LSB extraction methods from the dropdown above.</em></p>
          </div>
        `;
      }
    };
    
    img.onerror = function() {
      throw new Error('Could not load image into canvas. The file might be corrupt or not a valid image.');
    };

    img.src = currentImageSrc; // Use the stored Data URL
    
  } catch(e) {
    extractionResults.innerHTML = `
      <div class="detection-result" style="border-left-color: #F44336;">
        <div class="result-header">
          <span class="result-title">❌ Extraction Failed</span>
          <span class="result-badge badge-danger">ERROR</span>
        </div>
        <p>Error during LSB extraction: ${e.message}</p>
      </div>
    `;
    console.error('LSB extraction error:', e);
  }
}

// Helper to download extracted text
function downloadExtractedText(text, originalFilename) {
  const filename = 'extracted-lsb-' + originalFilename.replace(/\.[^/.]+$/, '') + '.txt';
  downloadFile(text, filename, 'text/plain');
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
    <p><strong>Confidence Threshold:</strong> ${(detectionSettings.confidenceThreshold * 100).toFixed(0)}%</p>
  </div>`;

  assessmentEl.innerHTML = html;
}

function displayQuickResults() {
  const quickEl = document.getElementById('quickResults');
  if (!quickEl) return;

  const count    = analysisResults.fileSignatures.length;
  const highConf = analysisResults.fileSignatures.filter(s => s.risk === 'CRITICAL' || s.risk === 'HIGH').length;
  const exeCount = analysisResults.fileSignatures.filter(s => s.extensions.includes('exe')).length;
  const appendedCount = analysisResults.fileSignatures.filter(s => s.description.includes('appended')).length;

  quickEl.innerHTML = `
    <div class="stats-grid">
      <div class="stat-card"><div class="stat-value">${count}</div><div class="stat-label">Total Detections</div></div>
      <div class="stat-card"><div class="stat-value">${highConf}</div><div class="stat-label">High/Critical Risk</div></div>
      <div class="stat-card"><div class="stat-value">${exeCount}</div><div class="stat-label">Executable Files</div></div>
      <div class="stat-card"><div class="stat-value">${appendedCount}</div><div class="stat-label">Appended Detections</div></div>
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
        <p>The image appears to contain only standard image data with no embedded files based on the current detection mode.</p>
        <p><em>💡 Try 'Balanced' or 'Aggressive' mode for a deeper scan.</em></p>
        <div class="detection-stats">
          <small>✓ Detection Mode: ${detectionSettings.mode}</small>
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
          <li>Signature: <strong>${sig.signature}</strong></li>
          <li>Offset: ${sig.hexOffset} (Byte: ${sig.offset})</li>
          <li>Possible Extensions: ${sig.extensions.join(', ')}</li>
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
  alert('Starting batch extraction...\nYou will receive multiple download prompts for any detected appended or embedded files.');
  extractAppendedFiles();
  extractEmbeddedFiles();
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
    alert('Session saved to browser local storage.');
  } catch (e) {
    alert('Could not save session: ' + e.message);
  }
}

// Clears result sections but keeps settings and file
function resetAnalysisResults() {
  analysisResults = { fileSignatures: [], lsbAnalysis: {}, statisticalAnalysis: {}, metadata: {}, threatLevel: 'safe', analysisErrors: [] };
  ['assessmentResult','quickResults','signatureResults','extractionResults','lsbResults','lsbVisual','statsResults','histograms','metadataResults','visualResults']
    .forEach(id => { const el = document.getElementById(id); if (el) el.innerHTML = ''; });
}

// Full reset
function resetAnalysis() {
  resetAnalysisResults();
  currentFile = null;
  currentImageBinary = null;
  currentImageSrc = null;
  
  const analysisEl = document.getElementById('analysisContainer');
  if (analysisEl) analysisEl.style.display = 'none';
  
  const infoEl = document.getElementById('fileInfo');
  if (infoEl) infoEl.innerHTML = '';

  const fileInput = document.getElementById('fileInput');
  if (fileInput) fileInput.value = '';
  
  window.scrollTo({ top: 0, behavior: 'smooth' });
}


// === Extraction Functions ===

function extractAppendedFiles() {
  if (!currentImageBinary) {
    alert('Please upload an image first');
    return;
  }
  
  const mime = currentFile?.type || '';
  let endOffset = -1;
  
  if (mime.includes('jpeg') || mime.includes('jpg')) endOffset = jpegEndOffset(currentImageBinary);
  else if (mime.includes('png')) endOffset = pngEndOffset(currentImageBinary);
  else if (mime.includes('gif')) endOffset = currentImageBinary.lastIndexOf(0x3B) + 1;
  
  if (endOffset > -1 && endOffset < currentImageBinary.length - 100) {
    const appendedData = currentImageBinary.slice(endOffset);
    const filename = `extracted-appended-${Date.now()}.bin`;
    downloadFile(appendedData, filename, 'application/octet-stream');
    alert(`Extracted ${appendedData.length} bytes of appended data after image end marker`);
  } else {
    alert('No appended data found after image termination marker');
  }
}

function extractEmbeddedFiles() {
  if (analysisResults.fileSignatures.length === 0) {
    alert('No embedded file signatures detected. Run analysis first or switch to Aggressive mode.');
    return;
  }
  
  alert(`Attempting to extract ${analysisResults.fileSignatures.length} embedded file(s)...`);
  
  analysisResults.fileSignatures.forEach(sig => {
    try {
      // Extract from the signature offset to the end of the file
      const extractedData = currentImageBinary.slice(sig.offset);
      const filename = `embedded-file-at-${sig.hexOffset}.${sig.extensions[0] || 'bin'}`;
      downloadFile(extractedData, filename, 'application/octet-stream');
    } catch (e) {
      console.error(`Failed to extract file at ${sig.hexOffset}:`, e);
      alert(`Failed to extract file at ${sig.hexOffset}: ${e.message}`);
    }
  });
}

function extractCustomPattern() {
  const pattern = prompt('Enter hex pattern to search (e.g., 504B0304 for ZIP):');
  if (!pattern) return;
  
  if (!currentImageBinary) {
    alert('Please upload an image first');
    return;
  }
  
  // Search in the first 1MB for performance
  const searchLimit = Math.min(currentImageBinary.length, 1024*1024);
  const hex = Array.from(currentImageBinary.slice(0, searchLimit))
    .map(b => b.toString(16).padStart(2,'0')).join('').toUpperCase();
  
  const idx = hex.indexOf(pattern.toUpperCase());
  if (idx !== -1 && idx % 2 === 0) { // Ensure it's on a byte boundary
    const byteOffset = (idx / 2) | 0;
    alert(`Pattern found at byte offset: ${byteOffset} (0x${byteOffset.toString(16)})`);
  } else {
    alert('Pattern not found in first 1MB of image data');
  }
}

// === Visual Analysis Functions ===
function showChannelAnalysis(channel) {
  const resultEl = document.getElementById('visualResults');
  if (!resultEl) return;
  
  if (!currentImageBinary || !currentImageSrc) {
    resultEl.innerHTML = '<p style="color: red; padding: 16px;">Please upload an image first</p>';
    return;
  }
  
  if (channel === 'histogram') {
    resultEl.innerHTML = `
      <div class="detection-result">
        <p>📊 <strong>Channel Histograms</strong></p>
        <p style="margin-top: 16px; color: #666;">
          <em>This feature is not yet implemented. It would show a statistical distribution of pixel values for the R, G, and B channels. Irregular patterns in a histogram can sometimes indicate steganography.</em>
        </p>
      </div>
    `;
    return;
  }
  
  resultEl.innerHTML = `<div class="progress-text" style="padding: 16px;">🎨 Generating ${channel} visualization...</div>`;

  const img = new Image();
  img.onload = () => {
    const canvas = document.createElement('canvas');
    const ctx = canvas.getContext('2d');
    
    // Scale canvas for display
    const maxWidth = resultEl.clientWidth > 0 ? resultEl.clientWidth : 600;
    const scale = Math.min(1, maxWidth / img.width);
    canvas.width = img.width * scale;
    canvas.height = img.height * scale;
    
    // Draw original image scaled
    ctx.drawImage(img, 0, 0, canvas.width, canvas.height);
    
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const pixels = imageData.data;

    let title = '';

    for (let i = 0; i < pixels.length; i += 4) {
      const r = pixels[i];
      const g = pixels[i+1];
      const b = pixels[i+2];

      switch (channel) {
        case 'red':
          title = '🔴 Red Channel Analysis';
          pixels[i+1] = 0; // green
          pixels[i+2] = 0; // blue
          break;
        case 'green':
          title = '🟢 Green Channel Analysis';
          pixels[i] = 0;   // red
          pixels[i+2] = 0; // blue
          break;
        case 'blue':
          title = '🔵 Blue Channel Analysis';
          pixels[i] = 0;   // red
          pixels[i+1] = 0; // green
          break;
        case 'lsb':
          title = '👁️ LSB Visualization';
          // Amplify the LSB of each channel
          pixels[i] = (r & 1) * 255;
          pixels[i+1] = (g & 1) * 255;
          pixels[i+2] = (b & 1) * 255;
          break;
      }
    }
    
    ctx.putImageData(imageData, 0, 0);
    
    resultEl.innerHTML = `
      <div class="detection-result">
        <h3>${title}</h3>
        <p>This image shows the isolated ${channel} data. Patterns or noise may indicate hidden information.</p>
        <canvas id="visualAnalysisCanvas" style="width: 100%; height: auto; margin-top: 16px; border-radius: 8px; border: 1px solid var(--color-card-border);"></canvas>
      </div>
    `;
    
    // Replace the placeholder canvas with the one we drew on
    const finalCanvas = document.getElementById('visualAnalysisCanvas');
    if (finalCanvas) {
        const finalCtx = finalCanvas.getContext('2d');
        finalCanvas.width = canvas.width;
        finalCanvas.height = canvas.height;
        finalCtx.drawImage(canvas, 0, 0);
    }
  };
  
  img.onerror = () => {
    resultEl.innerHTML = '<p style="color: red; padding: 16px;">Error: Could not load image for visual analysis.</p>';
  };
  
  img.src = currentImageSrc;
}


// === App Initialization ===
(function init() {
  const modeSel = document.getElementById('detectionMode');
  const thrSel  = document.getElementById('confidenceThreshold');
  const ctxSel  = document.getElementById('contextValidation');

  // Settings listeners
  if (modeSel) modeSel.addEventListener('change', (e) => {
    const m = e.target.value || 'conservative';
    detectionSettings.mode = m;
    const cfg = DETECTION_MODES[m] || DETECTION_MODES.conservative;
    detectionSettings.confidenceThreshold = cfg.confidenceThreshold;
    detectionSettings.contextValidation   = cfg.contextValidation;
    // Re-run analysis if a file is loaded
    if (currentFile) startAnalysis();
  });

  if (thrSel) thrSel.addEventListener('change', (e) => {
    const v = parseFloat(e.target.value);
    if (!Number.isNaN(v)) detectionSettings.confidenceThreshold = v;
    if (currentFile) startAnalysis();
  });

  if (ctxSel) ctxSel.addEventListener('change', (e) => {
    detectionSettings.contextValidation = (e.target.value === 'enabled');
    if (currentFile) startAnalysis();
  });

  // File upload listeners
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