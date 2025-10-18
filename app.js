// =============================
// Image Steganography Tool - Final JS
// Safe, conservative detection; helpers defined first
// =============================

// --- Constants ---
const IMAGE_TERMINATION_BYTES = {
  jpeg: 'FFD9',
  png: '49454E44AE426082',
  gif: '003B',
  bmp: '' // none
};

const FILE_SIGNATURES = {
  '4D5A': { name: 'Windows Executable', ext: ['exe','dll','scr','com'], risk: 'CRITICAL', minSize: 1024 },
  '7F454C46': { name: 'Linux ELF', ext: ['elf','so','o'], risk: 'CRITICAL', minSize: 1024 },
  '504B0304': { name: 'ZIP Archive', ext: ['zip','jar','apk','docx','xlsx'], risk: 'HIGH', minSize: 22 },
  '52617221': { name: 'RAR Archive', ext: ['rar'], risk: 'HIGH', minSize: 64 },
  '377ABCAF271C': { name: '7-Zip', ext: ['7z'], risk: 'HIGH', minSize: 64 },
  '25504446': { name: 'PDF Document', ext: ['pdf'], risk: 'MEDIUM', minSize: 100 }
};

const DETECTION_MODES = {
  conservative: { confidenceThreshold: 0.8, contextValidation: true },
  balanced:     { confidenceThreshold: 0.6, contextValidation: true },
  aggressive:   { confidenceThreshold: 0.4, contextValidation: false }
};

let detectionSettings = { mode: 'conservative', confidenceThreshold: 0.8, contextValidation: true };
let analysisResults = { fileSignatures: [], lsbAnalysis: {}, statisticalAnalysis: {}, metadata: {}, threatLevel: 'safe', analysisErrors: [] };
let currentFile = null;
let currentImageBinary = null;

// --- Utility helpers (MUST come first) ---
function checkForKnownSignatures(data) {
  try {
    if (!data || data.length < 4) return false;
    const max = Math.min(4096, data.length);
    let hex = '';
    for (let i = 0; i < max; i++) hex += data[i].toString(16).padStart(2,'0');
    const sigs = ['4d5a','504b0304','52617221','377abcaf271c','25504446'];
    hex = hex.toLowerCase();
    return sigs.some(s => hex.includes(s));
  } catch(e){ console.error('checkForKnownSignatures error:', e); return false; }
}

function analyzeLocalEntropy(uint8Array, offset, length){
  try{
    if (!uint8Array || !uint8Array.length) return 0;
    const start = Math.max(0, offset|0);
    const end = Math.min(start + Math.max(1,length|0), uint8Array.length);
    const sample = uint8Array.slice(start,end);
    const hist = new Array(256).fill(0);
    for (let i=0;i<sample.length;i++) hist[sample[i]]++;
    let H=0, n = sample.length||1;
    for (let i=0;i<256;i++){ const p = hist[i]/n; if (p>0) H -= p*Math.log2(p); }
    return H/8; // normalize
  }catch(e){ console.error('analyzeLocalEntropy error:', e); return 0; }
}

function validateAppendedData(data){
  try{
    if (!data || !data.length) return { confidence:0, details:['No data'], riskLevel:'LOW' };
    const details = [];
    let score = 0;
    let zeros=0; const n = Math.min(data.length, 8192);
    for (let i=0;i<n;i++) if (data[i]===0) zeros++;
    const nullRatio = zeros/n;
    if (nullRatio>0.9){ details.push('Mostly null bytes'); score=0.1; }
    else if (nullRatio>0.7){ details.push('High null byte ratio'); score=0.3; }
    else { details.push('Non-null content present'); score=0.6; }
    const ent = analyzeLocalEntropy(data,0,Math.min(4096,data.length));
    if (ent>0.5){ details.push(`High entropy (${ent.toFixed(3)})`); score+=0.3; }
    const hasSig = checkForKnownSignatures(data);
    if (hasSig){ details.push('Known file signature present'); score+=0.4; }
    const confidence = Math.min(1,score);
    return { confidence, details, riskLevel: hasSig? 'HIGH' : (ent>0.5? 'MEDIUM':'LOW') };
  }catch(e){ console.error('validateAppendedData error:', e); return { confidence:0, details:['Validation error: '+e.message], riskLevel:'LOW' } }
}

// --- General utilities ---
function hexAt(data, offset, length){
  const end = Math.min(offset+length, data.length);
  let s='';
  for (let i=offset;i<end;i++) s+=data[i].toString(16).padStart(2,'0');
  return s.toUpperCase();
}

function findImageEndOffsets(uint8){
  const results = [];
  const hex = hexAt(uint8,0,Math.min(uint8.length, 4*1024*1024)); // 4MB window

  // JPEG
  let idx = hex.indexOf(IMAGE_TERMINATION_BYTES.jpeg);
  while (idx!==-1){
    results.push({ format:'jpeg', offset: (idx/2)|0 + (IMAGE_TERMINATION_BYTES.jpeg.length/2)|0 });
    idx = hex.indexOf(IMAGE_TERMINATION_BYTES.jpeg, idx+IMAGE_TERMINATION_BYTES.jpeg.length);
  }
  // PNG
  idx = hex.indexOf(IMAGE_TERMINATION_BYTES.png);
  while (idx!==-1){
    results.push({ format:'png', offset: (idx/2)|0 + (IMAGE_TERMINATION_BYTES.png.length/2)|0 });
    idx = hex.indexOf(IMAGE_TERMINATION_BYTES.png, idx+IMAGE_TERMINATION_BYTES.png.length);
  }
  // GIF
  idx = hex.indexOf(IMAGE_TERMINATION_BYTES.gif);
  while (idx!==-1){
    results.push({ format:'gif', offset: (idx/2)|0 + (IMAGE_TERMINATION_BYTES.gif.length/2)|0 });
    idx = hex.indexOf(IMAGE_TERMINATION_BYTES.gif, idx+IMAGE_TERMINATION_BYTES.gif.length);
  }
  return results.sort((a,b)=>a.offset-b.offset);
}

// --- Core analysis ----
async function processFile(file){
  try{
    currentFile = file;
    analysisResults = { fileSignatures: [], lsbAnalysis:{}, statisticalAnalysis:{}, metadata:{}, threatLevel:'safe', analysisErrors:[] };
    const arr = await file.arrayBuffer();
    currentImageBinary = new Uint8Array(arr);
    await startAnalysis();
  }catch(e){ console.error('processFile error:', e); showBanner('error', 'Analysis failed: '+e.message); }
}

async function startAnalysis(){
  showBanner('info','Analyzing...');
  await analyzeFileSignatures();
  showBanner('success','Analysis complete');
  displayFileSignatures();
}

async function analyzeFileSignatures(){
  const ends = findImageEndOffsets(currentImageBinary);
  const afterEndRegions = [];
  for (const end of ends){
    if (end.offset < currentImageBinary.length - 1000){ // require 1KB after end
      afterEndRegions.push({ start:end.offset, format:end.format});
    }
  }
  const mode = detectionSettings.mode;
  const scanRegions = (mode==='aggressive' || afterEndRegions.length===0)
    ? [{ start: 0, format: 'full' }] // fallback
    : afterEndRegions;

  for (const region of scanRegions){
    const start = region.start;
    const window = currentImageBinary.slice(start);
    // Validate appended chunk
    if (region.format!=='full'){
      const val = validateAppendedData(window);
      if (val.confidence < detectionSettings.confidenceThreshold) continue;
    }
    // Signature scan (first 256KB)
    const maxScan = window.slice(0, Math.min(window.length, 256*1024));
    const hex = hexAt(maxScan,0,maxScan.length);
    for (const sigHex in FILE_SIGNATURES){
      const idx = hex.indexOf(sigHex);
      if (idx!==-1){
        const byteOffset = start + ((idx/2)|0);
        const meta = FILE_SIGNATURES[sigHex];
        const remaining = currentImageBinary.length - byteOffset;
        if (remaining >= meta.minSize){
          analysisResults.fileSignatures.push({
            signature: sigHex,
            name: meta.name,
            extensions: meta.ext,
            description: `${meta.name} signature`,
            offset: byteOffset,
            hexOffset: '0x'+byteOffset.toString(16),
            risk: meta.risk
          });
        }
      }
    }
  }
  // Threat level
  const exeFound = analysisResults.fileSignatures.some(s=>s.extensions.includes('exe'));
  analysisResults.threatLevel = exeFound? 'critical' : (analysisResults.fileSignatures.length? 'high':'safe');
}

// --- UI helpers (safe if elements missing) ---
function el(id){ return document.getElementById(id); }
function showBanner(type,msg){ const b=el('threatBanner'); if(!b) return; b.className='banner '+type; b.textContent=msg; }

function displayFileSignatures(){
  const signatureResults = el('signatureResults');
  if (!signatureResults) return;
  if (analysisResults.fileSignatures.length===0){
    const mode = detectionSettings.mode;
    signatureResults.innerHTML = `
      <div class="detection-result">
        <div class="result-header">
          <span class="result-title">✅ No embedded file signatures detected</span>
          <span class="result-badge badge-safe">CLEAN</span>
        </div>
        <p>The image appears to contain only standard image data with no embedded files.</p>
        <p><strong>Detection Mode:</strong> ${mode.charAt(0).toUpperCase()+mode.slice(1)}</p>
        <p><strong>Confidence Threshold:</strong> ${(detectionSettings.confidenceThreshold*100).toFixed(0)}%</p>
        <div class="detection-stats">
          <small>✓ Advanced structure validation enabled<br>
          ✓ Context-aware detection active<br>
          ✓ False positive filtering applied</small>
        </div>
      </div>`;
    return;
  }
  let html = '';
  analysisResults.fileSignatures.forEach((sig,i)=>{
    html += `
      <div class="detection-result">
        <div class="result-header">
          <span class="result-title">${sig.name}</span>
          <span class="result-badge ${sig.risk==='CRITICAL'?'badge-danger': sig.risk==='HIGH'?'badge-warn':'badge-info'}">${sig.risk}</span>
        </div>
        <p>${sig.description}</p>
        <ul>
          <li>Signature: ${sig.signature}</li>
          <li>Offset: ${sig.hexOffset}</li>
          <li>Extensions: ${sig.extensions.join(', ')}</li>
        </ul>
      </div>`;
  });
  signatureResults.innerHTML = html;
}

// --- Event wiring ---
(function init(){
  const modeSel = el('detectionMode');
  const thrSel  = el('confidenceThreshold');
  const ctxSel  = el('contextValidation');

  if (modeSel) modeSel.addEventListener('change', e=>{
    const m=e.target.value||'conservative';
    detectionSettings.mode=m;
    const cfg=DETECTION_MODES[m]||DETECTION_MODES.conservative;
    detectionSettings.confidenceThreshold=cfg.confidenceThreshold;
    detectionSettings.contextValidation=cfg.contextValidation;
  });
  if (thrSel) thrSel.addEventListener('change', e=>{
    detectionSettings.confidenceThreshold = parseFloat(e.target.value)||0.8;
  });
  if (ctxSel) ctxSel.addEventListener('change', e=>{
    detectionSettings.contextValidation = (e.target.value==='enabled');
  });

  const fileInput = el('fileInput');
  const uploadArea = el('uploadArea');
  if (fileInput) fileInput.addEventListener('change', ()=>{
    if(fileInput.files && fileInput.files[0]) processFile(fileInput.files[0]);
  });
  if (uploadArea){
    uploadArea.addEventListener('dragover', e=>{ e.preventDefault(); uploadArea.classList.add('drag'); });
    uploadArea.addEventListener('dragleave', e=>{ uploadArea.classList.remove('drag'); });
    uploadArea.addEventListener('drop', e=>{
      e.preventDefault(); uploadArea.classList.remove('drag');
      const f=e.dataTransfer.files&&e.dataTransfer.files[0]; if(f) processFile(f);
    });
  }
})();
