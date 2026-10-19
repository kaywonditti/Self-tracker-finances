/* Le mie finanze — PWA locale.
   Tutti i dati restano sul dispositivo, cifrati con AES-GCM 256 bit.
   La chiave deriva dalla password con PBKDF2-SHA256 (600.000 iterazioni) e non viene mai salvata. */
'use strict';

/* ======================= Utilità ======================= */
const $ = (sel) => document.querySelector(sel);
const PBKDF2_ITER = 600000;
const AUTOLOCK_MS = 5 * 60 * 1000;
const HIDDEN_LOCK_MS = 2 * 60 * 1000;

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else if (k === 'value') el.value = v;
    else if (k === 'checked' || k === 'selected') el[k] = !!v;
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return el;
}

// useGrouping 'always': in italiano il browser altrimenti scrive 1850,00 invece di 1.850,00
const eur = new Intl.NumberFormat('it-IT', { style: 'currency', currency: 'EUR', useGrouping: 'always' });
const eurSigned = new Intl.NumberFormat('it-IT', { style: 'currency', currency: 'EUR', signDisplay: 'exceptZero', useGrouping: 'always' });
const fmt = (n) => eur.format(n);
const fmtSigned = (n) => eurSigned.format(n);
const eur0 = new Intl.NumberFormat('it-IT', { style: 'currency', currency: 'EUR', maximumFractionDigits: 0, useGrouping: 'always' });

function monthLabel(ym) {
  const [y, m] = ym.split('-').map(Number);
  const s = new Intl.DateTimeFormat('it-IT', { month: 'long', year: 'numeric' }).format(new Date(y, m - 1, 1));
  return s.charAt(0).toUpperCase() + s.slice(1);
}
function monthShort(ym) {
  const [y, m] = ym.split('-').map(Number);
  return new Intl.DateTimeFormat('it-IT', { month: 'short' }).format(new Date(y, m - 1, 1)) + ' ' + String(y).slice(2);
}
function dateLabel(iso) {
  const [y, m, d] = iso.split('-').map(Number);
  return new Intl.DateTimeFormat('it-IT', { day: 'numeric', month: 'short', year: 'numeric' }).format(new Date(y, m - 1, d));
}

let toastTimer;
function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => t.classList.remove('show'), 3500);
}

/* Finestra modale. actions: [{label, cls, value, onClick}] — onClick può restituire false per lasciarla aperta. */
function openModal({ title, body, actions }) {
  const dlg = $('#modal');
  $('#modal-title').textContent = title;
  const b = $('#modal-body');
  b.replaceChildren(...[].concat(body || []));
  const a = $('#modal-actions');
  return new Promise((resolve) => {
    let done = false;
    const finish = (v) => { if (done) return; done = true; if (dlg.open) dlg.close(); resolve(v); };
    a.replaceChildren(...actions.map((act) => h('button', {
      class: 'btn ' + (act.cls || ''),
      onclick: async (e) => {
        e.preventDefault();
        if (act.onClick) {
          const r = await act.onClick();
          if (r === false) return;
        }
        finish(act.value);
      },
    }, act.label)));
    dlg.onclose = () => finish(null);
    dlg.showModal();
    const first = b.querySelector('input');
    if (first) first.focus();
  });
}
function closeModal() { const d = $('#modal'); if (d.open) d.close(); }

/* ======================= Crittografia ======================= */
const enc = new TextEncoder();
const dec = new TextDecoder();
function b64(buf) {
  const bytes = new Uint8Array(buf);
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(s);
}
function unb64(str) {
  const s = atob(str);
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i);
  return out;
}
async function deriveKey(password, salt, iter = PBKDF2_ITER) {
  const base = await crypto.subtle.importKey('raw', enc.encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: iter, hash: 'SHA-256' },
    base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']);
}
async function encryptJSON(key, obj) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, enc.encode(JSON.stringify(obj)));
  return { iv: b64(iv), data: b64(ct) };
}
async function decryptJSON(key, iv, data) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(iv) }, key, unb64(data));
  return JSON.parse(dec.decode(pt));
}
async function sha256hex(str) {
  const d = await crypto.subtle.digest('SHA-256', enc.encode(str));
  return Array.from(new Uint8Array(d), (x) => x.toString(16).padStart(2, '0')).join('');
}

/* ======================= Archivio locale (IndexedDB) ======================= */
function idb() {
  return new Promise((res, rej) => {
    const r = indexedDB.open('le-mie-finanze', 1);
    r.onupgradeneeded = () => r.result.createObjectStore('vault');
    r.onsuccess = () => res(r.result);
    r.onerror = () => rej(r.error);
  });
}
async function idbGet(k) {
  const db = await idb();
  return new Promise((res, rej) => {
    const r = db.transaction('vault').objectStore('vault').get(k);
    r.onsuccess = () => res(r.result); r.onerror = () => rej(r.error);
  });
}
async function idbPut(k, v) {
  const db = await idb();
  return new Promise((res, rej) => {
    const t = db.transaction('vault', 'readwrite');
    t.objectStore('vault').put(v, k);
    t.oncomplete = () => res(); t.onerror = () => rej(t.error);
  });
}
async function idbDel(k) {
  const db = await idb();
  return new Promise((res, rej) => {
    const t = db.transaction('vault', 'readwrite');
    t.objectStore('vault').delete(k);
    t.oncomplete = () => res(); t.onerror = () => rej(t.error);
  });
}

/* ======================= Stato ======================= */
let state = null;   // dati in chiaro, solo in memoria mentre l'app è sbloccata
let cryptoKey = null;
let vaultSalt = null;
let currentMonth = null;
let saveChain = Promise.resolve();

const OTHER_OUT = 'altre-uscite';
const OTHER_IN = 'altre-entrate';

function defaultCategories() {
  const C = (id, name, type, color, kw) => ({ id, name, type, color, keywords: kw.split(',').map((s) => s.trim()).filter(Boolean) });
  return [
    C('spesa', 'Spesa alimentare', 'out', '#1BAF7A', 'ESSELUNGA, CONAD, COOP, IPERCOOP, CARREFOUR, LIDL, EUROSPIN, PAM, PANORAMA, IPER, PENNY, ALDI, MD, SUPERMERCATO, SUPERMERCATI, U2, TIGROS, BENNET, NATURASI, CRAI, DESPAR, SIGMA, UNES, IL GIGANTE, FAMILA, SIMPLY, DOK'),
    C('ristoranti', 'Ristoranti e bar', 'out', '#EB6834', 'RISTORANTE, PIZZERIA, TRATTORIA, OSTERIA, BAR, CAFFE, CAFFETTERIA, PASTICCERIA, GELATERIA, PANETTERIA, PANIFICIO, MCDONALD, BURGER KING, KFC, OLD WILD WEST, ROADHOUSE, DELIVEROO, JUST EAT, GLOVO, SUSHI, STARBUCKS, AUTOGRILL, SPONTINI, POKE'),
    C('trasporti', 'Trasporti e auto', 'out', '#2A78D6', 'ENI, Q8, IP, TAMOIL, ESSO, SHELL, CARBURANTE, CARBURANTI, DISTRIBUTORE, TELEPASS, AUTOSTRADE, AUTOSTRADA, ATM, ATM MILANO, TRENITALIA, ITALO, TRENORD, FRECCIAROSSA, UBER, FREE NOW, TAXI, PARCHEGGIO, EASYPARK, MYCICERO, SHARE NOW, BIKEMI, RYANAIR, EASYJET, ITA AIRWAYS, BOLLO AUTO, ASSICURAZIONE AUTO, RCA AUTO'),
    C('casa', 'Casa e utenze', 'out', '#4A3AA7', 'ENEL, A2A, IREN, HERA, EDISON, SORGENIA, ACEA, PLENITUDE, ENI PLENITUDE, ILLUMIA, OCTOPUS, GAS, LUCE, ACQUA, CONDOMINIO, AFFITTO, CANONE LOCAZIONE, TARI, MUTUO, RATA MUTUO, ASSICURAZIONE CASA'),
    C('telefono', 'Telefono e internet', 'out', '#E87BA4', 'TIM, TELECOM, VODAFONE, WINDTRE, WIND TRE, ILIAD, FASTWEB, HO MOBILE, VERY MOBILE, KENA, POSTEMOBILE, LYCA, SPUSU, COOP VOCE'),
    C('abbonamenti', 'Abbonamenti e svago', 'out', '#E34948', 'NETFLIX, SPOTIFY, AMAZON PRIME, PRIME VIDEO, DISNEY, DAZN, SKY, NOW TV, APPLE COM, ITUNES, GOOGLE PLAY, YOUTUBE, PLAYSTATION, STEAM, NINTENDO, XBOX, CINEMA, UCI, THE SPACE, PALESTRA, MCFIT, VIRGIN ACTIVE'),
    C('shopping', 'Shopping', 'out', '#EDA100', 'AMAZON, AMZN, ZALANDO, ZARA, H&M, DECATHLON, IKEA, MEDIAWORLD, UNIEURO, EURONICS, EBAY, SHEIN, PRIMARK, OVS, TEMU, LEROY MERLIN, BRICOMAN, OBI, TIGOTA, ACQUA E SAPONE, DOUGLAS, SEPHORA'),
    C('salute', 'Salute', 'out', '#008300', 'FARMACIA, PARAFARMACIA, OSPEDALE, POLIAMBULATORIO, CENTRO MEDICO, MEDICO, DENTISTA, STUDIO DENTISTICO, ASL, ATS, TICKET, OTTICA, OTTICO, LABORATORIO ANALISI, SYNLAB, CDI'),
    C('banca', 'Tasse, banca e commissioni', 'out', '#8A6A4A', 'F24, IMPOSTA DI BOLLO, BOLLO, COMMISSIONI, COMMISSIONE, CANONE MENSILE, SPESE TENUTA CONTO, COMPETENZE, INTERESSI DEBITORI, AGENZIA DELLE ENTRATE, PAGOPA, MULTA'),
    C('prelievi', 'Prelievi contanti', 'out', '#7A786F', 'PRELIEVO, PRELEVAMENTO, PRELIEVO BANCOMAT, PRELIEVO CONTANTI'),
    C(OTHER_OUT, 'Altre uscite', 'out', '#A9A8A2', ''),
    C('stipendio', 'Stipendio e pensione', 'in', '#2A78D6', 'STIPENDIO, EMOLUMENTI, RETRIBUZIONE, CEDOLINO, PENSIONE, INPS, TFR, BUSTA PAGA, MENSILITA'),
    C(OTHER_IN, 'Altre entrate', 'in', '#1BAF7A', ''),
  ];
}
// Colori predefiniti della versione precedente: se l'utente non li ha cambiati, passano ai nuovi
const OLD_COLORS = {
  spesa: '#2F8F6F', ristoranti: '#D08C2B', trasporti: '#4F6DB8', casa: '#8A5BB0', telefono: '#3A9BC1', abbonamenti: '#C2577E',
  shopping: '#C9A227', salute: '#6E8B3D', banca: '#B4432E', prelievi: '#7A6A58', [OTHER_OUT]: '#9A9A9A', stipendio: '#0E7A55', [OTHER_IN]: '#5C9E8A',
};
function migrateState(s) {
  const defs = new Map(defaultCategories().map((c) => [c.id, c.color]));
  for (const c of s.categories || []) {
    if (OLD_COLORS[c.id] && String(c.color).toUpperCase() === OLD_COLORS[c.id] && defs.has(c.id)) c.color = defs.get(c.id);
  }
  return s;
}
function newState() {
  return { version: 1, updatedAt: Date.now(), categories: defaultCategories(), learned: {}, tx: [] };
}
function catById(id) { return state.categories.find((c) => c.id === id); }

function saveState() {
  state.updatedAt = Date.now();
  const snapshot = JSON.parse(JSON.stringify(state));
  saveChain = saveChain.then(async () => {
    if (!cryptoKey) return;
    const { iv, data } = await encryptJSON(cryptoKey, snapshot);
    await idbPut('main', { v: 1, iter: PBKDF2_ITER, salt: b64(vaultSalt), iv, data });
  }).catch((e) => { console.error(e); toast('Salvataggio non riuscito: ' + e.message); });
  return saveChain;
}

/* ======================= Categorie automatiche ======================= */
function norm(s) {
  return ' ' + (s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toUpperCase()
    .replace(/[^A-Z0-9&]+/g, ' ').trim() + ' ';
}
const STOP = new Set(('PAGAMENTO PAGAM PAG POS CARTA CARTE DI DEL DELLA DEI DA A AL ALLE ALLA IN SU PER PRESSO EUR EURO ' +
  'OPERAZIONE OP ADDEBITO ACCREDITO DIRETTO SDD SEPA CORE BONIFICO BON ORDINANTE BENEFICIARIO FAVORE VS VOSTRO VOSTRA ' +
  'N NR NUM RIF COD ID CRO TRN DATA ORE H ESTERO ITA IT CONTACTLESS MASTERCARD VISA MAESTRO DEBIT PAGOBANCOMAT NEXI ' +
  'CIRCUITO INTERNAZIONALE SRL SPA S R L P IL LA LO E CON TRAMITE WEB INTERNET ISTANTANEO ORDINE MANDATO').split(' '));

// Parte fissa dei pagamenti con carta ("Operazione ... del gg.mm.aa hh:mm Carta *NNNN"): non è il nome del negozio
const RE_CARD_PREFIX = /^.*?\bDEL\s+\d{1,2}[./]\d{1,2}[./]\d{2,4}(?:\s+\d{1,2}[:.]\d{2})?\s+(?:\S+\s+)?\*+\d{3,4}\b/i;
function merchantKey(tx) {
  const desc = (tx.desc || '').replace(RE_CARD_PREFIX, '');
  for (const src of [desc, tx.causale]) {
    const words = norm(src).trim().split(' ').filter((w) => w && !/\d/.test(w) && !STOP.has(w) && w.length > 1);
    if (words.length) return words.slice(0, 3).join(' ');
  }
  return null;
}
function guessCategory(tx) {
  const key = merchantKey(tx);
  if (key && state.learned[key] && catById(state.learned[key])) return state.learned[key];
  const type = tx.amount >= 0 ? 'in' : 'out';
  const text = norm(tx.causale + ' ' + tx.desc);
  let best = null; let bestLen = 0;
  for (const c of state.categories) {
    if (c.type !== type) continue;
    for (const kw of c.keywords) {
      const k = norm(kw);
      if (k.length > 2 && k.length > bestLen && text.includes(k)) { best = c.id; bestLen = k.length; }
    }
  }
  return best || (type === 'in' ? OTHER_IN : OTHER_OUT);
}
function recategorize() {
  for (const tx of state.tx) {
    if (tx.manual && catById(tx.cat)) continue;
    tx.manual = false;
    tx.cat = guessCategory(tx);
  }
}

/* ======================= Lettura del PDF ======================= */
let pdfReady = null;
function loadScript(src) {
  return new Promise((res, rej) => {
    const s = document.createElement('script');
    s.src = src; s.onload = res; s.onerror = () => rej(new Error('Impossibile caricare ' + src));
    document.head.append(s);
  });
}
function loadPdfLib() {
  // Il "worker" di pdf.js viene caricato nella pagina stessa: così funziona anche aprendo il file direttamente dal PC.
  if (!pdfReady) {
    pdfReady = Promise.all([loadScript('lib/pdf.worker.min.js'), loadScript('lib/pdf.min.js')]).then(() => {
      window.pdfjsLib.GlobalWorkerOptions.workerSrc = 'lib/pdf.worker.min.js';
    });
  }
  return pdfReady;
}

const RE_DATE = /^(\d{1,2})[/.\-](\d{1,2})[/.\-](\d{4}|\d{2})$/;
const RE_AMOUNT = /^([-+]?)(\d{1,3}(?:\.\d{3})+|\d+),(\d{2})([-+]?)$/;
const RE_FOOTER = /\b(SALDO|TOTALE|TOTALI|PAGINA|RIEPILOGO)\b/;

function parseDate(t) {
  const m = RE_DATE.exec(t);
  if (!m) return null;
  let [, d, mo, y] = m; d = +d; mo = +mo; y = +y;
  if (y < 100) y += 2000;
  if (mo < 1 || mo > 12 || d < 1 || d > 31) return null;
  return `${y}-${String(mo).padStart(2, '0')}-${String(d).padStart(2, '0')}`;
}
function parseAmount(t) {
  const m = RE_AMOUNT.exec(t.replace(/\u2212/g, '-').replace(/€|EUR/gi, ''));
  if (!m) return null;
  const v = parseFloat(m[2].replace(/\./g, '') + '.' + m[3]);
  return (m[1] === '-' || m[4] === '-') ? -v : v;
}

/* Estrae le righe di testo del PDF, ciascuna con le parole e la loro posizione orizzontale */
async function extractRows(file) {
  await loadPdfLib();
  const data = new Uint8Array(await file.arrayBuffer());
  const doc = await window.pdfjsLib.getDocument({
    data, isEvalSupported: false, disableFontFace: true, disableAutoFetch: true, disableStream: true, verbosity: 0,
  }).promise;
  const rows = [];
  try {
    for (let p = 1; p <= doc.numPages; p++) {
      const page = await doc.getPage(p);
      const tc = await page.getTextContent();
      // Coordinate come appaiono a schermo: alcune banche producono pagine ruotate (orizzontali)
      const vp = page.getViewport({ scale: 1 });
      const items = tc.items.filter((it) => it.str && it.str.trim()).map((it) => {
        const m = window.pdfjsLib.Util.transform(vp.transform, it.transform);
        return { x: m[4], y: vp.height - m[5], w: it.width || 0, h: Math.abs(it.height || it.transform[3] || 8), str: it.str };
      });
      items.sort((a, b) => b.y - a.y || a.x - b.x);
      const pageRows = [];
      for (const it of items) {
        const tol = Math.max(2, it.h * 0.45);
        let row = pageRows.find((r) => Math.abs(r.y - it.y) <= tol);
        if (!row) { row = { page: p, y: it.y, h: it.h, items: [] }; pageRows.push(row); }
        row.items.push(it);
      }
      pageRows.sort((a, b) => b.y - a.y);
      for (const r of pageRows) {
        r.items.sort((a, b) => a.x - b.x);
        r.tokens = [];
        for (const it of r.items) {
          const re = /\S+/g; let m;
          while ((m = re.exec(it.str))) {
            const x = it.x + (it.str.length ? it.w * (m.index / it.str.length) : 0);
            r.tokens.push({ x, y: it.y, h: it.h, t: m[0] });
          }
        }
        r.text = r.tokens.map((t) => t.t).join(' ');
        rows.push(r);
      }
      page.cleanup();
    }
  } finally {
    doc.destroy();
  }
  return rows;
}

/* Riconosce l'intestazione della tabella per sapere dove iniziano le colonne Causale e Descrizione */
function readHeader(row) {
  const up = norm(row.text);
  if (!(up.includes(' IMPORTO ') && (up.includes(' DESCRIZIONE ') || up.includes(' CAUSALE ')))) return null;
  const find = (re) => { const t = row.tokens.find((k) => re.test(norm(k.t).trim())); return t ? t.x : null; };
  return { importo: find(/^IMPORTO/), causale: find(/^CAUSALE/), descrizione: find(/^DESCRIZIONE/), valuta: find(/^VALUTA/) };
}

/* Assegna le righe di testo di una colonna ai movimenti della stessa pagina.
   Funziona sia se il testo sta sotto la riga con le date sia se è centrato in verticale:
   tra due movimenti il confine è lo spazio vuoto più ampio tra le righe. */
function assignColumn(anchors, tokens, field) {
  if (!anchors.length || !tokens.length) return;
  const lines = [];
  for (const t of [...tokens].sort((a, b) => b.y - a.y || a.x - b.x)) {
    const ln = lines.find((l) => Math.abs(l.y - t.y) <= 1.5);
    if (ln) ln.tokens.push(t); else lines.push({ y: t.y, h: t.h, tokens: [t] });
  }
  lines.sort((a, b) => b.y - a.y);
  const parts = anchors.map(() => []);
  const near = (ln, a) => Math.abs(ln.y - a.y) <= Math.max(1.5, ln.h * 0.45);
  const step = (ln) => Math.max(ln.h, 6) * 1.8;   // distanza massima tra righe dello stesso movimento
  const first = anchors[0]; const lastA = anchors[anchors.length - 1];
  // Righe sopra il primo movimento (solo se attaccate) e sotto l'ultimo
  let edge = first.y;
  for (const ln of lines.filter((l) => l.y > first.y && !near(l, first)).reverse()) {
    if (ln.y - edge > step(ln)) break;
    parts[0].push(ln); edge = ln.y;
  }
  edge = lastA.y;
  for (const ln of lines.filter((l) => l.y < lastA.y && !near(l, lastA))) {
    if (edge - ln.y > step(ln)) break;
    parts[anchors.length - 1].push(ln); edge = ln.y;
  }
  anchors.forEach((a, i) => {
    for (const ln of lines) if (near(ln, a)) parts[i].push(ln);
    const b = anchors[i + 1];
    if (!b) return;
    const mid = lines.filter((l) => l.y < a.y && l.y > b.y && !near(l, a) && !near(l, b));
    const ys = [a.y, ...mid.map((l) => l.y), b.y];
    let cut = 0; let best = -1;
    for (let k = 0; k < ys.length - 1; k++) { const g = ys[k] - ys[k + 1]; if (g >= best) { best = g; cut = k; } }
    mid.forEach((l, k) => parts[k < cut ? i : i + 1].push(l));
  });
  anchors.forEach((a, i) => {
    const text = parts[i].sort((p, q) => q.y - p.y)
      .map((l) => l.tokens.sort((p, q) => p.x - q.x).map((t) => t.t).join(' ')).join(' ');
    a.tx[field] = text;
  });
}

function parseStatement(rows) {
  const found = [];
  let header = null;
  const warnings = [];
  let page = 0;
  let anchors = [];     // movimenti della pagina corrente, con la loro riga
  let textTok = [];     // parole delle colonne Causale/Descrizione della pagina corrente

  // Assegna il testo raccolto ai movimenti (a fine pagina, o prima di un'intestazione / riga di saldo)
  const flushPage = () => {
    if (header && header.descrizione != null) {
      assignColumn(anchors, textTok.filter((t) => t.x < header.descrizione - 3), 'causale');
      assignColumn(anchors, textTok.filter((t) => t.x >= header.descrizione - 3), 'desc');
    } else {
      assignColumn(anchors, textTok, 'desc');
    }
    anchors = []; textTok = [];
  };

  for (const row of rows) {
    if (row.page !== page) { flushPage(); page = row.page; }
    const hd = readHeader(row);
    if (hd) { flushPage(); header = hd; continue; }
    const textStart = header ? Math.min(...[header.causale, header.descrizione].filter((v) => v != null)) : null;
    const tk = row.tokens;

    // Cerca le date (contabile e valuta) all'inizio della riga
    const dates = [];
    for (let i = 0; i < tk.length && dates.length < 2; i++) {
      const d = parseDate(tk[i].t);
      if (d && (textStart == null || tk[i].x < textStart - 3)) {
        if (dates.length === 0 || i <= dates[0].i + 2) dates.push({ i, d });
        else break;
      }
    }

    if (dates.length) {
      let i = dates[dates.length - 1].i + 1;
      let sign = '';
      let amount = null; let amtIdx = -1;
      for (; i < tk.length; i++) {
        const t = tk[i].t;
        if (t === '€' || /^EUR$/i.test(t)) continue;
        if (t === '-' || t === '+' || t === '\u2212') { sign = t === '+' ? '' : '-'; continue; }
        const a = parseAmount(t);
        if (a !== null) { amount = sign === '-' ? -Math.abs(a) : a; amtIdx = i; }
        break;
      }
      if (amount !== null && (textStart == null || tk[amtIdx].x < textStart - 3)) {
        const rest = tk.slice(amtIdx + 1).filter((t) => t.t !== '€' && !/^EUR$/i.test(t.t));
        const tx = {
          date: dates[0].d,
          valuta: dates[1] ? dates[1].d : dates[0].d,
          amount: Math.round(amount * 100) / 100,
          causale: '',
          desc: '',
          twoDates: dates.length === 2,
        };
        const limit = textStart != null ? textStart - 3 : (rest.length ? rest[0].x - 3 : Infinity);
        found.push(tx); anchors.push({ tx, y: tk[dates[0].i].y, limit });
        textTok.push(...tk.filter((t) => t.x >= limit && !(t.t === '€' || /^EUR$/i.test(t.t))));
        continue;
      }
    }

    // Altre righe: testo che continua nelle colonne Causale/Descrizione, oppure saldo / piè di pagina
    const limit = textStart != null ? textStart - 3 : (anchors.length ? Math.min(...anchors.map((a) => a.limit)) : Infinity);
    const left = tk.filter((t) => t.x < limit);
    if (left.length && (RE_FOOTER.test(norm(left.map((t) => t.t).join(' '))) || left.some((t) => parseAmount(t.t) !== null))) {
      flushPage();
      continue;
    }
    textTok.push(...tk.filter((t) => t.x >= limit));
  }
  flushPage();

  // Se esistono righe con due date, scarta quelle con una sola (di solito saldi o totali)
  let result = found;
  if (found.some((t) => t.twoDates)) result = found.filter((t) => t.twoDates);
  if (result.length && !result.some((t) => t.amount < 0)) {
    warnings.push('Nessun importo negativo trovato: se il PDF non indica il segno delle uscite, dopo il salvataggio puoi invertirlo con il pulsante ± nella scheda Movimenti.');
  }
  if (result.length && !header) {
    warnings.push("Non ho trovato l'intestazione della tabella: causale e descrizione sono state unite in un solo campo.");
  }
  return { tx: result.map(({ twoDates, ...t }) => t), warnings };
}

async function assignIds(list) {
  const seen = {};
  for (const t of list) {
    const base = `${t.date}|${t.amount.toFixed(2)}|${norm(t.causale + ' ' + t.desc).trim()}`;
    seen[base] = (seen[base] || 0) + 1;
    t.id = (await sha256hex(base + '|' + seen[base])).slice(0, 24);
  }
}

/* ======================= Importazione PDF ======================= */
async function importPdfs(files) {
  if (!files.length) return;
  const btns = [$('#import-btn'), $('#empty-import')];
  btns.forEach((b) => { b.disabled = true; });
  toast('Lettura del PDF in corso…');
  const all = []; const warnings = []; const failed = [];
  try {
    for (const f of files) {
      try {
        const rows = await extractRows(f);
        const r = parseStatement(rows);
        if (!r.tx.length) failed.push(f.name);
        all.push(...r.tx);
        r.warnings.forEach((w) => warnings.push(f.name + ': ' + w));
      } catch (e) {
        console.error(e);
        failed.push(f.name + ' (' + (e.message || 'file non leggibile') + ')');
      }
    }
  } finally {
    btns.forEach((b) => { b.disabled = false; });
  }

  if (!all.length) {
    await openModal({
      title: 'Nessun movimento trovato',
      body: [
        h('p', null, "Non sono riuscito a riconoscere la tabella dei movimenti in: " + failed.join(', ') + '.'),
        h('p', { class: 'small muted' }, "Apri Backup → Diagnostica lettura PDF per vedere come l'app legge il file."),
      ],
      actions: [{ label: 'Chiudi', cls: 'primary', value: true }],
    });
    return;
  }

  await assignIds(all);
  const existing = new Set(state.tx.map((t) => t.id));
  const fresh = all.filter((t) => !existing.has(t.id));
  fresh.forEach((t) => { t.manual = false; t.cat = guessCategory(t); });
  const dupes = all.length - fresh.length;
  const months = [...new Set(fresh.map((t) => t.date.slice(0, 7)))].sort();

  const body = [];
  body.push(h('p', null,
    `Trovati ${all.length} movimenti` + (months.length ? ` (${months.map(monthLabel).join(', ')})` : '') + '.' +
    (dupes ? ` ${dupes} erano già presenti e verranno ignorati.` : '')));
  failed.forEach((f) => body.push(h('div', { class: 'warn' }, 'Non letto: ' + f)));
  warnings.forEach((w) => body.push(h('div', { class: 'warn' }, w)));
  if (fresh.length) {
    body.push(h('div', { class: 'preview-table-wrap' }, h('table', { class: 'preview-table' },
      h('thead', null, h('tr', null, h('th', null, 'Data'), h('th', null, 'Descrizione'), h('th', null, 'Categoria'), h('th', null, 'Importo'))),
      h('tbody', null, fresh.map((t) => h('tr', null,
        h('td', null, t.date.split('-').reverse().join('/')),
        h('td', null, t.desc || t.causale),
        h('td', null, catById(t.cat)?.name || ''),
        h('td', { class: 'num' }, fmtSigned(t.amount))))))));
    body.push(h('p', { class: 'small muted' }, 'Controlla qualche riga: date, importi e segni devono corrispondere al tuo estratto conto.'));
  }

  const ok = await openModal({
    title: 'Controlla i movimenti',
    body,
    actions: fresh.length
      ? [{ label: 'Annulla', value: false }, { label: `Salva ${fresh.length} movimenti`, cls: 'primary', value: true }]
      : [{ label: 'Chiudi', cls: 'primary', value: false }],
  });
  if (!ok) return;
  const now = new Date().toISOString();
  fresh.forEach((t) => { t.imported = now; });
  state.tx.push(...fresh);
  await saveState();
  currentMonth = months[months.length - 1] || currentMonth;
  renderAll();
  toast(`${fresh.length} movimenti salvati`);
}

async function diagnosePdf(file) {
  try {
    const rows = await extractRows(file);
    const parsed = parseStatement(rows);
    const lines = rows.slice(0, 80).map((r) => `p${r.page} | ` + r.tokens.map((t) => `[${Math.round(t.x)}]${t.t}`).join(' '));
    await openModal({
      title: 'Diagnostica',
      body: [
        h('p', null, `Righe di testo trovate: ${rows.length}. Movimenti riconosciuti: ${parsed.tx.length}.`),
        h('p', { class: 'small muted' }, 'Tra parentesi quadre la posizione orizzontale di ogni parola. Se condividi questo testo per un aiuto, cancella prima nomi, IBAN e numeri di conto.'),
        h('div', { class: 'diag' }, lines.join('\n')),
      ],
      actions: [{ label: 'Chiudi', cls: 'primary', value: true }],
    });
  } catch (e) {
    toast('PDF non leggibile: ' + e.message);
  }
}

/* ======================= Grafici ======================= */
/* I grafici NON vengono distrutti quando si cambia sezione: restano disegnati e vengono rifatti
   solo se cambiano i dati, il mese o il tema. Così tornando al Riepilogo sono sempre presenti. */
const charts = {};
let summaryKey = null;
function cssVar(n) { return getComputedStyle(document.documentElement).getPropertyValue(n).trim(); }
function destroyCharts() { for (const k of Object.keys(charts)) { charts[k].destroy(); delete charts[k]; } summaryKey = null; }
const isDark = () => window.matchMedia('(prefers-color-scheme: dark)').matches;
const anim = () => (window.matchMedia('(prefers-reduced-motion: reduce)').matches ? false : { duration: 350 });

// Colori delle categorie: tavolozza verificata per i daltonici; nel tema scuro gli stessi colori adattati al nero
const DARK_STEP = {
  '#2a78d6': '#3987e5', '#eb6834': '#d95926', '#1baf7a': '#199e70', '#eda100': '#c98500',
  '#e87ba4': '#d55181', '#008300': '#008300', '#4a3aa7': '#9085e9', '#e34948': '#e66767', '#a9a8a2': '#6e6e73',
};
function paint(hex) { return isDark() ? (DARK_STEP[String(hex).toLowerCase()] || hex) : hex; }
const catColor = (c) => paint(c?.color || '#A9A8A2');
const FOLD = '__altro';   // categorie raggruppate in "Altro" quando sono troppe per distinguerne i colori
const foldColor = () => (isDark() ? '#48484A' : '#D3D2CC');
const SERIES_BLUE = '#2A78D6';
const SERIES_GRAY = '#A9A8A2';
const CAL_RAMP = { light: ['#cde2fb', '#9ec5f4', '#5598e7', '#256abf', '#104281'], dark: ['#104281', '#1c5cab', '#2a78d6', '#5598e7', '#9ec5f4'] };

function chartDefaults() {
  const C = window.Chart;
  C.defaults.font.family = cssVar('--font');
  C.defaults.font.size = 12;
  C.defaults.color = cssVar('--muted');
  C.defaults.borderColor = cssVar('--grid');
  const tt = C.defaults.plugins.tooltip;
  tt.backgroundColor = 'rgba(30, 30, 32, .94)'; tt.cornerRadius = 10; tt.padding = 10; tt.boxPadding = 4;
  tt.titleFont = { weight: '600' }; tt.usePointStyle = true;
  const lg = C.defaults.plugins.legend.labels;
  lg.usePointStyle = true; lg.pointStyle = 'rectRounded'; lg.boxWidth = 10; lg.boxHeight = 10; lg.padding = 14;
}
const moneyTick = (v) => eur0.format(v);
const pointer = (e, els) => { if (e.native) e.native.target.style.cursor = els.length ? 'pointer' : 'default'; };
// Le azioni dei clic partono dopo che Chart.js ha finito di gestire l'evento (il grafico può venire ridisegnato)
const later = (fn) => setTimeout(fn, 0);
function titleCase(s) { return s.toLowerCase().replace(/(^|\s)\S/g, (c) => c.toUpperCase()); }
function shorten(s, n) { return s.length > n ? s.slice(0, n - 1) + '…' : s; }
function spendKey(t) { return merchantKey(t) || norm(t.desc || t.causale).trim() || '?'; }
const sumOut = (list) => list.filter((t) => t.amount < 0).reduce((s, t) => s - t.amount, 0);

/* ======================= Rendering ======================= */
function monthsWithData() {
  return [...new Set(state.tx.map((t) => t.date.slice(0, 7)))].sort().reverse();
}
function txOfMonth(ym) { return state.tx.filter((t) => t.date.startsWith(ym)); }

function renderMonthSelect() {
  const months = monthsWithData();
  if (!currentMonth || !months.includes(currentMonth)) currentMonth = months[0] || null;
  const sel = $('#month-select');
  sel.replaceChildren(...(months.length ? months.map((m) => h('option', { value: m, selected: m === currentMonth }, monthLabel(m)))
    : [h('option', { value: '' }, 'Nessun mese')]));
  sel.disabled = !months.length;
  // la larghezza segue il mese scelto, così la freccina resta accanto al nome
  const ctx2d = (renderMonthSelect.c ||= document.createElement('canvas').getContext('2d'));
  ctx2d.font = getComputedStyle(sel).font;
  sel.style.width = months.length ? Math.ceil(ctx2d.measureText(monthLabel(currentMonth)).width + 36) + 'px' : '';
  updateHeader();
}
// Riepilogo e Movimenti hanno come titolo il mese (si sceglie toccandolo); le altre sezioni il proprio nome
function updateHeader() {
  const withMonth = (activeView === 'summary' || activeView === 'moves') && !$('#month-select').disabled;
  $('#view-name').textContent = VIEW_NAMES[activeView];
  $('#view-name').hidden = !withMonth;
  $('#month-pick').hidden = !withMonth;
  $('#view-title').hidden = withMonth;
  $('#view-title').textContent = VIEW_NAMES[activeView];
}

function renderSummary() {
  const has = state.tx.length > 0;
  $('#empty').hidden = has;
  $('#summary-content').hidden = !has;
  if (!has || !currentMonth) { destroyCharts(); return; }

  const key = `${state.updatedAt}|${state.tx.length}|${currentMonth}|${isDark()}`;
  if (key === summaryKey && Object.keys(charts).length) {
    // Stessi dati: i grafici esistono già, basta adattarli alla dimensione attuale
    Object.values(charts).forEach((c) => c.resize());
    return;
  }
  destroyCharts();
  summaryKey = key;
  chartDefaults();

  const list = txOfMonth(currentMonth);
  const tin = list.filter((t) => t.amount > 0).reduce((s, t) => s + t.amount, 0);
  const tout = list.filter((t) => t.amount < 0).reduce((s, t) => s + t.amount, 0);
  const net = Math.round((tin + tout) * 100) / 100;
  $('#result-label').textContent = `${monthLabel(currentMonth)}: ` + (net > 0 ? 'mese in positivo' : net < 0 ? 'mese in deficit' : 'mese in pareggio');
  const rv = $('#result-value');
  rv.textContent = fmtSigned(net);
  rv.className = 'result-value ' + (net > 0 ? 'plus' : net < 0 ? 'minus' : '');
  $('#tot-in').textContent = fmt(tin);
  $('#tot-out').textContent = fmt(Math.abs(tout));
  const rate = tin > 0 ? Math.round((net / tin) * 100) : null;
  $('#savings').textContent = rate === null ? ''
    : rate >= 0 ? `Hai messo da parte il ${rate}% delle entrate.`
      : `Hai speso il ${Math.abs(rate)}% in più di quanto è entrato.`;

  renderTrend(list);
  renderCategories(list);
  renderCalendar(list);
  renderTop(list);
  renderAverage();
  renderStack();
  renderMonths();
}

// Andamento giornaliero (somma progressiva)
function renderTrend(list) {
  const [y, m] = currentMonth.split('-').map(Number);
  const days = new Date(y, m, 0).getDate();
  const daily = new Array(days).fill(0);
  list.forEach((t) => { daily[+t.date.slice(8, 10) - 1] += t.amount; });
  let run = 0;
  const cum = daily.map((v) => (run = Math.round((run + v) * 100) / 100));
  const brand = cssVar('--brand');
  charts.trend = new window.Chart($('#chart-trend'), {
    type: 'line',
    data: {
      labels: cum.map((_, i) => String(i + 1)),
      datasets: [{
        data: cum, borderColor: brand, backgroundColor: brand, borderWidth: 2, cubicInterpolationMode: 'monotone',
        pointRadius: daily.map((v) => (v ? 4 : 0)), pointHoverRadius: 6, pointBorderColor: cssVar('--surface'), pointBorderWidth: 2, fill: false,
      }],
    },
    options: {
      maintainAspectRatio: false, animation: anim(),
      interaction: { mode: 'index', intersect: false },
      plugins: {
        legend: { display: false },
        tooltip: { callbacks: {
          title: (it) => `${it[0].label} ${monthLabel(currentMonth).toLowerCase()}`,
          label: (it) => `Progressivo: ${fmtSigned(it.raw)} (giorno: ${fmtSigned(daily[it.dataIndex])})`,
        } },
      },
      scales: {
        x: { grid: { display: false }, ticks: { maxTicksLimit: 10 } },
        y: { border: { display: false }, ticks: { callback: moneyTick, maxTicksLimit: 6 }, grid: { color: (c) => (c.tick.value === 0 ? cssVar('--muted') : cssVar('--grid')) } },
      },
    },
  });
}

// Ciambella delle spese per categoria + elenco completo
function renderCategories(list) {
  const byCat = {};
  list.filter((t) => t.amount < 0).forEach((t) => { byCat[t.cat] = (byCat[t.cat] || 0) + Math.abs(t.amount); });
  const entries = Object.entries(byCat).sort((a, b) => b[1] - a[1]);
  const totOut = entries.reduce((s, e) => s + e[1], 0);
  // Oltre 8 fette i colori non si distinguono più: le più piccole vanno in "Altro" (l'elenco a fianco resta completo)
  const slices = entries.length > 8
    ? [...entries.slice(0, 7), [FOLD, entries.slice(7).reduce((s, e) => s + e[1], 0)]]
    : entries;
  charts.cats = new window.Chart($('#chart-cats'), {
    type: 'doughnut',
    data: {
      labels: slices.map(([id]) => (id === FOLD ? 'Altre categorie' : catById(id)?.name || 'Senza categoria')),
      datasets: [{
        data: slices.map((e) => Math.round(e[1] * 100) / 100),
        backgroundColor: slices.map(([id]) => (id === FOLD ? foldColor() : catColor(catById(id)))),
        borderColor: cssVar('--surface'), borderWidth: 2, hoverOffset: 6,
      }],
    },
    options: {
      maintainAspectRatio: false, cutout: '64%', animation: anim(),
      plugins: { legend: { display: false }, tooltip: { callbacks: { label: (it) => ` ${it.label}: ${fmt(it.raw)}` } } },
      onHover: pointer,
      onClick: (_, els) => {
        if (!els.length) return;
        const id = slices[els[0].index][0];
        if (id !== FOLD) later(() => openMoves({ cat: id }));
      },
    },
  });
  const ul = $('#cat-totals');
  ul.replaceChildren(...(entries.length ? entries.map(([id, v]) => {
    const c = catById(id);
    const dot = h('span', { class: 'dot' }); dot.style.background = catColor(c);
    return h('li', null, dot,
      h('button', { class: 'link', onclick: () => openMoves({ cat: id }) }, c?.name || 'Senza categoria'),
      h('span', { class: 'pct' }, totOut ? Math.round((v / totOut) * 100) + '%' : ''),
      h('span', { class: 'amt' }, fmt(v)));
  }) : [h('li', null, h('span'), h('span', { class: 'muted' }, 'Nessuna spesa in questo mese'))]));
}

// Calendario: ogni giorno colorato in base a quanto si è speso
function renderCalendar(list) {
  const [y, m] = currentMonth.split('-').map(Number);
  const days = new Date(y, m, 0).getDate();
  const spent = new Array(days).fill(0); const count = new Array(days).fill(0); const income = new Array(days).fill(false);
  list.forEach((t) => {
    const d = +t.date.slice(8, 10) - 1;
    count[d]++;
    if (t.amount < 0) spent[d] -= t.amount; else income[d] = true;
  });
  const max = Math.max(0, ...spent);
  const ramp = CAL_RAMP[isDark() ? 'dark' : 'light'];
  // I passi chiari del tema chiaro e quelli scuri del tema scuro vogliono testo di colore opposto
  const textOnStep = (lvl) => (isDark() ? (lvl >= 3 ? 'on-light' : 'on-dark') : (lvl >= 3 ? 'on-dark' : 'on-light'));
  const cells = ['L', 'M', 'M', 'G', 'V', 'S', 'D'].map((d) => h('div', { class: 'cal-head', 'aria-hidden': 'true' }, d));
  const offset = (new Date(y, m - 1, 1).getDay() + 6) % 7;   // lunedì = prima colonna
  for (let i = 0; i < offset; i++) cells.push(h('div', { 'aria-hidden': 'true' }));
  for (let d = 0; d < days; d++) {
    const iso = `${currentMonth}-${String(d + 1).padStart(2, '0')}`;
    const s = Math.round(spent[d] * 100) / 100;
    // scala a radice quadrata: una spesa enorme non deve "spegnere" tutti gli altri giorni
    const lvl = s > 0 && max > 0 ? Math.max(0, Math.ceil(Math.sqrt(s / max) * 5) - 1) : -1;
    const label = `${d + 1} ${monthLabel(currentMonth).toLowerCase()}: ` +
      (count[d] ? `${count[d]} movimenti` + (s ? `, spesi ${fmt(s)}` : '') : 'nessun movimento');
    const btn = h('button', {
      class: 'cal-day' + (lvl >= 0 ? ' ' + textOnStep(lvl) : ''), disabled: !count[d], title: label, 'aria-label': label,
      onclick: () => openMoves({ extra: { type: 'day', value: iso, label: dateLabel(iso) } }),
    }, h('span', { class: 'n' }, String(d + 1)), h('span', { class: 'v' }, s ? eur0.format(s) : ''),
    income[d] ? h('span', { class: 'inc', title: 'Entrata' }) : null);
    if (lvl >= 0) btn.style.background = ramp[lvl];
    cells.push(btn);
  }
  $('#calendar').replaceChildren(...cells);
  $('#cal-scale').replaceChildren(...ramp.map((c) => { const i = h('i'); i.style.background = c; return i; }));
}

// Classifica dei negozi / beneficiari con la spesa più alta
function renderTop(list) {
  const groups = {};
  list.filter((t) => t.amount < 0).forEach((t) => {
    const k = spendKey(t);
    const g = groups[k] || (groups[k] = { k, sum: 0, n: 0 });
    g.sum -= t.amount; g.n++;
  });
  const top = Object.values(groups).sort((a, b) => b.sum - a.sum).slice(0, 10);
  $('#top-empty').hidden = top.length > 0;
  $('#top-box').hidden = !top.length;
  if (!top.length) return;
  $('#top-box').style.height = (top.length * 34 + 40) + 'px';
  const labels = top.map((g) => shorten(titleCase(g.k), 26));
  charts.top = new window.Chart($('#chart-top'), {
    type: 'bar',
    data: { labels, datasets: [{ data: top.map((g) => Math.round(g.sum * 100) / 100), backgroundColor: paint(SERIES_BLUE), borderRadius: 4, borderSkipped: 'start', barPercentage: .8, categoryPercentage: .85 }] },
    options: {
      indexAxis: 'y', maintainAspectRatio: false, animation: anim(),
      plugins: { legend: { display: false }, tooltip: { callbacks: {
        title: (it) => titleCase(top[it[0].dataIndex].k),
        label: (it) => ` ${fmt(it.raw)} in ${top[it.dataIndex].n} ${top[it.dataIndex].n === 1 ? 'movimento' : 'movimenti'}`,
      } } },
      scales: {
        x: { beginAtZero: true, border: { display: false }, ticks: { callback: moneyTick, maxTicksLimit: 5 } },
        y: { grid: { display: false }, ticks: { color: cssVar('--ink-2'), autoSkip: false } },
      },
      onHover: pointer,
      onClick: (_, els) => {
        if (!els.length) return;
        const g = top[els[0].index];
        later(() => openMoves({ extra: { type: 'merchant', value: g.k, label: titleCase(g.k) } }));
      },
    },
  });
}

// Spesa del mese per categoria rispetto alla media dei mesi precedenti
function renderAverage() {
  const prev = monthsWithData().filter((mm) => mm < currentMonth).slice(0, 6);
  const note = $('#avg-note');
  $('#avg-box').hidden = !prev.length;
  if (!prev.length) {
    note.textContent = 'Servono almeno 2 mesi di dati: il confronto comparirà quando importerai l\'estratto conto di un altro mese.';
    return;
  }
  const outCats = state.categories.filter((c) => c.type === 'out');
  const spendIn = (ym, id) => sumOut(txOfMonth(ym).filter((t) => t.cat === id));
  const rows = outCats.map((c) => ({
    id: c.id, name: c.name,
    cur: Math.round(spendIn(currentMonth, c.id) * 100) / 100,
    avg: Math.round((prev.reduce((s, mm) => s + spendIn(mm, c.id), 0) / prev.length) * 100) / 100,
  })).filter((r) => r.cur > 0 || r.avg > 0).sort((a, b) => Math.max(b.cur, b.avg) - Math.max(a.cur, a.avg)).slice(0, 8);
  const avgLabel = prev.length > 1 ? `Media di ${prev.length} mesi` : monthLabel(prev[0]);
  note.textContent = (prev.length > 1
    ? `Confronto con la media dei ${prev.length} mesi precedenti (${monthShort(prev[prev.length - 1])} – ${monthShort(prev[0])}).`
    : `Confronto con ${monthLabel(prev[0])}.`) + ' Tocca una categoria per vederne i movimenti.';
  $('#avg-box').style.height = (rows.length * 48 + 70) + 'px';
  charts.avg = new window.Chart($('#chart-avg'), {
    type: 'bar',
    data: {
      labels: rows.map((r) => shorten(r.name, 24)),
      datasets: [
        { label: 'Questo mese', data: rows.map((r) => r.cur), backgroundColor: paint(SERIES_BLUE), borderRadius: 4, borderSkipped: 'start' },
        { label: avgLabel, data: rows.map((r) => r.avg), backgroundColor: paint(SERIES_GRAY), borderRadius: 4, borderSkipped: 'start' },
      ],
    },
    options: {
      indexAxis: 'y', maintainAspectRatio: false, animation: anim(),
      interaction: { mode: 'index', axis: 'y', intersect: false },
      plugins: {
        legend: { position: 'bottom' },
        tooltip: { callbacks: {
          title: (it) => rows[it[0].dataIndex].name,
          label: (it) => ` ${it.dataset.label}: ${fmt(it.raw)}`,
          footer: (it) => {
            const r = rows[it[0].dataIndex];
            if (!r.avg) return 'Nessuna spesa nei mesi precedenti';
            const d = Math.round(((r.cur - r.avg) / r.avg) * 100);
            return d === 0 ? 'In linea con la media' : `${d > 0 ? '+' : ''}${d}% rispetto alla media`;
          },
        } },
      },
      scales: {
        x: { beginAtZero: true, border: { display: false }, ticks: { callback: moneyTick, maxTicksLimit: 5 } },
        y: { grid: { display: false }, ticks: { color: cssVar('--ink-2'), autoSkip: false } },
      },
      onHover: pointer,
      onClick: (_, els) => { if (els.length) { const id = rows[els[0].index].id; later(() => openMoves({ cat: id })); } },
    },
  });
}

// Spese per categoria, una barra per mese (ultimi 12 mesi con dati)
function renderStack() {
  const months = monthsWithData().slice(0, 12).reverse();
  const outTx = state.tx.filter((t) => t.amount < 0 && months.includes(t.date.slice(0, 7)));
  const totals = {};
  outTx.forEach((t) => { totals[t.cat] = (totals[t.cat] || 0) - t.amount; });
  const order = Object.entries(totals).sort((a, b) => b[1] - a[1]).map((e) => e[0]);
  const shown = order.length > 8 ? order.slice(0, 7) : order;
  const folded = order.filter((id) => !shown.includes(id));
  const series = [...shown.map((id) => ({ id, ids: [id] })), ...(folded.length ? [{ id: FOLD, ids: folded }] : [])];
  const surface = cssVar('--surface');
  charts.stack = new window.Chart($('#chart-stack'), {
    type: 'bar',
    data: {
      labels: months.map(monthShort),
      datasets: series.map((s) => ({
        label: s.id === FOLD ? 'Altre categorie' : catById(s.id)?.name || 'Senza categoria',
        data: months.map((mm) => Math.round(sumOut(outTx.filter((t) => s.ids.includes(t.cat) && t.date.startsWith(mm))) * 100) / 100),
        backgroundColor: s.id === FOLD ? foldColor() : catColor(catById(s.id)),
        borderColor: surface, borderWidth: { top: 2 }, borderSkipped: false, maxBarThickness: 56,
      })),
    },
    options: {
      maintainAspectRatio: false, animation: anim(),
      plugins: {
        legend: { position: 'bottom' },
        tooltip: { callbacks: {
          label: (it) => ` ${it.dataset.label}: ${fmt(it.raw)}`,
          footer: (it) => `Totale uscite: ${fmt(it[0].chart.data.datasets.reduce((s, d) => s + (d.data[it[0].dataIndex] || 0), 0))}`,
        } },
      },
      scales: {
        x: { stacked: true, grid: { display: false } },
        y: { stacked: true, beginAtZero: true, border: { display: false }, ticks: { callback: moneyTick, maxTicksLimit: 6 } },
      },
      onHover: pointer,
      onClick: (_, els) => {
        if (!els.length) return;
        const s = series[els[0].datasetIndex];
        const month = months[els[0].index];
        later(() => openMoves({ cat: s.id === FOLD ? 'all' : s.id, month }));
      },
    },
  });
}

// Entrate e uscite dei vari mesi (ultimi 12 con dati)
function renderMonths() {
  const months = monthsWithData().slice(0, 12).reverse();
  const ins = months.map((mm) => Math.round(txOfMonth(mm).filter((t) => t.amount > 0).reduce((s, t) => s + t.amount, 0) * 100) / 100);
  const outs = months.map((mm) => Math.round(sumOut(txOfMonth(mm)) * 100) / 100);
  charts.months = new window.Chart($('#chart-months'), {
    type: 'bar',
    data: {
      labels: months.map(monthShort),
      datasets: [
        { label: 'Entrate', data: ins, backgroundColor: cssVar('--plus-fill'), borderRadius: 4, borderSkipped: 'start', maxBarThickness: 40 },
        { label: 'Uscite', data: outs, backgroundColor: cssVar('--minus-fill'), borderRadius: 4, borderSkipped: 'start', maxBarThickness: 40 },
      ],
    },
    options: {
      maintainAspectRatio: false, animation: anim(),
      plugins: {
        legend: { position: 'bottom' },
        tooltip: { callbacks: {
          label: (it) => ` ${it.dataset.label}: ${fmt(it.raw)}`,
          footer: (its) => `Risultato: ${fmtSigned(ins[its[0].dataIndex] - outs[its[0].dataIndex])}`,
        } },
      },
      scales: { x: { grid: { display: false } }, y: { beginAtZero: true, border: { display: false }, ticks: { callback: moneyTick, maxTicksLimit: 6 } } },
      onHover: pointer,
      onClick: (_, els) => {
        if (!els.length) return;
        const mm = months[els[0].index];
        later(() => { currentMonth = mm; renderAll(); window.scrollTo(0, 0); });
      },
    },
  });
}

function categoryOptions(selected) {
  const groups = [['out', 'Uscite'], ['in', 'Entrate']];
  return groups.map(([type, label]) => h('optgroup', { label },
    state.categories.filter((c) => c.type === type).map((c) => h('option', { value: c.id, selected: c.id === selected }, c.name))));
}

/* --- Movimenti: filtri impostati anche toccando i grafici --- */
let moveCat = 'all';
let moveExtra = null;   // { type: 'merchant' | 'day', value, label }
function openMoves({ cat = 'all', extra = null, month = null } = {}) {
  if (month) currentMonth = month;
  moveCat = cat; moveExtra = extra;
  $('#moves-search').value = '';
  renderMonthSelect();
  showView('moves');
}

function renderMoves() {
  const fsel = $('#moves-filter');
  fsel.replaceChildren(h('option', { value: 'all' }, 'Tutte'), ...categoryOptions(null));
  fsel.value = [...fsel.options].some((o) => o.value === moveCat) ? moveCat : 'all';

  const chips = [];
  if (moveExtra) {
    chips.push(h('button', {
      class: 'chip', 'aria-label': 'Togli il filtro ' + moveExtra.label,
      onclick: () => { moveExtra = null; renderMoves(); },
    }, (moveExtra.type === 'day' ? 'Giorno: ' : 'Negozio: ') + moveExtra.label, h('span', { class: 'x', 'aria-hidden': 'true' }, '✕')));
  }
  $('#moves-chips').replaceChildren(...chips);

  const q = norm($('#moves-search').value).trim();
  let list = currentMonth ? txOfMonth(currentMonth) : [];
  if (fsel.value !== 'all') list = list.filter((t) => t.cat === fsel.value);
  if (moveExtra?.type === 'merchant') list = list.filter((t) => spendKey(t) === moveExtra.value);
  if (moveExtra?.type === 'day') list = list.filter((t) => t.date === moveExtra.value);
  if (q) list = list.filter((t) => norm(t.causale + ' ' + t.desc).includes(q));
  list.sort((a, b) => b.date.localeCompare(a.date) || a.amount - b.amount);

  const ul = $('#moves-list');
  if (!list.length) { ul.replaceChildren(h('li', { class: 'moves-empty' }, 'Nessun movimento corrisponde ai filtri.')); return; }
  ul.replaceChildren(...list.map((t) => {
    const sel = h('select', { 'aria-label': 'Categoria', onchange: (e) => setCategory(t.id, e.target.value) }, categoryOptions(t.cat));
    return h('li', null,
      h('div', null,
        h('div', { class: 'mv-desc' }, t.desc || t.causale || '(senza descrizione)'),
        h('div', { class: 'mv-meta' }, dateLabel(t.date) + (t.desc && t.causale ? ' — ' + t.causale : ''))),
      h('div', { class: 'mv-amt ' + (t.amount < 0 ? 'minus' : 'plus') }, fmtSigned(t.amount)),
      h('div', { class: 'mv-controls' }, sel,
        t.manual ? h('span', { class: 'tag-manual' }, 'manuale') : null,
        h('span', { class: 'spacer' }),
        h('button', { class: 'icon-btn', title: 'Inverti il segno', 'aria-label': 'Inverti il segno', onclick: () => flipSign(t.id) }, '±'),
        h('button', { class: 'icon-btn danger', title: 'Elimina movimento', 'aria-label': 'Elimina movimento', onclick: () => deleteTx(t.id) }, '✕')));
  }));
}

async function setCategory(id, catId) {
  const tx = state.tx.find((t) => t.id === id);
  if (!tx) return;
  tx.cat = catId; tx.manual = true;
  const key = merchantKey(tx);
  let n = 0;
  if (key) {
    state.learned[key] = catId;
    for (const o of state.tx) {
      if (o !== tx && !o.manual && merchantKey(o) === key && o.cat !== catId) { o.cat = catId; n++; }
    }
  }
  await saveState();
  renderAll();
  toast(n ? `Categoria aggiornata anche per ${n} movimenti simili` : 'Categoria aggiornata');
}
async function flipSign(id) {
  const tx = state.tx.find((t) => t.id === id);
  if (!tx) return;
  tx.amount = -tx.amount;
  if (!tx.manual) tx.cat = guessCategory(tx);
  await saveState(); renderAll();
}
async function deleteTx(id) {
  const tx = state.tx.find((t) => t.id === id);
  if (!tx) return;
  const ok = await openModal({
    title: 'Eliminare il movimento?',
    body: h('p', null, `${dateLabel(tx.date)}: ${tx.desc || tx.causale} (${fmtSigned(tx.amount)}). Se reimporti lo stesso PDF tornerà presente.`),
    actions: [{ label: 'Annulla', value: false }, { label: 'Elimina', cls: 'danger', value: true }],
  });
  if (!ok) return;
  state.tx = state.tx.filter((t) => t.id !== id);
  await saveState(); renderAll();
}

/* --- Editor categorie --- */
let catDraft = [];
function renderCats() {
  catDraft = JSON.parse(JSON.stringify(state.categories));
  drawCatEditor();
  const ll = $('#learned-list');
  const entries = Object.entries(state.learned);
  ll.replaceChildren(...(entries.length ? entries.sort().map(([k, cid]) => h('li', null,
    h('span', { class: 'key' }, `${k} → ${catById(cid)?.name || '?'}`),
    h('button', { class: 'icon-btn', 'aria-label': 'Dimentica associazione', title: 'Dimentica', onclick: async () => {
      delete state.learned[k];
      state.tx.forEach((t) => { if (t.manual && merchantKey(t) === k) t.manual = false; });
      recategorize(); await saveState(); renderAll();
    } }, '✕'))) : [h('li', { class: 'muted' }, 'Nessuna ancora.')]));
}
function drawCatEditor() {
  const box = $('#cats-editor');
  box.replaceChildren(...catDraft.map((c, idx) => {
    const fixed = c.id === OTHER_IN || c.id === OTHER_OUT;
    return h('div', { class: 'cat-edit' },
      h('div', { class: 'cat-edit-head' },
        h('input', { type: 'color', value: c.color, 'aria-label': 'Colore', oninput: (e) => { c.color = e.target.value; } }),
        h('input', { type: 'text', value: c.name, 'aria-label': 'Nome categoria', oninput: (e) => { c.name = e.target.value; } }),
        h('select', { 'aria-label': 'Tipo', disabled: fixed, onchange: (e) => { c.type = e.target.value; } },
          h('option', { value: 'out', selected: c.type === 'out' }, 'Uscite'),
          h('option', { value: 'in', selected: c.type === 'in' }, 'Entrate')),
        fixed ? null : h('button', { class: 'icon-btn', title: 'Elimina categoria', 'aria-label': 'Elimina categoria', onclick: () => { catDraft.splice(idx, 1); drawCatEditor(); } }, '✕')),
      fixed
        ? h('p', { class: 'small muted' }, 'Raccoglie i movimenti che non rientrano in nessuna altra categoria.')
        : h('textarea', { 'aria-label': 'Parole chiave', placeholder: 'Es. ESSELUNGA, CONAD', oninput: (e) => { c.keywords = e.target.value.split(',').map((s) => s.trim()).filter(Boolean); } }, c.keywords.join(', ')));
  }));
}
async function saveCats() {
  const names = new Set();
  for (const c of catDraft) {
    c.name = c.name.trim();
    if (!c.name) { toast('Ogni categoria deve avere un nome'); return; }
    if (names.has(c.name.toUpperCase())) { toast('Ci sono due categorie con lo stesso nome: ' + c.name); return; }
    names.add(c.name.toUpperCase());
  }
  state.categories = catDraft.map((c) => ({ ...c, keywords: c.keywords.map((k) => k.toUpperCase()) }));
  for (const [k, cid] of Object.entries(state.learned)) if (!catById(cid)) delete state.learned[k];
  recategorize();
  await saveState(); renderAll();
  toast('Categorie salvate, movimenti ricategorizzati');
}

/* --- Navigazione --- */
let activeView = 'summary';
const VIEW_NAMES = { summary: 'Riepilogo', moves: 'Movimenti', cats: 'Categorie', settings: 'Backup' };
function showView(v) {
  const changed = v !== activeView;
  activeView = v;
  document.querySelectorAll('.tabbar button').forEach((b) => b.setAttribute('aria-selected', String(b.dataset.view === v)));
  document.querySelectorAll('.view').forEach((s) => { s.hidden = s.id !== 'view-' + v; });
  updateHeader();
  if (changed) window.scrollTo(0, 0);
  renderActive();
}
function renderActive() {
  if (!state) return;
  if (activeView === 'summary') renderSummary();
  if (activeView === 'moves') renderMoves();
  if (activeView === 'cats') renderCats();
}
function renderAll() { if (!state) return; renderMonthSelect(); renderActive(); }

/* ======================= Blocco e sblocco ======================= */
let setupMode = false;
let lastActivity = Date.now();
let hiddenAt = null;

async function initLock() {
  const rec = await idbGet('main');
  setupMode = !rec;
  $('#pw2-wrap').hidden = !setupMode;
  $('#pw1').autocomplete = setupMode ? 'new-password' : 'current-password';
  $('#lock-text').textContent = setupMode
    ? 'Scegli una password per proteggere i tuoi dati. Servirà ogni volta che apri l\'app.'
    : 'Inserisci la password per aprire i tuoi dati.';
  $('#lock-btn').textContent = setupMode ? 'Crea password e inizia' : 'Sblocca';
  $('#lock-note').textContent = setupMode
    ? 'Almeno 10 caratteri. Non esiste un modo per recuperarla: annotala in un posto sicuro.'
    : '';
  $('#lock').hidden = false;
  $('#app').hidden = true;
  $('#pw1').focus();
}

async function onUnlock() {
  const btn = $('#lock-btn');
  const p1 = $('#pw1').value; const p2 = $('#pw2').value;
  $('#lock-error').textContent = '';
  if (setupMode) {
    if (p1.length < 10) { $('#lock-error').textContent = 'La password deve avere almeno 10 caratteri.'; return; }
    if (p1 !== p2) { $('#lock-error').textContent = 'Le due password non coincidono.'; return; }
  } else if (!p1) return;

  btn.disabled = true; const label = btn.textContent; btn.textContent = 'Attendi…';
  try {
    if (setupMode) {
      vaultSalt = crypto.getRandomValues(new Uint8Array(16));
      cryptoKey = await deriveKey(p1, vaultSalt);
      state = newState();
      await saveState();
    } else {
      const rec = await idbGet('main');
      const salt = unb64(rec.salt);
      const key = await deriveKey(p1, salt, rec.iter || PBKDF2_ITER);
      try {
        state = migrateState(await decryptJSON(key, rec.iv, rec.data));
      } catch {
        $('#lock-error').textContent = 'Password errata.';
        return;
      }
      cryptoKey = key; vaultSalt = salt;
    }
    $('#pw1').value = ''; $('#pw2').value = '';
    $('#lock').hidden = true; $('#app').hidden = false;
    lastActivity = Date.now();
    if (navigator.storage && navigator.storage.persist) navigator.storage.persist().catch(() => {});
    showView('summary');
    renderAll();
  } finally {
    btn.disabled = false; btn.textContent = label;
  }
}

async function lockNow() {
  await saveChain;
  closeModal();
  destroyCharts();
  state = null; cryptoKey = null; vaultSalt = null; catDraft = [];
  moveCat = 'all'; moveExtra = null;
  ['#moves-list', '#cat-totals', '#cats-editor', '#learned-list', '#month-select', '#calendar', '#moves-chips'].forEach((s) => $(s).replaceChildren());
  $('#moves-search').value = '';
  await initLock();
}

/* ======================= Backup ======================= */
const isIOS = () => /iPhone|iPad|iPod/.test(navigator.userAgent) || (navigator.platform === 'MacIntel' && navigator.maxTouchPoints > 1);

async function exportBackup() {
  await saveChain;
  const { iv, data } = await encryptJSON(cryptoKey, state);
  const env = { app: 'le-mie-finanze', v: 1, created: new Date().toISOString(), iter: PBKDF2_ITER, salt: b64(vaultSalt), iv, data };
  const name = `finanze-backup-${new Date().toISOString().slice(0, 10)}.fin`;
  const blob = new Blob([JSON.stringify(env)], { type: 'application/json' });
  const file = new File([blob], name, { type: 'application/json' });
  if (isIOS() && navigator.canShare && navigator.canShare({ files: [file] })) {
    try { await navigator.share({ files: [file], title: name }); return; } catch (e) { if (e.name === 'AbortError') return; }
  }
  const url = URL.createObjectURL(blob);
  const a = h('a', { href: url, download: name });
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 10000);
  toast('Backup esportato: ' + name);
}

async function importBackup(file) {
  let env;
  try {
    env = JSON.parse(await file.text());
    if (env.app !== 'le-mie-finanze' || !env.salt || !env.iv || !env.data) throw new Error();
  } catch { toast('Questo file non è un backup di Le mie finanze'); return; }

  const pw = h('input', { type: 'password', autocomplete: 'off' });
  const err = h('p', { class: 'error' });
  let incoming = null;
  const ok = await openModal({
    title: 'Importa backup',
    body: [h('p', null, `Backup del ${dateLabel(env.created.slice(0, 10))}. Inserisci la password usata quando è stato creato.`),
      h('label', { class: 'field' }, h('span', null, 'Password del backup'), pw), err],
    actions: [{ label: 'Annulla', value: false }, { label: 'Importa', cls: 'primary', value: true, onClick: async () => {
      err.textContent = 'Verifica in corso…';
      try {
        const key = await deriveKey(pw.value, unb64(env.salt), env.iter || PBKDF2_ITER);
        incoming = migrateState(await decryptJSON(key, env.iv, env.data));
        return true;
      } catch { err.textContent = 'Password errata.'; return false; }
    } }],
  });
  if (!ok || !incoming) return;

  const newerIncoming = (incoming.updatedAt || 0) > (state.updatedAt || 0);
  const catMap = new Map(state.categories.map((c) => [c.id, c]));
  for (const c of incoming.categories || []) if (!catMap.has(c.id) || newerIncoming) catMap.set(c.id, c);
  state.categories = [...catMap.values()];
  state.learned = newerIncoming ? { ...state.learned, ...incoming.learned } : { ...incoming.learned, ...state.learned };
  const byId = new Map(state.tx.map((t) => [t.id, t]));
  let added = 0;
  for (const t of incoming.tx || []) {
    const cur = byId.get(t.id);
    if (!cur) { byId.set(t.id, t); added++; } else if (t.manual && (!cur.manual || newerIncoming)) byId.set(t.id, t);
  }
  state.tx = [...byId.values()];
  recategorize();
  await saveState(); renderAll();
  toast(`Backup importato: ${added} nuovi movimenti`);
}

async function changePassword() {
  const oldPw = h('input', { type: 'password', autocomplete: 'current-password' });
  const n1 = h('input', { type: 'password', autocomplete: 'new-password' });
  const n2 = h('input', { type: 'password', autocomplete: 'new-password' });
  const err = h('p', { class: 'error' });
  await openModal({
    title: 'Cambia password',
    body: [h('label', { class: 'field' }, h('span', null, 'Password attuale'), oldPw),
      h('label', { class: 'field' }, h('span', null, 'Nuova password (almeno 10 caratteri)'), n1),
      h('label', { class: 'field' }, h('span', null, 'Ripeti la nuova password'), n2), err],
    actions: [{ label: 'Annulla', value: false }, { label: 'Cambia password', cls: 'primary', value: true, onClick: async () => {
      if (n1.value.length < 10) { err.textContent = 'La nuova password deve avere almeno 10 caratteri.'; return false; }
      if (n1.value !== n2.value) { err.textContent = 'Le nuove password non coincidono.'; return false; }
      err.textContent = 'Attendi…';
      const rec = await idbGet('main');
      try {
        const k = await deriveKey(oldPw.value, unb64(rec.salt), rec.iter || PBKDF2_ITER);
        await decryptJSON(k, rec.iv, rec.data);
      } catch { err.textContent = 'La password attuale non è corretta.'; return false; }
      vaultSalt = crypto.getRandomValues(new Uint8Array(16));
      cryptoKey = await deriveKey(n1.value, vaultSalt);
      await saveState();
      toast('Password cambiata. I backup già esportati usano ancora la vecchia password.');
      return true;
    } }],
  });
}

async function wipeAll() {
  const inp = h('input', { type: 'text', autocomplete: 'off' });
  const err = h('p', { class: 'error' });
  const ok = await openModal({
    title: 'Eliminare tutti i dati?',
    body: [h('p', null, 'Movimenti, categorie e password verranno cancellati da questo dispositivo. I backup esportati non vengono toccati.'),
      h('label', { class: 'field' }, h('span', null, 'Scrivi ELIMINA per confermare'), inp), err],
    actions: [{ label: 'Annulla', value: false }, { label: 'Elimina tutto', cls: 'danger', value: true, onClick: () => {
      if (inp.value.trim().toUpperCase() !== 'ELIMINA') { err.textContent = 'Scrivi ELIMINA per confermare.'; return false; }
      return true;
    } }],
  });
  if (!ok) return;
  await saveChain;
  cryptoKey = null;
  await idbDel('main');
  await lockNow();
  toast('Dati eliminati');
}

/* ======================= Avvio ======================= */
function bind() {
  $('#lock-btn').addEventListener('click', onUnlock);
  ['#pw1', '#pw2'].forEach((s) => $(s).addEventListener('keydown', (e) => { if (e.key === 'Enter') onUnlock(); }));
  $('#lock-now').addEventListener('click', lockNow);
  document.querySelectorAll('.tabbar button').forEach((b) => b.addEventListener('click', () => showView(b.dataset.view)));
  $('#month-select').addEventListener('change', (e) => {
    currentMonth = e.target.value;
    renderMonthSelect();
    if (moveExtra?.type === 'day') moveExtra = null;   // il giorno scelto appartiene all'altro mese
    renderActive();
  });

  const pickPdf = () => { $('#pdf-input').value = ''; $('#pdf-input').dataset.mode = 'import'; $('#pdf-input').click(); };
  $('#import-btn').addEventListener('click', pickPdf);
  $('#empty-import').addEventListener('click', pickPdf);
  $('#diag-btn').addEventListener('click', () => { $('#pdf-input').value = ''; $('#pdf-input').dataset.mode = 'diag'; $('#pdf-input').click(); });
  $('#pdf-input').addEventListener('change', (e) => {
    const files = [...e.target.files];
    if (!files.length || !state) return;
    if (e.target.dataset.mode === 'diag') diagnosePdf(files[0]);
    else importPdfs(files);
  });

  $('#moves-filter').addEventListener('change', (e) => { moveCat = e.target.value; renderMoves(); });
  $('#moves-search').addEventListener('input', renderMoves);
  $('#add-cat').addEventListener('click', () => {
    catDraft.push({ id: 'c' + Date.now().toString(36), name: 'Nuova categoria', type: 'out', color: '#5C7A89', keywords: [] });
    drawCatEditor();
    const inputs = $('#cats-editor').querySelectorAll('input[type="text"]');
    inputs[inputs.length - 1].select();
  });
  $('#save-cats').addEventListener('click', saveCats);

  $('#export-btn').addEventListener('click', exportBackup);
  $('#import-backup-btn').addEventListener('click', () => { $('#backup-input').value = ''; $('#backup-input').click(); });
  $('#backup-input').addEventListener('change', (e) => { if (e.target.files[0] && state) importBackup(e.target.files[0]); });
  $('#change-pw-btn').addEventListener('click', changePassword);
  $('#wipe-btn').addEventListener('click', wipeAll);

  // Blocco automatico
  ['pointerdown', 'keydown', 'touchstart', 'wheel'].forEach((ev) => document.addEventListener(ev, () => { lastActivity = Date.now(); }, { passive: true }));
  setInterval(() => { if (state && Date.now() - lastActivity > AUTOLOCK_MS) lockNow(); }, 15000);
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) hiddenAt = Date.now();
    else if (state && hiddenAt && Date.now() - hiddenAt > HIDDEN_LOCK_MS) lockNow();
  });

  // Ridisegna i grafici quando cambia il tema chiaro/scuro
  window.matchMedia('(prefers-color-scheme: dark)').addEventListener?.('change', () => { summaryKey = null; renderActive(); });
}

if ('serviceWorker' in navigator && location.protocol.startsWith('http')) {
  navigator.serviceWorker.register('sw.js').catch((e) => console.warn('Service worker non registrato', e));
}
bind();
initLock().catch((e) => { $('#lock-error').textContent = 'Archivio locale non disponibile: ' + e.message; });

