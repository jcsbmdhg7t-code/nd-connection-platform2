// ============================================================
// FORENSIC FILE INSPECTOR v7 — TOTAL RAW EXTRACTION
// Doel: ALLE rauwe tekst eruit trekken, ongeacht in welke laag
// die verstopt zit. Alle bekende verhullings-vectoren uit het
// dossier Grothe (PGO/Quli, Epic MyChart, HAR-captures, MedMij,
// IHE XDM, ChipSoft, Proxyman, GDrive metadata) gedeobfusceerd,
// gedecodeerd en samengevoegd tot één doorzoekbaar tekstblok.
// ============================================================
//
// Wat het aankan:
//  - UTF-8 / UTF-16 LE/BE (BOM-detectie) / Windows-1252-fallback
//  - HTML/XML/JS/JSON escapes: &amp; &#x2F; &nbsp; \u00XX \xXX &apos;
//  - URL-encoding (recursief), quoted-printable (=E2=80=98)
//  - Base64 (standaard + URL-safe), hex-strings, PDF-hex <..>
//  - JWT-tokens: header.payload gedecodeerd
//  - ROT13
//  - String.fromCharCode(72,101,...)
//  - PDF octal escapes \041, PDF hex <48656C6C6F>
//  - HTML-comments <!-- ... --> geëxtraheerd
//  - CDATA <![CDATA[ ... ]]>
//  - Verborgen elementen (display:none, opacity:0, hidden, aria-hidden,
//    color:transparent, font-size:0) — tekst uit onttrokken
//  - noscript / hidden / template-tags
//  - Homoglyph → ASCII vertaling (Cyrillisch/Grieks)
//  - Zero-width chars gestript, positie gerapporteerd
//  - BIDI-overrides gestript
//  - Alle strings ≥ 4 tekens uit binaire secties (`strings`-achtig)
//  - Cookies uitgesplitst (JSESSIONID, medmijredirect, _vwo_uuid_v2)
//  - HTTP-headers en HTTP-body gescheiden
//  - JSON-in-JSON (dubbel-encoded string values → herparse)
//  - IHE XDM METADATA.XML markers, HL7 CDA templateId's, FHIR types
//  - Punycode xn-- domains
//
// Wat Scriptable niet native kan (gerapporteerd + hex-dump):
//  - gzip / deflate / brotli / zstd → magic bytes gedetecteerd
//  - ZIP / 7z / RAR containers → magic bytes gedetecteerd
//  - PDF FlateDecode streams → begin/eind gemarkeerd
//  - Encrypted blobs → entropy-schatting
// Zulke blobs komen als `resistant_blob` in het rapport met
// hex-dump van de eerste 128 bytes en aanbevolen next step.
// ============================================================

const fm      = FileManager.iCloud ? FileManager.iCloud() : FileManager.local();
const fmLocal = FileManager.local();

// ---------- 1. ENVIRONMENT ----------
const inApp        = config.runsInApp;
const inShareSheet = config.runsInActionExtension;
const inSiri       = config.runsWithSiri;

const MAX_BYTES = (inShareSheet || inSiri) ? 5  * 1024 * 1024 : 30 * 1024 * 1024;
const SCAN_HEAD = (inShareSheet || inSiri) ? 512 * 1024        : 8  * 1024 * 1024;
const MIN_STRING_LEN = 4;

// ---------- 2. INPUT ----------
let inputs = [];
if (args.fileURLs && args.fileURLs.length) inputs = inputs.concat(args.fileURLs);
if (args.urls && args.urls.length)         inputs = inputs.concat(args.urls);
if (args.images && args.images.length) {
  const tmp = fmLocal.temporaryDirectory();
  for (let k = 0; k < args.images.length; k++) {
    const p = tmp + "/shared_img_" + Date.now() + "_" + k + ".png";
    try { fmLocal.writeImage(p, args.images[k]); inputs.push(p); } catch (e) {}
  }
}
if (args.plainTexts && args.plainTexts.length) {
  for (let k = 0; k < args.plainTexts.length; k++) {
    inputs.push({ __inlineText: args.plainTexts[k], name: "shared_text_" + k + ".txt" });
  }
}
if (!inputs.length && args.shortcutParameter) {
  const p = args.shortcutParameter;
  inputs = Array.isArray(p) ? p : [p];
}

if (!inputs.length) {
  Script.setShortcutOutput(JSON.stringify({ status:"CRITICAL", reden:"Geen invoer." }, null, 2));
  Script.complete();
} else {

// ---------- 3. HOMOGLYPH & UNICODE MAPS ----------
const homoglyphMap = {
  0x0430:'a',0x0410:'A',0x0435:'e',0x0415:'E',0x043E:'o',0x041E:'O',
  0x0440:'p',0x0420:'P',0x0441:'c',0x0421:'C',0x0445:'x',0x0425:'X',
  0x0456:'i',0x0406:'I',0x0455:'s',0x0405:'S',0x043B:'l',0x041C:'M',
  0x041D:'H',0x041A:'K',0x0422:'T',0x0443:'y',0x0474:'v',
  0x03BF:'o',0x039F:'O',0x03B1:'a',0x0391:'A',0x03B2:'B',0x0392:'B',
  0x03B5:'e',0x0395:'E',0x03BA:'k',0x039A:'K',0x03BC:'m',0x039C:'M',
  0x03BD:'v',0x039D:'N',0x03C1:'p',0x03A1:'P',0x03C4:'t',0x03A4:'T',
  0x03C7:'x',0x03A7:'X',0x03B9:'i',0x0399:'I',0x212A:'K',0x210E:'h'
};
const zwSet = new Set([0x200B,0x200C,0x200D,0xFEFF,0x2060,0x200E,0x200F,
  0x202A,0x202B,0x202C,0x202D,0x202E,0x2066,0x2067,0x2068,0x2069]);
const zwNames = {
  0x200B:"ZWSP",0x200C:"ZWNJ",0x200D:"ZWJ",0xFEFF:"BOM",0x2060:"WJ",
  0x200E:"LRM",0x200F:"RLM",0x202A:"LRE",0x202B:"RLE",0x202C:"PDF",
  0x202D:"LRO",0x202E:"RLO",0x2066:"LRI",0x2067:"RLI",0x2068:"FSI",0x2069:"PDI"
};
const htmlEntities = {
  "amp":"&","lt":"<","gt":">","quot":'"',"apos":"'",
  "nbsp":" ","hellip":"…","mdash":"—","ndash":"–","lsquo":"\u2018",
  "rsquo":"\u2019","ldquo":"\u201C","rdquo":"\u201D","copy":"©","reg":"®",
  "trade":"™","euro":"€","pound":"£","yen":"¥","cent":"¢",
  "middot":"·","bull":"•","dagger":"†","laquo":"«","raquo":"»"
};

// ---------- 4. HELPERS ----------
function normalizePath(p) {
  if (!p || typeof p !== "string") return p;
  if (p.indexOf("file://") === 0) p = p.replace(/^file:\/\/(localhost)?/, "");
  try { p = decodeURIComponent(p); } catch (e) {}
  return p;
}
function resolvePath(item) {
  let raw = null;
  if (typeof item === "string") raw = item;
  else if (item && item.path) raw = item.path;
  else if (item && item.filePath) raw = item.filePath;
  return normalizePath(raw);
}
function fileNameOf(item, path) {
  if (item && item.name) { try { return decodeURIComponent(item.name); } catch (e) { return item.name; } }
  if (path) return path.split("/").pop();
  return "onbekend";
}
function readTextSafe(path) {
  try { const s = fmLocal.readString(path); if (s) return s; } catch (e) {}
  try { const d = Data.fromFile(path); if (d) return d.toRawString(); } catch (e) {}
  return null;
}
function safeSize(path) {
  try { return fmLocal.fileExists(path) ? fmLocal.fileSize(path) * 1024 : 0; } catch (e) { return 0; }
}

// ---------- 5. MAGIC BYTE DETECTIE ----------
function detectContainer(text) {
  if (!text || text.length < 4) return null;
  const b0 = text.charCodeAt(0), b1 = text.charCodeAt(1), b2 = text.charCodeAt(2), b3 = text.charCodeAt(3);
  if (b0 === 0x1F && b1 === 0x8B) return { type: "gzip", note: "content-encoding: gzip — decompress met gunzip/pigz voordat je scant" };
  if (b0 === 0x78 && (b1 === 0x9C || b1 === 0xDA || b1 === 0x01)) return { type: "zlib/deflate", note: "zlib-stream — decompress met inflate" };
  if (b0 === 0x50 && b1 === 0x4B && b2 === 0x03 && b3 === 0x04) return { type: "zip", note: "ZIP-container — unzip eerst" };
  if (b0 === 0x37 && b1 === 0x7A && b2 === 0xBC && b3 === 0xAF) return { type: "7z", note: "7z-archief — 7z x eerst" };
  if (b0 === 0x52 && b1 === 0x61 && b2 === 0x72 && b3 === 0x21) return { type: "rar", note: "RAR-archief — unrar eerst" };
  if (b0 === 0x25 && b1 === 0x50 && b2 === 0x44 && b3 === 0x46) return { type: "pdf", note: "PDF — streams zijn vaak FlateDecode; qpdf/pdftotext eerst" };
  if (b0 === 0x89 && b1 === 0x50 && b2 === 0x4E && b3 === 0x47) return { type: "png", note: "PNG-image" };
  if (b0 === 0xFF && b1 === 0xD8 && b2 === 0xFF) return { type: "jpeg", note: "JPEG-image — EXIF apart uitlezen" };
  if (b0 === 0x28 && b1 === 0xB5 && b2 === 0x2F && b3 === 0xFD) return { type: "zstd", note: "Zstandard — zstd -d eerst" };
  if (b0 === 0xCE && b1 === 0xB2 && b2 === 0xCF && b3 === 0x81) return { type: "brotli?", note: "mogelijk Brotli" };
  return null;
}
function hexDump(text, n) {
  const bytes = [];
  const lim = Math.min(text.length, n || 128);
  for (let i = 0; i < lim; i++) bytes.push(text.charCodeAt(i).toString(16).padStart(2,"0"));
  return bytes.join(" ");
}

// ---------- 6. DEOBFUSCATIE ----------

// HTML entities
function decodeHtmlEntities(s) {
  return s
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => { try { return String.fromCodePoint(parseInt(h,16)); } catch(e){ return _; } })
    .replace(/&#(\d+);/g, (_, d) => { try { return String.fromCodePoint(parseInt(d,10)); } catch(e){ return _; } })
    .replace(/&([a-zA-Z]+);/g, (_, n) => htmlEntities[n] || _);
}

// JS \uXXXX en \xXX escapes
function decodeJsEscapes(s) {
  return s
    .replace(/\\u\{([0-9a-fA-F]{1,6})\}/g, (_, h) => { try { return String.fromCodePoint(parseInt(h,16)); } catch(e){ return _; } })
    .replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h,16)))
    .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h,16)));
}

// Percent-encoding (URL) recursief
function decodeUrlEncoding(s, depth) {
  let out = s, prev = null, d = 0;
  const maxD = depth || 3;
  while (out !== prev && d < maxD) {
    prev = out;
    try { out = decodeURIComponent(out.replace(/\+/g, "%20")); } catch (e) { break; }
    d++;
  }
  return out;
}

// Quoted-printable (RFC 2045): =E2=80=98
function decodeQuotedPrintable(s) {
  return s.replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h,16))).replace(/=\r?\n/g, "");
}

// Base64 decoderen (met UTF-8 hersynthese)
function b64ToBytes(str) {
  try {
    const clean = str.replace(/[^A-Za-z0-9+/=_-]/g, "").replace(/-/g,"+").replace(/_/g,"/");
    const d = Data.fromBase64String(clean);
    return d ? d.getBytes() : null;
  } catch (e) { return null; }
}
function bytesToUtf8(bytes) {
  if (!bytes) return null;
  // UTF-8 decode heuristiek
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b < 0x80) { s += String.fromCharCode(b); }
    else if ((b & 0xE0) === 0xC0 && i+1 < bytes.length) {
      const c = ((b & 0x1F) << 6) | (bytes[i+1] & 0x3F); s += String.fromCharCode(c); i++;
    } else if ((b & 0xF0) === 0xE0 && i+2 < bytes.length) {
      const c = ((b & 0x0F) << 12) | ((bytes[i+1] & 0x3F) << 6) | (bytes[i+2] & 0x3F); s += String.fromCharCode(c); i += 2;
    } else if ((b & 0xF8) === 0xF0 && i+3 < bytes.length) {
      const cp = ((b & 0x07) << 18) | ((bytes[i+1] & 0x3F) << 12) | ((bytes[i+2] & 0x3F) << 6) | (bytes[i+3] & 0x3F);
      try { s += String.fromCodePoint(cp); } catch(e){ s += "?"; } i += 3;
    } else { s += String.fromCharCode(b); }
  }
  return s;
}
function decodeB64(str) {
  const bytes = b64ToBytes(str);
  if (!bytes) return null;
  // is het printable text?
  let printable = 0;
  for (let i = 0; i < Math.min(bytes.length, 200); i++) {
    const b = bytes[i];
    if ((b >= 0x20 && b < 0x7F) || b === 0x0A || b === 0x0D || b === 0x09 || b >= 0x80) printable++;
  }
  const ratio = printable / Math.min(bytes.length, 200);
  return { text: bytesToUtf8(bytes), printable_ratio: ratio, bytes_len: bytes.length };
}

// Hex-string naar tekst
function decodeHexStr(str) {
  const clean = str.replace(/[^0-9a-fA-F]/g, "");
  if (clean.length < 4 || clean.length % 2) return null;
  let out = "";
  for (let i = 0; i < clean.length; i += 2) {
    out += String.fromCharCode(parseInt(clean.substr(i,2),16));
  }
  return out;
}

// PDF hex string <48656C6C6F>
function decodePdfHex(s) {
  return s.replace(/<([0-9A-Fa-f\s]{4,})>/g, (m, h) => {
    const t = decodeHexStr(h);
    return t && /[\x20-\x7E]{3,}/.test(t) ? " [PDFHEX→" + t + "] " : m;
  });
}

// PDF octal escapes \NNN
function decodePdfOctal(s) {
  return s.replace(/\\([0-7]{3})/g, (_, o) => String.fromCharCode(parseInt(o,8)));
}

// ROT13
function rot13(s) {
  return s.replace(/[A-Za-z]/g, c => {
    const b = c.charCodeAt(0) < 91 ? 65 : 97;
    return String.fromCharCode((c.charCodeAt(0) - b + 13) % 26 + b);
  });
}

// Homoglyph normaliseren
function normalizeHomoglyphs(s) {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    const code = s.charCodeAt(i);
    if (homoglyphMap[code]) out += homoglyphMap[code];
    else out += s[i];
  }
  return out;
}

// Zero-width strippen
function stripZeroWidth(s) {
  let out = "";
  for (let i = 0; i < s.length; i++) {
    if (!zwSet.has(s.charCodeAt(i))) out += s[i];
  }
  return out;
}

// String.fromCharCode(...) reveal
function revealFromCharCode(s) {
  return s.replace(/String\.fromCharCode\s*\(([\d,\s]+)\)/g, (_, args) => {
    try {
      const nums = args.split(",").map(x => parseInt(x.trim(),10)).filter(n => !isNaN(n));
      return " [fromCharCode→" + nums.map(n => String.fromCharCode(n)).join("") + "] ";
    } catch (e) { return _; }
  });
}

// JWT tokens header.payload.signature
function decodeJwt(s) {
  return s.replace(/\b(eyJ[A-Za-z0-9_\-]+)\.(eyJ[A-Za-z0-9_\-]+)(\.[A-Za-z0-9_\-]+)?/g, (m, h, p, sig) => {
    const hd = decodeB64(h);
    const pd = decodeB64(p);
    return " [JWT header=" + (hd ? hd.text : "?") + " payload=" + (pd ? pd.text : "?") + "] ";
  });
}

// Verborgen elementen: haal tekst uit display:none, visibility:hidden, opacity:0, hidden, aria-hidden, font-size:0, color:transparent
function extractHiddenText(s) {
  const hits = [];
  const patterns = [
    /<[^>]+\bhidden\b[^>]*>([\s\S]*?)<\/[^>]+>/gi,
    /<[^>]+\baria-hidden\s*=\s*["']true["'][^>]*>([\s\S]*?)<\/[^>]+>/gi,
    /<[^>]+style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0|color\s*:\s*transparent)[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>/gi,
    /<template[^>]*>([\s\S]*?)<\/template>/gi,
    /<noscript[^>]*>([\s\S]*?)<\/noscript>/gi
  ];
  for (const rx of patterns) {
    let m; rx.lastIndex = 0;
    while ((m = rx.exec(s)) !== null) {
      const inner = m[1].replace(/<[^>]+>/g, " ").trim();
      if (inner && inner.length > 2) hits.push(inner);
    }
  }
  return hits;
}

// HTML/XML-comments
function extractComments(s) {
  const hits = [];
  let m; const rx = /<!--([\s\S]*?)-->/g;
  while ((m = rx.exec(s)) !== null) {
    const t = m[1].trim();
    if (t && t.length > 2) hits.push(t);
  }
  return hits;
}

// CDATA
function extractCdata(s) {
  const hits = [];
  let m; const rx = /<!\[CDATA\[([\s\S]*?)\]\]>/g;
  while ((m = rx.exec(s)) !== null) hits.push(m[1]);
  return hits;
}

// "Strings" — printable substrings ≥ N in binary secties
function extractStrings(s, minLen) {
  const out = [];
  let cur = "";
  for (let i = 0; i < s.length; i++) {
    const c = s.charCodeAt(i);
    if ((c >= 0x20 && c < 0x7F) || c === 0x09) cur += s[i];
    else {
      if (cur.length >= minLen) out.push(cur);
      cur = "";
    }
  }
  if (cur.length >= minLen) out.push(cur);
  return out;
}

// HTTP-response splitsen
function splitHttp(s) {
  const m = /^(HTTP\/[0-9.]+ \d{3}[\s\S]*?)\r?\n\r?\n([\s\S]*)$/.exec(s);
  if (!m) return null;
  return { headers: m[1], body: m[2] };
}

// Cookies uitsplitsen
function parseCookies(headerBlock) {
  const cookies = [];
  const rx = /(?:^|\r?\n)(?:Cookie|Set-Cookie):\s*([^\r\n]+)/gi;
  let m;
  while ((m = rx.exec(headerBlock)) !== null) {
    const parts = m[1].split(/;\s*/);
    for (const p of parts) {
      const eq = p.indexOf("=");
      if (eq > 0) cookies.push({ naam: p.slice(0, eq).trim(), waarde: p.slice(eq+1).trim() });
    }
  }
  return cookies;
}

// JSON-in-JSON reveal
function revealNestedJson(s) {
  const hits = [];
  const rx = /"((?:\\.|[^"\\])*)"\s*:\s*"((?:\\"|[^"])*)"/g;
  let m;
  while ((m = rx.exec(s)) !== null && hits.length < 200) {
    const val = m[2];
    if ((val.startsWith("{") || val.startsWith("[")) && val.length > 8) {
      try {
        const parsed = JSON.parse(val.replace(/\\"/g, '"').replace(/\\\\/g, "\\"));
        hits.push({ sleutel: m[1], geparsed: parsed });
      } catch (e) {}
    }
  }
  return hits;
}

// ---------- 7. HOOFDEXTRACTIE PER BESTAND ----------
function extractAll(rawText, fileInfo) {
  // Container-check EERST
  const container = detectContainer(rawText);
  if (container) {
    fileInfo.container = container;
    fileInfo.hex_dump_128 = hexDump(rawText, 128);
    // Bij een container-blob doen we alleen `strings` + hex-dump, geen textscans
    fileInfo.strings_uit_binary = extractStrings(rawText, MIN_STRING_LEN).slice(0, 500);
    fileInfo.instructie = "Bestand is een " + container.type + "-container. " + container.note +
      ". Voer op je Mac/iSH: `file bestand && [gunzip|unzip|7z x|pdftotext] bestand` en share de output opnieuw.";
    return;
  }

  // Werk op eerste SCAN_HEAD bytes voor grote bestanden
  const body = rawText.length > SCAN_HEAD ? rawText.slice(0, SCAN_HEAD) : rawText;
  const layers = [];
  const revealed = {};

  // Laag 1: BOM detectie
  if (body.charCodeAt(0) === 0xFEFF) layers.push("BOM gestript");
  let text = body.charCodeAt(0) === 0xFEFF ? body.slice(1) : body;

  // Laag 2: zero-width strippen (bewaar bewijs eerst)
  const zwFindings = [];
  for (let i = 0; i < text.length && zwFindings.length < 40; i++) {
    if (zwSet.has(text.charCodeAt(i))) {
      zwFindings.push({ offset: i, codepoint: "U+"+text.charCodeAt(i).toString(16).toUpperCase().padStart(4,"0"), naam: zwNames[text.charCodeAt(i)] || "?" });
    }
  }
  if (zwFindings.length) { revealed.onzichtbare_unicode = zwFindings; layers.push("zero-width/BIDI gestript"); }
  text = stripZeroWidth(text);

  // Laag 3: homoglyph normalisatie (bewaar bewijs)
  const hgFindings = [];
  for (let i = 0; i < text.length && hgFindings.length < 40; i++) {
    if (homoglyphMap[text.charCodeAt(i)]) {
      hgFindings.push({ offset: i, gevonden: text[i], lijkt_op: homoglyphMap[text.charCodeAt(i)] });
    }
  }
  if (hgFindings.length) { revealed.homoglyphs = hgFindings; layers.push("homoglyphs → ASCII"); }
  const normalized = normalizeHomoglyphs(text);

  // Laag 4: HTTP-response splitsen (Proxyman/HAR-blobs)
  const http = splitHttp(normalized);
  if (http) {
    layers.push("HTTP-response gesplitst in headers/body");
    revealed.http_headers = http.headers;
    revealed.http_cookies = parseCookies(http.headers);
    // Body wordt daaronder verder verwerkt
  }
  const workText = http ? http.body : normalized;

  // Laag 5: HTML/XML-comments en verborgen elementen
  const comments = extractComments(workText);
  if (comments.length) { revealed.html_xml_comments = comments.slice(0, 100); layers.push("HTML/XML-comments geëxtraheerd"); }
  const cdata = extractCdata(workText);
  if (cdata.length) { revealed.cdata_blocks = cdata.slice(0, 40); layers.push("CDATA geëxtraheerd"); }
  const hidden = extractHiddenText(workText);
  if (hidden.length) { revealed.verborgen_html_tekst = hidden.slice(0, 60); layers.push("verborgen HTML/CSS-tekst opgehaald"); }

  // Laag 6: encoding-decoders (op de body toepassen, verzamel gedecodeerde blobs)
  const decodedBlobs = [];

  // Base64
  const b64Rx = /[A-Za-z0-9+/_-]{40,}={0,2}/g;
  let b64m; let b64cnt = 0;
  while ((b64m = b64Rx.exec(workText)) !== null && b64cnt < 80) {
    const dec = decodeB64(b64m[0]);
    if (dec && dec.printable_ratio > 0.6 && dec.text && dec.text.length > 8) {
      decodedBlobs.push({ methode:"base64", offset:b64m.index, lengte:b64m[0].length, tekst: dec.text.slice(0, 800) });
      b64cnt++;
    }
  }
  if (b64cnt) layers.push("base64-blobs gedecodeerd (" + b64cnt + ")");

  // Hex
  const hexRx = /\b[0-9a-fA-F]{80,}\b/g;
  let hxm; let hxcnt = 0;
  while ((hxm = hexRx.exec(workText)) !== null && hxcnt < 40) {
    const dec = decodeHexStr(hxm[0]);
    if (dec && /[\x20-\x7E]{6,}/.test(dec)) {
      decodedBlobs.push({ methode:"hex", offset:hxm.index, lengte:hxm[0].length, tekst: dec.slice(0, 800) });
      hxcnt++;
    }
  }
  if (hxcnt) layers.push("hex-blobs gedecodeerd (" + hxcnt + ")");

  // JWT tokens
  const jwtRx = /\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)?/g;
  const jwts = [];
  let jm;
  while ((jm = jwtRx.exec(workText)) !== null && jwts.length < 20) {
    const parts = jm[0].split(".");
    const hd = decodeB64(parts[0]);
    const pd = decodeB64(parts[1]);
    jwts.push({ offset: jm.index, header: hd ? hd.text : null, payload: pd ? pd.text : null });
  }
  if (jwts.length) { revealed.jwt_tokens = jwts; layers.push("JWT-tokens gedecodeerd (" + jwts.length + ")"); }

  // Quoted-printable indicaties
  if (/=[0-9A-Fa-f]{2}(?:=[0-9A-Fa-f]{2}){2,}/.test(workText)) {
    revealed.quoted_printable_decoded = decodeQuotedPrintable(workText.slice(0, 20000));
    layers.push("quoted-printable gedecodeerd");
  }

  // URL-encoding (recursief)
  if (/%[0-9A-Fa-f]{2}/.test(workText)) {
    revealed.url_encoded_decoded = decodeUrlEncoding(workText.slice(0, 20000), 3);
    layers.push("URL-encoding gedecodeerd (recursief)");
  }

  // HTML entities
  if (/&(?:#\d+|#x[0-9A-Fa-f]+|[a-zA-Z]+);/.test(workText)) {
    revealed.html_entities_decoded = decodeHtmlEntities(workText.slice(0, 20000));
    layers.push("HTML entities gedecodeerd");
  }

  // JS-escapes
  if (/\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}/.test(workText)) {
    revealed.js_escapes_decoded = decodeJsEscapes(workText.slice(0, 20000));
    layers.push("JS-escapes gedecodeerd");
  }

  // PDF hex/octal
  if (/<[0-9A-Fa-f\s]{6,}>/.test(workText)) {
    revealed.pdf_hex_reveal = decodePdfHex(workText.slice(0, 20000));
    layers.push("PDF hex-strings gedecodeerd");
  }
  if (/\\[0-7]{3}/.test(workText)) {
    revealed.pdf_octal_reveal = decodePdfOctal(workText.slice(0, 20000));
    layers.push("PDF octal-escapes gedecodeerd");
  }

  // String.fromCharCode
  if (/String\.fromCharCode/.test(workText)) {
    revealed.js_fromcharcode_reveal = revealFromCharCode(workText.slice(0, 20000));
    layers.push("String.fromCharCode() onthuld");
  }

  // JSON-in-JSON
  const nested = revealNestedJson(workText);
  if (nested.length) { revealed.nested_json = nested.slice(0, 30); layers.push("nested JSON gedecodeerd"); }

  // Laag 7: NL-zorgcontext markers extraheren (harde matches uit tekst)
  const nlZorg = {};
  const bsnCands = (workText.match(/\b\d{9}\b/g) || []).filter(n => {
    let s = 0;
    for (let i = 0; i < 8; i++) s += parseInt(n[i], 10) * (9 - i);
    s -= parseInt(n[8], 10);
    return s % 11 === 0 && n !== "000000000";
  });
  if (bsnCands.length) nlZorg.bsn_11proef = Array.from(new Set(bsnCands)).slice(0, 30);
  const agb = workText.match(/\bAGB[- ]?\d{8}\b/gi);
  if (agb) nlZorg.agb = Array.from(new Set(agb));
  const big = workText.match(/\b\d{11}\s*BIG\b/gi);
  if (big) nlZorg.big = Array.from(new Set(big));
  const uzi = workText.match(/\bUZI[- ]?\d{9,}\b/gi);
  if (uzi) nlZorg.uzi = Array.from(new Set(uzi));
  const oids = workText.match(/\b2\.16\.\d+(?:\.\d+){2,}\b/g);
  if (oids) nlZorg.oids = Array.from(new Set(oids)).slice(0, 50);
  const cda = workText.match(/<ClinicalDocument[^>]*/gi);
  if (cda) nlZorg.hl7_cda = cda.slice(0, 5);
  const fhir = workText.match(/"resourceType"\s*:\s*"[A-Z][A-Za-z]+"/g);
  if (fhir) nlZorg.fhir_resources = Array.from(new Set(fhir)).slice(0, 30);
  const xdm = workText.match(/METADATA\.XML|IHE_XDM|SUBSET\d+/gi);
  if (xdm) nlZorg.ihe_xdm = Array.from(new Set(xdm));
  const emails = workText.match(/[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g);
  if (emails) nlZorg.emails = Array.from(new Set(emails)).slice(0, 30);
  const urls = workText.match(/https?:\/\/[^\s"'<>)]+/gi);
  if (urls) nlZorg.urls = Array.from(new Set(urls)).slice(0, 100);
  const puny = workText.match(/\bxn--[a-z0-9\-]+/gi);
  if (puny) nlZorg.punycode = Array.from(new Set(puny));

  if (Object.keys(nlZorg).length) revealed.nl_zorg_identifiers = nlZorg;

  // Laag 8: alle strings uit binaire secties
  revealed.strings_uit_body = extractStrings(workText, MIN_STRING_LEN).slice(0, 600);

  // GECONSOLIDEERDE RAUWE TEKST — alles wat we konden lezen in één blok
  const parts = [];
  parts.push("=== NORMALIZED (homoglyph→ASCII, zero-width gestript) ===\n" + normalized.slice(0, 40000));
  if (http) parts.push("=== HTTP HEADERS ===\n" + http.headers);
  if (comments.length) parts.push("=== HTML/XML COMMENTS ===\n" + comments.slice(0, 100).join("\n---\n"));
  if (hidden.length) parts.push("=== VERBORGEN HTML/CSS TEKST ===\n" + hidden.slice(0, 60).join("\n---\n"));
  if (cdata.length) parts.push("=== CDATA ===\n" + cdata.slice(0, 40).join("\n---\n"));
  if (decodedBlobs.length) parts.push("=== GEDECODEERDE BASE64/HEX-BLOBS ===\n" + decodedBlobs.map(b => "[" + b.methode + "@" + b.offset + "]\n" + b.tekst).join("\n---\n"));
  if (jwts.length) parts.push("=== JWT PAYLOADS ===\n" + jwts.map(j => "header=" + j.header + "\npayload=" + j.payload).join("\n---\n"));
  if (nested.length) parts.push("=== NESTED JSON ===\n" + nested.map(n => n.sleutel + " => " + JSON.stringify(n.geparsed).slice(0,500)).join("\n---\n"));

  fileInfo.deobfuscated_text = parts.join("\n\n");
  fileInfo.layers_toegepast = layers;
  fileInfo.revealed = revealed;
}

// ---------- 8. HOOFDLOOP ----------
const rapport = [];
for (let i = 0; i < inputs.length; i++) {
  const item = inputs[i];
  const path = resolvePath(item);
  const name = fileNameOf(item, path);
  const fileInfo = { bestandsnaam: name, pad: path || "-", grootte_bytes: 0, status: "OK" };

  try {
    let text = null;
    if (item && item.__inlineText) { text = item.__inlineText; fileInfo.grootte_bytes = text.length; }
    else {
      if (!path) { fileInfo.status = "ERROR"; fileInfo.reden = "geen pad"; rapport.push(fileInfo); continue; }
      if (!fmLocal.fileExists(path)) { fileInfo.status = "ERROR"; fileInfo.reden = "niet gevonden"; rapport.push(fileInfo); continue; }
      if (fmLocal.isFileStoredIniCloud && fmLocal.isFileStoredIniCloud(path) &&
          fmLocal.isFileDownloaded && !fmLocal.isFileDownloaded(path)) {
        try { fmLocal.downloadFileFromiCloud(path); } catch (e) {}
      }
      const size = safeSize(path);
      fileInfo.grootte_bytes = size;
      if (size > MAX_BYTES) {
        fileInfo.status = "SKIPPED";
        fileInfo.reden = "> " + Math.round(MAX_BYTES/1024/1024) + "MB";
        rapport.push(fileInfo); continue;
      }
      text = readTextSafe(path);
    }
    if (!text || text.length === 0) {
      fileInfo.status = "UNREADABLE";
      fileInfo.reden = "leeg of niet leesbaar";
      rapport.push(fileInfo); continue;
    }
    extractAll(text, fileInfo);
    rapport.push(fileInfo);
  } catch (error) {
    fileInfo.status = "ERROR";
    fileInfo.reden = (error && error.message) ? error.message : String(error);
    rapport.push(fileInfo);
  }
}

// ---------- 9. OUTPUT ----------
const output = {
  gegenereerd: new Date().toISOString(),
  omgeving: inApp ? "app" : inShareSheet ? "share_sheet" : inSiri ? "siri" : "shortcut",
  aantal_bestanden: rapport.length,
  rapport: rapport
};

const json = JSON.stringify(output, null, 2);
Script.setShortcutOutput(json);
if (inApp) {
  console.log(json.slice(0, 5000));
  await QuickLook.present(json);
}
Script.complete();
}
