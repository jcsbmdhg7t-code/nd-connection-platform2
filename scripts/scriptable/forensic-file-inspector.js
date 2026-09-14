// ============================================================
// FORENSIC FILE INSPECTOR v5 — Scriptable + Shortcuts
// Auteur: forensisch-juridische AI-expert (voor dossier Grothe)
// API-geverifieerd tegen docs.scriptable.app
// Features: multi-input (Share Sheet/Shortcut/URL), homoglyph,
// zero-width & bidi, PDF-triggers, Office-macros, base64/hex
// DECODERING, URL/IP-extractie, NL-zorg identifiers (BSN 11-proef,
// AGB, BIG), HL7 CDA / FHIR / IHE XDM detectie, datums.
// ============================================================

const fm = FileManager.local();

// ---------- 1. ENVIRONMENT ----------
const inApp        = config.runsInApp;
const inShareSheet = config.runsInActionExtension;
const inSiri       = config.runsWithSiri;
const inWidget     = config.runsInWidget;
const inNotif      = config.runsInNotification;

const MAX_BYTES = (inShareSheet || inSiri) ? 5  * 1024 * 1024 : 20 * 1024 * 1024;
const SCAN_HEAD = (inShareSheet || inSiri) ? 512 * 1024        : 4  * 1024 * 1024;
const MAX_SAMPLES_PER_TYPE = 8;
const SAMPLE_CONTEXT = 40;

// ---------- 2. INPUT ----------
let inputs = [];
if (args.fileURLs && args.fileURLs.length) inputs = inputs.concat(args.fileURLs);
if (args.urls && args.urls.length)         inputs = inputs.concat(args.urls);
if (args.images && args.images.length) {
  const tmp = fm.temporaryDirectory();
  for (let k = 0; k < args.images.length; k++) {
    const p = tmp + "/shared_img_" + Date.now() + "_" + k + ".png";
    try { fm.writeImage(p, args.images[k]); inputs.push(p); } catch (e) {}
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
if (!inputs.length && args.queryParameters && args.queryParameters.path) {
  inputs = [args.queryParameters.path];
}

if (!inputs.length) {
  Script.setShortcutOutput(JSON.stringify([{
    bestandsnaam: "-", status: "CRITICAL",
    indicatoren: [{ tech: "NO INPUT", data: "Geen invoer. Check Script Settings -> Share Sheet Inputs, of Shortcut Input van de Run Script-actie." }]
  }], null, 2));
  Script.complete();
} else {

// ---------- 3. HOMOGLYPH & UNICODE MAP ----------
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

const zwNames = {
  0x200B:"ZWSP", 0x200C:"ZWNJ", 0x200D:"ZWJ", 0xFEFF:"BOM/ZWNBSP",
  0x2060:"WJ",   0x200E:"LRM",  0x200F:"RLM",
  0x202A:"LRE",  0x202B:"RLE",  0x202C:"PDF",  0x202D:"LRO", 0x202E:"RLO",
  0x2066:"LRI",  0x2067:"RLI",  0x2068:"FSI",  0x2069:"PDI"
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
  if (item && item.name) {
    try { return decodeURIComponent(item.name); } catch (e) { return item.name; }
  }
  if (path) return path.split("/").pop();
  return "onbekend";
}
function safeSize(path) {
  try {
    if (!path || !fm.fileExists(path)) return 0;
    return fm.fileSize(path) * 1024; // docs: fileSize() = KB
  } catch (e) { return 0; }
}
function fileExtension(name) {
  const m = /\.([A-Za-z0-9]{1,8})$/.exec(name || "");
  return m ? m[1].toLowerCase() : "";
}
function isBinaryLike(str) {
  const sample = str.slice(0, 4096);
  let nulls = 0;
  for (let i = 0; i < sample.length; i++) if (sample.charCodeAt(i) === 0) nulls++;
  return nulls > 4;
}
function readTextSafe(path) {
  try {
    const s = fm.readString(path);
    if (s !== null && typeof s !== "undefined") return s;
  } catch (e) {}
  try {
    const d = Data.fromFile(path);
    if (d) return d.toRawString();
  } catch (e) {}
  return null;
}
function contextAround(text, index, length) {
  const from = Math.max(0, index - SAMPLE_CONTEXT);
  const to   = Math.min(text.length, index + length + SAMPLE_CONTEXT);
  return {
    pre:  text.slice(from, index).replace(/\s+/g, " "),
    hit:  text.slice(index, index + length),
    post: text.slice(index + length, to).replace(/\s+/g, " "),
    index: index
  };
}
function decodeBase64(s) {
  try {
    const d = Data.fromBase64String(s);
    if (!d) return null;
    const raw = d.toRawString();
    if (!raw) return null;
    return raw.slice(0, 200);
  } catch (e) { return null; }
}
function decodeHex(s) {
  try {
    let out = "";
    const clean = s.replace(/\s+/g, "");
    const lim = Math.min(clean.length, 400);
    for (let i = 0; i < lim; i += 2) {
      const c = parseInt(clean.substr(i, 2), 16);
      if (isNaN(c)) return null;
      out += String.fromCharCode(c);
    }
    return out.slice(0, 200);
  } catch (e) { return null; }
}
function findAll(text, regex, limit) {
  const results = [];
  regex.lastIndex = 0;
  let m;
  while ((m = regex.exec(text)) !== null && results.length < limit) {
    results.push({ match: m[0], index: m.index });
    if (m.index === regex.lastIndex) regex.lastIndex++;
  }
  return results;
}
function bsn11Proef(d) {
  if (!/^\d{9}$/.test(d)) return false;
  let sum = 0;
  for (let i = 0; i < 8; i++) sum += parseInt(d[i], 10) * (9 - i);
  sum -= parseInt(d[8], 10);
  return sum % 11 === 0 && d !== "000000000";
}

// ---------- 5. SCAN + SAMPLE EXTRACTIE ----------
function scanText(text, fileInfo) {
  const body = text.length > SCAN_HEAD ? text.slice(0, SCAN_HEAD) : text;

  // A. Homoglyph
  const hgHits = [];
  for (let j = 0; j < body.length && hgHits.length < MAX_SAMPLES_PER_TYPE; j++) {
    const code = body.charCodeAt(j);
    if (homoglyphMap[code]) {
      hgHits.push({
        positie: j,
        code: "U+" + code.toString(16).toUpperCase().padStart(4, "0"),
        gevonden: body[j],
        lijkt_op: homoglyphMap[code],
        context: contextAround(body, j, 1)
      });
    }
  }
  if (hgHits.length) {
    fileInfo.status = "ALERT";
    fileInfo.indicatoren.push({ tech: "HOMOGLYPH FONT SPOOFING", aantal: hgHits.length + "+", samples: hgHits });
  }

  // B. Zero-width & invisible / BIDI
  const zwHits = [];
  for (let j = 0; j < body.length && zwHits.length < MAX_SAMPLES_PER_TYPE; j++) {
    const code = body.charCodeAt(j);
    if (zwNames[code]) {
      zwHits.push({
        positie: j,
        code: "U+" + code.toString(16).toUpperCase().padStart(4, "0"),
        naam: zwNames[code],
        context: contextAround(body, j, 1)
      });
    }
  }
  if (zwHits.length) {
    fileInfo.status = "ALERT";
    fileInfo.indicatoren.push({ tech: "INVISIBLE / BIDI CHARS", aantal: zwHits.length + "+", samples: zwHits });
  }

  // C. PDF-triggers
  const pdfPatterns = [
    { name: "PDF /OpenAction",   rx: /\/OpenAction[\s\S]{0,80}/gi },
    { name: "PDF /AA",           rx: /\/AA[\s\S]{0,80}/gi },
    { name: "PDF /JavaScript",   rx: /\/JavaScript[\s\S]{0,80}/gi },
    { name: "PDF /JS",           rx: /\/JS[\s\S]{0,80}/gi },
    { name: "PDF /Launch",       rx: /\/Launch[\s\S]{0,80}/gi },
    { name: "PDF /EmbeddedFile", rx: /\/EmbeddedFile[\s\S]{0,80}/gi }
  ];
  for (const p of pdfPatterns) {
    const hits = findAll(body, p.rx, MAX_SAMPLES_PER_TYPE);
    if (hits.length) {
      fileInfo.status = "SUSPECT";
      fileInfo.indicatoren.push({
        tech: p.name, aantal: hits.length,
        samples: hits.map(h => ({ positie: h.index, fragment: h.match.trim() }))
      });
    }
  }

  // D. Office / macro
  const officePatterns = [
    { name: "OFFICE EXTERNAL RELATIONSHIP", rx: /TargetMode\s*=\s*["']External["'][\s\S]{0,120}/gi },
    { name: "OFFICE OLE OBJECT",            rx: /oleObject[\s\S]{0,120}/gi },
    { name: "OFFICE VBA PROJECT",           rx: /vbaProject\.bin[\s\S]{0,80}/gi },
    { name: "OFFICE MACRO PATH",            rx: /macros?\/[A-Za-z0-9_\-.]+/gi }
  ];
  for (const p of officePatterns) {
    const hits = findAll(body, p.rx, MAX_SAMPLES_PER_TYPE);
    if (hits.length) {
      fileInfo.status = "SUSPECT";
      fileInfo.indicatoren.push({
        tech: p.name, aantal: hits.length,
        samples: hits.map(h => ({ positie: h.index, fragment: h.match.trim() }))
      });
    }
  }

  // E. Shell / sandbox
  const shellHits = findAll(body, /\b(osascript|applescript|powershell|cmd\.exe|wscript|cscript|bash|zsh)\b[\s\S]{0,80}/gi, MAX_SAMPLES_PER_TYPE);
  if (shellHits.length) {
    fileInfo.status = "SUSPECT";
    fileInfo.indicatoren.push({
      tech: "SHELL / SCRIPT ENGINE REFERENCE", aantal: shellHits.length,
      samples: shellHits.map(h => ({ positie: h.index, fragment: h.match.trim() }))
    });
  }

  // F. Base64 payloads — DECODEREN
  const b64Hits = findAll(body, /[A-Za-z0-9+/]{80,}={0,2}/g, MAX_SAMPLES_PER_TYPE);
  if (b64Hits.length) {
    fileInfo.indicatoren.push({
      tech: "BASE64 PAYLOAD CHAIN", aantal: b64Hits.length,
      samples: b64Hits.map(h => ({
        positie: h.index, lengte: h.match.length,
        encoded_preview: h.match.slice(0, 80) + (h.match.length > 80 ? "…" : ""),
        decoded_preview: decodeBase64(h.match)
      }))
    });
  }

  // G. Hex payloads — DECODEREN
  const hexHits = findAll(body, /[0-9a-fA-F]{80,}/g, MAX_SAMPLES_PER_TYPE);
  if (hexHits.length) {
    fileInfo.indicatoren.push({
      tech: "HEX PAYLOAD CHAIN", aantal: hexHits.length,
      samples: hexHits.map(h => ({
        positie: h.index, lengte: h.match.length,
        encoded_preview: h.match.slice(0, 80) + (h.match.length > 80 ? "…" : ""),
        decoded_preview: decodeHex(h.match)
      }))
    });
  }

  // H. URLs
  const urlHits = findAll(body, /https?:\/\/[^\s"'<>)]+/gi, 20);
  if (urlHits.length) {
    fileInfo.indicatoren.push({
      tech: "EMBEDDED URL(S)", aantal: urlHits.length,
      samples: urlHits.map(h => ({ positie: h.index, url: h.match }))
    });
  }

  // I. IPv4
  const ipHits = findAll(body, /\b\d{1,3}(?:\.\d{1,3}){3}\b/g, 20);
  if (ipHits.length) {
    fileInfo.indicatoren.push({
      tech: "EMBEDDED IPv4", aantal: ipHits.length,
      samples: ipHits.map(h => ({ positie: h.index, ip: h.match }))
    });
  }

  // J. Dev comments
  const devHits = findAll(body, /<!--[\s\S]{0,400}?-->/g, MAX_SAMPLES_PER_TYPE)
    .filter(h => /TODO|FIXME|DEBUG|internal|test only/i.test(h.match));
  if (devHits.length) {
    fileInfo.indicatoren.push({
      tech: "DEV COMMENT LEAK", aantal: devHits.length,
      samples: devHits.map(h => ({ positie: h.index, comment: h.match.trim() }))
    });
  }

  // K. NL zorg-context
  const cdaHits = findAll(body, /<ClinicalDocument[\s\S]{0,200}/gi, 3);
  if (cdaHits.length) {
    fileInfo.indicatoren.push({
      tech: "HL7 CDA R2 DOCUMENT", aantal: cdaHits.length,
      samples: cdaHits.map(h => ({ positie: h.index, fragment: h.match.trim() }))
    });
  }
  const fhirHits = findAll(body, /"resourceType"\s*:\s*"(Patient|Bundle|Composition|Observation|DocumentReference|Practitioner|Organization|Encounter|Condition|MedicationStatement|AllergyIntolerance|Procedure)"/gi, 10);
  if (fhirHits.length) {
    fileInfo.indicatoren.push({
      tech: "FHIR RESOURCES", aantal: fhirHits.length,
      samples: fhirHits.map(h => ({ positie: h.index, fragment: h.match }))
    });
  }
  const xdmHits = findAll(body, /(METADATA\.XML|IHE_XDM|SUBSET\d+)/gi, 5);
  if (xdmHits.length) {
    fileInfo.indicatoren.push({
      tech: "IHE XDM ENVELOPPE", aantal: xdmHits.length,
      samples: xdmHits.map(h => ({ positie: h.index, fragment: h.match }))
    });
  }

  // L. NL identifiers — BSN met 11-proef
  const bsnCandidates = findAll(body, /\b\d{9}\b/g, 100);
  const bsnHits = bsnCandidates.filter(h => bsn11Proef(h.match)).slice(0, 15);
  if (bsnHits.length) {
    fileInfo.status = "ALERT";
    fileInfo.indicatoren.push({
      tech: "MOGELIJK BSN (11-proef valide)", aantal: bsnHits.length,
      samples: bsnHits.map(h => ({ positie: h.index, bsn: h.match, context: contextAround(body, h.index, 9) }))
    });
  }
  const agbHits = findAll(body, /\bAGB[- ]?\d{8}\b/gi, 10);
  if (agbHits.length) {
    fileInfo.indicatoren.push({
      tech: "AGB-CODE ZORGVERLENER", aantal: agbHits.length,
      samples: agbHits.map(h => ({ positie: h.index, agb: h.match }))
    });
  }
  const bigHits = findAll(body, /\b\d{11}\s*(BIG|big)\b/g, 10);
  if (bigHits.length) {
    fileInfo.indicatoren.push({
      tech: "BIG-NUMMER", aantal: bigHits.length,
      samples: bigHits.map(h => ({ positie: h.index, big: h.match }))
    });
  }
  const uziHits = findAll(body, /\b(UZI|uzi)[- ]?\d{9,}\b/g, 10);
  if (uziHits.length) {
    fileInfo.indicatoren.push({
      tech: "UZI-NUMMER", aantal: uziHits.length,
      samples: uziHits.map(h => ({ positie: h.index, uzi: h.match }))
    });
  }

  // M. Datums / tijdstempels
  const dateHits = findAll(body, /\b(20\d{2})[-/](\d{1,2})[-/](\d{1,2})(?:[T ](\d{2}):(\d{2})(?::(\d{2}))?)?/g, 20);
  if (dateHits.length) {
    fileInfo.indicatoren.push({
      tech: "DATUMS/TIJDSTEMPELS", aantal: dateHits.length,
      samples: dateHits.slice(0, 10).map(h => ({ positie: h.index, timestamp: h.match }))
    });
  }

  // N. Epic / OIDs
  const oidHits = findAll(body, /\b2\.16\.840\.1\.113883[\.\d]+/g, 10);
  if (oidHits.length) {
    fileInfo.indicatoren.push({
      tech: "HL7 OID (o.a. Epic/ChipSoft)", aantal: oidHits.length,
      samples: oidHits.map(h => ({ positie: h.index, oid: h.match }))
    });
  }

  if (fileInfo.status === "CLEAN" && fileInfo.indicatoren.length) {
    fileInfo.status = "NOTE";
  }
}

// ---------- 6. HOOFDLOOP ----------
let rapport = [];

for (let i = 0; i < inputs.length; i++) {
  const item = inputs[i];
  const path = resolvePath(item);
  const name = fileNameOf(item, path);
  const fileInfo = {
    bestandsnaam: name,
    extensie: fileExtension(name),
    pad: path || "-",
    grootte_bytes: 0,
    status: "CLEAN",
    indicatoren: []
  };

  try {
    if (item && item.__inlineText) {
      fileInfo.grootte_bytes = item.__inlineText.length;
      scanText(item.__inlineText, fileInfo);
      rapport.push(fileInfo);
      continue;
    }
    if (!path) {
      fileInfo.status = "ERROR";
      fileInfo.indicatoren.push({ tech: "NO PATH", data: "Geen pad." });
      rapport.push(fileInfo);
      continue;
    }
    if (!fm.fileExists(path)) {
      fileInfo.status = "ERROR";
      fileInfo.indicatoren.push({ tech: "NOT FOUND", data: "Bestand bestaat niet." });
      rapport.push(fileInfo);
      continue;
    }
    if (fm.isFileStoredIniCloud && fm.isFileStoredIniCloud(path) &&
        fm.isFileDownloaded && !fm.isFileDownloaded(path)) {
      try { fm.downloadFileFromiCloud(path); } catch (e) {}
    }
    const size = safeSize(path);
    fileInfo.grootte_bytes = size;
    if (size > MAX_BYTES) {
      fileInfo.status = "ALERT";
      fileInfo.indicatoren.push({
        tech: "MEMORY GUARD",
        data: "Bestand > " + Math.round(MAX_BYTES / 1024 / 1024) + "MB (" + Math.round(size / 1024 / 1024) + "MB)."
      });
      rapport.push(fileInfo);
      continue;
    }
    const text = readTextSafe(path);
    if (text === null || typeof text === "undefined" || text.length === 0) {
      fileInfo.status = "UNREADABLE";
      fileInfo.indicatoren.push({ tech: "BINARY OR EMPTY", data: "Niet als tekst leesbaar." });
      rapport.push(fileInfo);
      continue;
    }
    if (isBinaryLike(text)) {
      fileInfo.indicatoren.push({ tech: "BINARY MIXED", data: "Null-bytes; scan best-effort." });
    }
    scanText(text, fileInfo);
    rapport.push(fileInfo);
  } catch (error) {
    fileInfo.status = "ERROR";
    fileInfo.indicatoren.push({
      tech: "FORENSIC EXCEPTION",
      data: (error && error.message) ? error.message : String(error)
    });
    rapport.push(fileInfo);
  }
}

// ---------- 7. OUTPUT ----------
const omgeving = inApp ? "app"
              : inShareSheet ? "share_sheet"
              : inSiri ? "siri"
              : inWidget ? "widget"
              : inNotif ? "notification"
              : "shortcut";

const output = {
  gegenereerd: new Date().toISOString(),
  omgeving: omgeving,
  aantal_bestanden: rapport.length,
  samenvatting: {
    ALERT:      rapport.filter(r => r.status === "ALERT").length,
    SUSPECT:    rapport.filter(r => r.status === "SUSPECT").length,
    NOTE:       rapport.filter(r => r.status === "NOTE").length,
    CLEAN:      rapport.filter(r => r.status === "CLEAN").length,
    ERROR:      rapport.filter(r => r.status === "ERROR").length,
    UNREADABLE: rapport.filter(r => r.status === "UNREADABLE").length
  },
  rapport: rapport
};

const json = JSON.stringify(output, null, 2);
Script.setShortcutOutput(json);
if (inApp) {
  console.log(json);
  await QuickLook.present(json);
}
Script.complete();
}
