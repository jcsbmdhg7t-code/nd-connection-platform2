// ============================================================
// FORENSIC FILE INSPECTOR v6 — NOVELTY MODE
// Rapporteert ALLEEN nieuwe data t.o.v. het known-register.
// Wat je al hebt, verdwijnt uit het rapport; wat nieuw is, komt op.
// ============================================================
//
// KNOWN-REGISTER
// --------------
// Locatie: <Scriptable-map>/forensic-known.json
// Structuur (alle keys optioneel; alles waarden zijn arrays van strings):
//   {
//     "bsn":      ["123456782", ...],
//     "agb":      ["AGB-01234567"],
//     "big":      ["12345678901"],
//     "uzi":      ["UZI-999999999"],
//     "oid":      ["2.16.840.1.113883.2.4.3.11.999"],
//     "url":      ["https://mijn.example.nl/..."],
//     "host":     ["mijn.example.nl"],
//     "ip":       ["10.0.0.1"],
//     "email":    ["dossier@example.nl"],
//     "uuid":     ["01234567-89ab-cdef-0123-456789abcdef"],
//     "session":  ["sess_abc123"],
//     "author":   ["A. Behandelaar"],
//     "xml_ns":   ["urn:hl7-org:v3"],
//     "json_key": ["resourceType", "extension"],
//     "hash":     ["deadbeef..."],       // sha-1/256 prefixen
//     "font":     ["Arial", "Helvetica"]
//   }
//
// Bij eerste run wordt een leeg register aangemaakt. Zet AUTO_LEARN op true
// om ontdekte entities automatisch toe te voegen aan het register.
// ============================================================

const fm         = FileManager.iCloud ? FileManager.iCloud() : FileManager.local();
const fmLocal    = FileManager.local();
const AUTO_LEARN = false; // true = nieuwe entities toevoegen aan register na rapport

// ---------- 1. ENVIRONMENT ----------
const inApp        = config.runsInApp;
const inShareSheet = config.runsInActionExtension;
const inSiri       = config.runsWithSiri;
const inWidget     = config.runsInWidget;
const inNotif      = config.runsInNotification;

const MAX_BYTES = (inShareSheet || inSiri) ? 5  * 1024 * 1024 : 20 * 1024 * 1024;
const SCAN_HEAD = (inShareSheet || inSiri) ? 512 * 1024        : 4  * 1024 * 1024;
const MAX_NEW_PER_TYPE = 40;
const SAMPLE_CONTEXT = 60;

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
if (!inputs.length && args.queryParameters && args.queryParameters.path) {
  inputs = [args.queryParameters.path];
}

if (!inputs.length) {
  Script.setShortcutOutput(JSON.stringify([{
    status: "CRITICAL",
    reden: "Geen invoer. Check Script Settings -> Share Sheet Inputs, of Shortcut Input van de Run Script-actie."
  }], null, 2));
  Script.complete();
} else {

// ---------- 3. KNOWN-REGISTER LADEN ----------
function loadKnown() {
  try {
    const dir  = fm.documentsDirectory();
    const path = dir + "/forensic-known.json";
    if (!fm.fileExists(path)) {
      const empty = {
        bsn:[],agb:[],big:[],uzi:[],oid:[],url:[],host:[],ip:[],email:[],
        uuid:[],session:[],author:[],xml_ns:[],json_key:[],hash:[],font:[]
      };
      try { fm.writeString(path, JSON.stringify(empty, null, 2)); } catch (e) {}
      return { path: path, data: empty };
    }
    if (fm.isFileStoredIniCloud && fm.isFileStoredIniCloud(path) &&
        fm.isFileDownloaded && !fm.isFileDownloaded(path)) {
      try { fm.downloadFileFromiCloud(path); } catch (e) {}
    }
    const raw = fm.readString(path);
    const parsed = JSON.parse(raw || "{}");
    return { path: path, data: parsed };
  } catch (e) {
    return { path: null, data: {} };
  }
}
const known = loadKnown();
const K = known.data;
function knownSet(key) {
  const arr = K[key] || [];
  return new Set(arr.map(v => String(v).toLowerCase()));
}
const KS = {
  bsn:      knownSet("bsn"),
  agb:      knownSet("agb"),
  big:      knownSet("big"),
  uzi:      knownSet("uzi"),
  oid:      knownSet("oid"),
  url:      knownSet("url"),
  host:     knownSet("host"),
  ip:       knownSet("ip"),
  email:    knownSet("email"),
  uuid:     knownSet("uuid"),
  session:  knownSet("session"),
  author:   knownSet("author"),
  xml_ns:   knownSet("xml_ns"),
  json_key: knownSet("json_key"),
  hash:     knownSet("hash"),
  font:     knownSet("font")
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
    if (!path || !fmLocal.fileExists(path)) return 0;
    return fmLocal.fileSize(path) * 1024;
  } catch (e) { return 0; }
}
function readTextSafe(path) {
  try {
    const s = fmLocal.readString(path);
    if (s !== null && typeof s !== "undefined") return s;
  } catch (e) {}
  try {
    const d = Data.fromFile(path);
    if (d) return d.toRawString();
  } catch (e) {}
  return null;
}
function bsn11Proef(d) {
  if (!/^\d{9}$/.test(d)) return false;
  if (d === "000000000") return false;
  let sum = 0;
  for (let i = 0; i < 8; i++) sum += parseInt(d[i], 10) * (9 - i);
  sum -= parseInt(d[8], 10);
  return sum % 11 === 0;
}
function findAll(text, regex, limit) {
  const results = [];
  regex.lastIndex = 0;
  let m;
  while ((m = regex.exec(text)) !== null && results.length < limit) {
    results.push({ match: m[0], index: m.index, groups: m });
    if (m.index === regex.lastIndex) regex.lastIndex++;
  }
  return results;
}
function contextAround(text, index, length) {
  const from = Math.max(0, index - SAMPLE_CONTEXT);
  const to   = Math.min(text.length, index + length + SAMPLE_CONTEXT);
  return {
    pre:  text.slice(from, index).replace(/\s+/g, " "),
    hit:  text.slice(index, index + length),
    post: text.slice(index + length, to).replace(/\s+/g, " "),
    offset: index
  };
}
function novel(list, knownSet, hitPos) {
  // list: array of {match, index}; return {new:[unique+context], dup:count}
  const seenLocal = new Set();
  const result = [];
  let dup = 0;
  for (const h of list) {
    const key = String(h.match).toLowerCase();
    if (knownSet.has(key)) { dup++; continue; }
    if (seenLocal.has(key)) continue;
    seenLocal.add(key);
    result.push({
      waarde: h.match,
      offset: h.index,
      context: hitPos ? contextAround(hitPos.text, h.index, h.match.length) : undefined
    });
    if (result.length >= MAX_NEW_PER_TYPE) break;
  }
  return { nieuw: result, dubbel_bekend: dup };
}
function pushNovel(dest, tech, extracted) {
  if (extracted.nieuw.length === 0 && extracted.dubbel_bekend === 0) return;
  dest.push({
    tech: tech,
    nieuw_aantal: extracted.nieuw.length,
    reeds_bekend_aantal: extracted.dubbel_bekend,
    nieuwe_waarden: extracted.nieuw
  });
}
function hostFromUrl(u) {
  try { const m = /^https?:\/\/([^\/\s"'<>)]+)/i.exec(u); return m ? m[1].toLowerCase() : null; }
  catch (e) { return null; }
}

// ---------- 5. NOVELTY SCAN ----------
function scanNovelty(text, fileInfo, learn) {
  const body = text.length > SCAN_HEAD ? text.slice(0, SCAN_HEAD) : text;
  const ctx  = { text: body };

  // BSN (11-proef, uniek, nog niet bekend)
  const bsnCands = findAll(body, /\b\d{9}\b/g, 300).filter(h => bsn11Proef(h.match));
  pushNovel(fileInfo.novelty, "BSN (11-proef valide, nieuw)", novel(bsnCands, KS.bsn, ctx));

  // AGB
  const agb = findAll(body, /\bAGB[- ]?\d{8}\b/gi, 200);
  pushNovel(fileInfo.novelty, "AGB-code (nieuw)", novel(agb, KS.agb, ctx));

  // BIG
  const big = findAll(body, /\b\d{11}(?=\s*(?:BIG|big)\b)/g, 200);
  pushNovel(fileInfo.novelty, "BIG-nummer (nieuw)", novel(big, KS.big, ctx));

  // UZI
  const uzi = findAll(body, /\b(?:UZI|uzi)[- ]?\d{9,}\b/g, 200);
  pushNovel(fileInfo.novelty, "UZI-nummer (nieuw)", novel(uzi, KS.uzi, ctx));

  // OIDs (Epic/HL7/ChipSoft)
  const oids = findAll(body, /\b2\.16\.\d+(?:\.\d+){2,}\b/g, 400);
  pushNovel(fileInfo.novelty, "HL7/Epic OID (nieuw)", novel(oids, KS.oid, ctx));

  // URLs volledig
  const urls = findAll(body, /https?:\/\/[^\s"'<>)]+/gi, 500);
  pushNovel(fileInfo.novelty, "URL (nieuw)", novel(urls, KS.url, ctx));

  // Hostnames uit URLs
  const hostList = [];
  for (const u of urls) {
    const h = hostFromUrl(u.match);
    if (h) hostList.push({ match: h, index: u.index });
  }
  pushNovel(fileInfo.novelty, "Hostname (nieuw)", novel(hostList, KS.host));

  // IPv4
  const ips = findAll(body, /\b(?:\d{1,3}\.){3}\d{1,3}\b/g, 300);
  pushNovel(fileInfo.novelty, "IPv4-adres (nieuw)", novel(ips, KS.ip, ctx));

  // Emails
  const emails = findAll(body, /[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g, 300);
  pushNovel(fileInfo.novelty, "E-mailadres (nieuw)", novel(emails, KS.email, ctx));

  // UUIDs
  const uuids = findAll(body, /\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g, 300);
  pushNovel(fileInfo.novelty, "UUID (nieuw)", novel(uuids, KS.uuid, ctx));

  // Session-/request-IDs
  const sessions = findAll(body, /\b(?:sess(?:ion)?|req(?:uest)?|token|trace|correlation)[-_]?id["']?\s*[:=]\s*["']?([A-Za-z0-9_\-]{8,})["']?/gi, 200);
  const sessList = sessions.map(s => ({ match: (s.groups[1] || s.match), index: s.index }));
  pushNovel(fileInfo.novelty, "Session/request-ID (nieuw)", novel(sessList, KS.session));

  // Auteurs / usernames (author=, username=, "created_by":"...", <author>...)
  const authors = [];
  const authorRxs = [
    /\bauthor["']?\s*[:=]\s*["']([^"'<>]{2,120})["']/gi,
    /<author[^>]*>\s*([^<]{2,120})\s*<\/author>/gi,
    /\b(?:username|user_name|createdBy|created_by|modifiedBy)["']?\s*[:=]\s*["']([^"'<>]{2,80})["']/gi
  ];
  for (const rx of authorRxs) {
    for (const h of findAll(body, rx, 200)) {
      const v = (h.groups[1] || h.match).trim();
      if (v.length >= 2) authors.push({ match: v, index: h.index });
    }
  }
  pushNovel(fileInfo.novelty, "Auteur / gebruiker (nieuw)", novel(authors, KS.author));

  // XML namespaces
  const xmlns = findAll(body, /xmlns(?::[a-zA-Z0-9]+)?\s*=\s*["']([^"']+)["']/g, 200);
  const nsList = xmlns.map(x => ({ match: x.groups[1], index: x.index }));
  pushNovel(fileInfo.novelty, "XML-namespace (nieuw)", novel(nsList, KS.xml_ns));

  // JSON keys — top-level en 1 diepte
  const jsonKeys = findAll(body, /"([A-Za-z_][A-Za-z0-9_]{2,60})"\s*:/g, 800);
  const keyList = jsonKeys.map(k => ({ match: k.groups[1], index: k.index }));
  pushNovel(fileInfo.novelty, "JSON-key (structurele novelty)", novel(keyList, KS.json_key));

  // Hashes (sha1/256 prefixen)
  const hashes = findAll(body, /\b[a-f0-9]{40,64}\b/gi, 200);
  pushNovel(fileInfo.novelty, "Hash-string (nieuw)", novel(hashes, KS.hash, ctx));

  // Font-family
  const fonts = findAll(body, /font(?:-family)?\s*[:=]\s*["']?([^"';{}<>\n]{2,80})["']?/gi, 200);
  const fontList = fonts.map(f => ({ match: (f.groups[1] || "").trim(), index: f.index }));
  pushNovel(fileInfo.novelty, "Font-declaratie (nieuw)", novel(fontList, KS.font));

  // -- ANOMALIE-DETECTIE (dingen die niet in het register hoeven, maar altijd verdacht) --

  // Redactie-markers: [REDACTED], ***, xxxx, [WEGGELAKT], [ZWART]
  const redact = findAll(body, /(\[REDACTED\]|\[WEGGELAKT\]|\[ZWART\]|\*{4,}|x{6,}|█{3,})/gi, 40);
  if (redact.length) {
    fileInfo.novelty.push({
      tech: "REDACTIE-MARKER (mogelijk verborgen inhoud)",
      nieuw_aantal: redact.length,
      nieuwe_waarden: redact.slice(0, 20).map(r => ({ waarde: r.match, offset: r.index, context: contextAround(body, r.index, r.match.length) }))
    });
  }

  // Tracking pixels / beacons
  const beacons = findAll(body, /<img[^>]+(?:1x1|pixel|track|beacon)[^>]*>/gi, 20);
  if (beacons.length) {
    fileInfo.novelty.push({
      tech: "TRACKING-PIXEL / BEACON",
      nieuw_aantal: beacons.length,
      nieuwe_waarden: beacons.map(b => ({ waarde: b.match.slice(0, 200), offset: b.index }))
    });
  }

  // Verborgen CSS-regels: display:none, visibility:hidden, opacity:0, height:0
  const hidden = findAll(body, /(display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|height\s*:\s*0)[^;{}<>\n]{0,40}/gi, 40);
  if (hidden.length) {
    fileInfo.novelty.push({
      tech: "VERBORGEN CSS/HTML-ELEMENT (mogelijk verborgen inhoud)",
      nieuw_aantal: hidden.length,
      nieuwe_waarden: hidden.slice(0, 20).map(h => ({ waarde: h.match.trim(), offset: h.index, context: contextAround(body, h.index, h.match.length) }))
    });
  }

  // Developer-comments met info-lek
  const devHits = findAll(body, /<!--[\s\S]{0,600}?-->/g, 40)
    .filter(h => /TODO|FIXME|DEBUG|internal|test only|password|token|secret|hidden|deprecated|hack|workaround/i.test(h.match));
  if (devHits.length) {
    fileInfo.novelty.push({
      tech: "DEV-COMMENT met info-lek",
      nieuw_aantal: devHits.length,
      nieuwe_waarden: devHits.map(h => ({ waarde: h.match.trim().slice(0, 400), offset: h.index }))
    });
  }

  // Homoglyph / invisible (altijd melden — dat is nooit "normaal")
  let hgList = [];
  const homoglyphMap = {
    0x0430:'a',0x0410:'A',0x0435:'e',0x0415:'E',0x043E:'o',0x041E:'O',
    0x0440:'p',0x0420:'P',0x0441:'c',0x0421:'C',0x0445:'x',0x0425:'X',
    0x0456:'i',0x0406:'I',0x0455:'s',0x0405:'S',0x043B:'l',0x03BF:'o',
    0x03B1:'a',0x03B5:'e',0x03C1:'p',0x03C4:'t',0x212A:'K',0x210E:'h'
  };
  const zwNames = {
    0x200B:"ZWSP",0x200C:"ZWNJ",0x200D:"ZWJ",0xFEFF:"BOM",0x2060:"WJ",
    0x200E:"LRM",0x200F:"RLM",0x202A:"LRE",0x202B:"RLE",0x202C:"PDF",
    0x202D:"LRO",0x202E:"RLO",0x2066:"LRI",0x2067:"RLI",0x2068:"FSI",0x2069:"PDI"
  };
  for (let j = 0; j < body.length && hgList.length < 20; j++) {
    const code = body.charCodeAt(j);
    if (homoglyphMap[code]) hgList.push({ codepoint: "U+"+code.toString(16).toUpperCase().padStart(4,"0"), lijkt_op: homoglyphMap[code], offset: j, context: contextAround(body, j, 1) });
  }
  if (hgList.length) {
    fileInfo.novelty.push({ tech: "HOMOGLYPH (Cyrillisch/Grieks in ASCII-context)", nieuw_aantal: hgList.length, nieuwe_waarden: hgList });
  }
  let zwList = [];
  for (let j = 0; j < body.length && zwList.length < 30; j++) {
    const code = body.charCodeAt(j);
    if (zwNames[code]) zwList.push({ codepoint: "U+"+code.toString(16).toUpperCase().padStart(4,"0"), naam: zwNames[code], offset: j, context: contextAround(body, j, 1) });
  }
  if (zwList.length) {
    fileInfo.novelty.push({ tech: "ONZICHTBARE UNICODE / BIDI", nieuw_aantal: zwList.length, nieuwe_waarden: zwList });
  }

  // Auto-learn: alleen als vlag aan
  if (learn) {
    function absorb(key, values) {
      const cur = new Set((K[key] || []).map(v => String(v).toLowerCase()));
      for (const v of values) cur.add(String(v).toLowerCase());
      K[key] = Array.from(cur).sort();
    }
    absorb("bsn",      bsnCands.map(h => h.match));
    absorb("agb",      agb.map(h => h.match));
    absorb("big",      big.map(h => h.match));
    absorb("uzi",      uzi.map(h => h.match));
    absorb("oid",      oids.map(h => h.match));
    absorb("url",      urls.map(h => h.match));
    absorb("host",     hostList.map(h => h.match));
    absorb("ip",       ips.map(h => h.match));
    absorb("email",    emails.map(h => h.match));
    absorb("uuid",     uuids.map(h => h.match));
    absorb("session",  sessList.map(h => h.match));
    absorb("author",   authors.map(h => h.match));
    absorb("xml_ns",   nsList.map(h => h.match));
    absorb("json_key", keyList.map(h => h.match));
    absorb("hash",     hashes.map(h => h.match));
    absorb("font",     fontList.map(h => h.match));
  }
}

// ---------- 6. HOOFDLOOP ----------
const rapport = [];
for (let i = 0; i < inputs.length; i++) {
  const item = inputs[i];
  const path = resolvePath(item);
  const name = fileNameOf(item, path);
  const fileInfo = {
    bestandsnaam: name,
    pad: path || "-",
    grootte_bytes: 0,
    status: "SCAN",
    novelty: []
  };

  try {
    if (item && item.__inlineText) {
      fileInfo.grootte_bytes = item.__inlineText.length;
      scanNovelty(item.__inlineText, fileInfo, AUTO_LEARN);
      rapport.push(fileInfo);
      continue;
    }
    if (!path) { fileInfo.status = "ERROR"; fileInfo.reden = "geen pad"; rapport.push(fileInfo); continue; }
    if (!fmLocal.fileExists(path)) { fileInfo.status = "ERROR"; fileInfo.reden = "bestand bestaat niet"; rapport.push(fileInfo); continue; }
    if (fmLocal.isFileStoredIniCloud && fmLocal.isFileStoredIniCloud(path) &&
        fmLocal.isFileDownloaded && !fmLocal.isFileDownloaded(path)) {
      try { fmLocal.downloadFileFromiCloud(path); } catch (e) {}
    }
    const size = safeSize(path);
    fileInfo.grootte_bytes = size;
    if (size > MAX_BYTES) {
      fileInfo.status = "SKIPPED";
      fileInfo.reden = "> " + Math.round(MAX_BYTES/1024/1024) + "MB (" + Math.round(size/1024/1024) + "MB)";
      rapport.push(fileInfo);
      continue;
    }
    const text = readTextSafe(path);
    if (!text || text.length === 0) {
      fileInfo.status = "UNREADABLE";
      fileInfo.reden = "niet als tekst leesbaar";
      rapport.push(fileInfo);
      continue;
    }
    scanNovelty(text, fileInfo, AUTO_LEARN);
    rapport.push(fileInfo);
  } catch (error) {
    fileInfo.status = "ERROR";
    fileInfo.reden = (error && error.message) ? error.message : String(error);
    rapport.push(fileInfo);
  }
}

// ---------- 7. AUTO-LEARN WRITEBACK ----------
if (AUTO_LEARN && known.path) {
  try { fm.writeString(known.path, JSON.stringify(K, null, 2)); } catch (e) {}
}

// ---------- 8. OUTPUT ----------
const totaalNieuw = rapport.reduce((s, r) => s + (r.novelty || []).reduce((a, n) => a + (n.nieuw_aantal || 0), 0), 0);
const output = {
  gegenereerd: new Date().toISOString(),
  omgeving: inApp ? "app" : inShareSheet ? "share_sheet" : inSiri ? "siri" : inWidget ? "widget" : inNotif ? "notification" : "shortcut",
  known_register: known.path,
  auto_learn: AUTO_LEARN,
  aantal_bestanden: rapport.length,
  totaal_nieuwe_bevindingen: totaalNieuw,
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
