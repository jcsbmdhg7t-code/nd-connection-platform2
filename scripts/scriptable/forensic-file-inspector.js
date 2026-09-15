// ============================================================
// FORENSIC FILE INSPECTOR v10 — MATROESJKA + STEGO + ZICHTBAARHEID
// Basis: v7-schema dat tekst.txt (32 MB, 132 bestanden) succesvol
// produceerde. tinyinflate-tak van v8/v9 verwijderd omdat Scriptable-
// JSC daar op sommige toestellen op crasht.
//
// Toegevoegd t.o.v. v7:
//   1. MATROESJKA — recursief blijven decoderen tot niks meer decodeerbaar
//   2. STEGANOGRAFIE — whitespace-stego, zero-width-stego, verborgen-CSS
//   3. ZICHTBAARHEID — per bevinding: was_zichtbaar (in narrative) vs
//      alleen_in_structuur (entries/binary/CSS-hidden/escape)
//   4. AUTO-DECODE — geen tussenstap meer voor gebruiker: alle base64/
//      hex/entities/JS-escapes/URL-encoding/QP worden ontsleuteld in de
//      output; ook nested (base64→hex→text-tot-6-lagen-diep)
//   5. CDA-heuristieken uit v9.1 (self-closing, re-codering, versie-explosie)
// ============================================================

const fm      = FileManager.iCloud ? FileManager.iCloud() : FileManager.local();
const fmLocal = FileManager.local();

const inApp        = config.runsInApp;
const inShareSheet = config.runsInActionExtension;
const inSiri       = config.runsWithSiri;

const MAX_BYTES  = (inShareSheet || inSiri) ? 5  * 1024 * 1024 : 25 * 1024 * 1024;
const SCAN_HEAD  = (inShareSheet || inSiri) ? 512 * 1024        : 6  * 1024 * 1024;
const MATROESJKA_MAX_DEPTH = 6;
const MIN_STRING_LEN = 4;

// ---------- 1. INPUT ----------
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
  Script.setShortcutOutput(JSON.stringify({ status: "CRITICAL", reden: "Geen invoer." }, null, 2));
  Script.complete();
} else {

// ---------- 2. UNICODE MAPS ----------
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
const zwNames = { 0x200B:"ZWSP",0x200C:"ZWNJ",0x200D:"ZWJ",0xFEFF:"BOM",
  0x2060:"WJ",0x200E:"LRM",0x200F:"RLM",0x202A:"LRE",0x202B:"RLE",
  0x202C:"PDF",0x202D:"LRO",0x202E:"RLO",0x2066:"LRI",0x2067:"RLI",
  0x2068:"FSI",0x2069:"PDI" };
const htmlEntities = { amp:"&",lt:"<",gt:">",quot:'"',apos:"'",nbsp:" ",
  hellip:"…",mdash:"—",ndash:"–",lsquo:"‘",rsquo:"’",
  ldquo:"“",rdquo:"”",copy:"©",reg:"®",trade:"™",euro:"€" };

// ---------- 3. HELPERS ----------
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
  try { return fmLocal.fileExists(path) ? fmLocal.fileSize(path) * 1024 : 0; }
  catch (e) { return 0; }
}
function readTextSafe(path) {
  try { const s = fmLocal.readString(path); if (s) return s; } catch (e) {}
  try { const d = Data.fromFile(path); if (d) return d.toRawString(); } catch (e) {}
  return null;
}

// ---------- 4. DECODERS ----------
function decodeHtmlEntities(s) {
  return s
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => { try { return String.fromCodePoint(parseInt(h,16)); } catch(e){ return _; } })
    .replace(/&#(\d+);/g, (_, d) => { try { return String.fromCodePoint(parseInt(d,10)); } catch(e){ return _; } })
    .replace(/&([a-zA-Z]+);/g, (_, n) => htmlEntities[n] || _);
}
function decodeJsEscapes(s) {
  return s.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h,16)))
          .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h,16)))
          .replace(/\\u\{([0-9a-fA-F]{1,6})\}/g, (_, h) => { try { return String.fromCodePoint(parseInt(h,16)); } catch(e){ return _; } });
}
function decodeUrlOnce(s) {
  try { return decodeURIComponent(s.replace(/\+/g, "%20")); }
  catch (e) { return s; }
}
function decodeQP(s) {
  return s.replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h,16))).replace(/=\r?\n/g, "");
}
function decodeB64(str) {
  try {
    const d = Data.fromBase64String(str.replace(/-/g,"+").replace(/_/g,"/"));
    if (!d) return null;
    return d.toRawString();
  } catch (e) { return null; }
}
function decodeHex(str) {
  const clean = str.replace(/[^0-9a-fA-F]/g, "");
  if (clean.length < 4 || clean.length % 2) return null;
  let out = "";
  for (let i = 0; i < clean.length; i += 2) out += String.fromCharCode(parseInt(clean.substr(i,2),16));
  return out;
}
function stripZeroWidth(s) {
  let out = "";
  for (let i = 0; i < s.length; i++) if (!zwSet.has(s.charCodeAt(i))) out += s[i];
  return out;
}
function normalizeHomoglyphs(s) {
  let out = "";
  for (let i = 0; i < s.length; i++) out += homoglyphMap[s.charCodeAt(i)] || s[i];
  return out;
}

// ---------- 5. MATROESJKA — RECURSIEVE ONTLEDING ----------
// Blijft ontsleutelen tot geen enkele laag meer resultaat oplevert.
// Elke succesvolle laag krijgt een spoor `matroesjka_lagen` met wat er
// werd toegepast en welke tekst het opleverde.
function matroesjkaDecode(text, depth, log) {
  if (depth >= MATROESJKA_MAX_DEPTH || !text || text.length < 20) return text;
  let changed = false;
  let cur = text;

  // Poging 1: HTML entities
  if (/&(?:#\d+|#x[0-9A-Fa-f]+|[a-zA-Z]+);/.test(cur)) {
    const n = decodeHtmlEntities(cur);
    if (n !== cur) { log.push({ diepte: depth + 1, laag: "html-entities" }); cur = n; changed = true; }
  }
  // Poging 2: JS-escapes
  if (/\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}/.test(cur)) {
    const n = decodeJsEscapes(cur);
    if (n !== cur) { log.push({ diepte: depth + 1, laag: "js-escapes (\\uNNNN/\\xNN)" }); cur = n; changed = true; }
  }
  // Poging 3: URL-encoding
  if (/%[0-9A-Fa-f]{2}/.test(cur)) {
    const n = decodeUrlOnce(cur);
    if (n !== cur) { log.push({ diepte: depth + 1, laag: "url-encoding" }); cur = n; changed = true; }
  }
  // Poging 4: Quoted-printable
  if (/=[0-9A-Fa-f]{2}(?:=[0-9A-Fa-f]{2}){2,}/.test(cur)) {
    const n = decodeQP(cur);
    if (n !== cur) { log.push({ diepte: depth + 1, laag: "quoted-printable" }); cur = n; changed = true; }
  }
  // Poging 5: Base64-blob detectie in de tekst; ontsleutel de langste
  const b64match = cur.match(/[A-Za-z0-9+/_-]{80,}={0,2}/);
  if (b64match) {
    const dec = decodeB64(b64match[0]);
    if (dec && /[\x20-\x7E]{6,}/.test(dec)) {
      const n = cur.replace(b64match[0], "[[B64→" + dec.slice(0, 400) + "]]");
      log.push({ diepte: depth + 1, laag: "base64", encoded_start: b64match[0].slice(0, 40) + "…", decoded_preview: dec.slice(0, 200) });
      cur = n; changed = true;
    }
  }
  // Poging 6: Hex-blob detectie
  const hexmatch = cur.match(/[0-9a-fA-F]{80,}/);
  if (hexmatch) {
    const dec = decodeHex(hexmatch[0]);
    if (dec && /[\x20-\x7E]{4,}/.test(dec)) {
      const n = cur.replace(hexmatch[0], "[[HEX→" + dec.slice(0, 400) + "]]");
      log.push({ diepte: depth + 1, laag: "hex", decoded_preview: dec.slice(0, 200) });
      cur = n; changed = true;
    }
  }

  return changed ? matroesjkaDecode(cur, depth + 1, log) : cur;
}

// ---------- 6. STEGANOGRAFIE ----------
function detectSteganography(text) {
  const findings = [];

  // 6a. Whitespace-stego: trailing spaces/tabs per regel als bit-encoding
  const lines = text.split(/\n/);
  const trailingBits = [];
  let bitStream = "";
  for (let i = 0; i < lines.length && trailingBits.length < 100; i++) {
    const m = /([ \t]+)$/.exec(lines[i]);
    if (m) {
      trailingBits.push({ regel: i + 1, aantal_tekens: m[1].length, is_tab_dominated: /\t/.test(m[1]) });
      // Simpel encoding: spatie=0, tab=1
      for (const c of m[1]) bitStream += (c === "\t" ? "1" : "0");
    }
  }
  if (trailingBits.length >= 8) {
    // Poging: bitstream → tekst (8 bits per byte)
    let decoded = "";
    for (let i = 0; i + 7 < bitStream.length; i += 8) {
      const byte = parseInt(bitStream.substr(i, 8), 2);
      if (byte >= 0x20 && byte < 0x7F) decoded += String.fromCharCode(byte);
      else if (byte === 0x0A || byte === 0x0D || byte === 0x09) decoded += " ";
      else decoded += ".";
    }
    findings.push({
      soort: "whitespace-steganografie",
      aantal_regels_met_trailing: trailingBits.length,
      voorbeelden: trailingBits.slice(0, 5),
      bit_decodering_poging: decoded.slice(0, 200)
    });
  }

  // 6b. Zero-width steganografie: reeksen ZWSP/ZWNJ/ZWJ als bit-code
  const zwSequences = [];
  let cur = "";
  let curStart = -1;
  for (let i = 0; i < text.length; i++) {
    const cc = text.charCodeAt(i);
    if (zwSet.has(cc)) {
      if (curStart < 0) curStart = i;
      cur += (cc === 0x200B) ? "0" : (cc === 0x200C) ? "1" : "X";
    } else {
      if (cur.length >= 6) {
        zwSequences.push({ offset: curStart, lengte: cur.length, bits_ZWSP_0_ZWNJ_1: cur });
      }
      cur = ""; curStart = -1;
    }
  }
  if (cur.length >= 6) zwSequences.push({ offset: curStart, lengte: cur.length, bits_ZWSP_0_ZWNJ_1: cur });
  if (zwSequences.length) {
    // Decodeer eerste 200 bits als tekst
    let allBits = zwSequences.map(s => s.bits_ZWSP_0_ZWNJ_1).join("").replace(/X/g, "");
    let decoded = "";
    for (let i = 0; i + 7 < allBits.length && decoded.length < 100; i += 8) {
      const b = parseInt(allBits.substr(i, 8), 2);
      decoded += (b >= 0x20 && b < 0x7F) ? String.fromCharCode(b) : ".";
    }
    findings.push({
      soort: "zero-width-steganografie",
      aantal_reeksen: zwSequences.length,
      totaal_bits: allBits.length,
      voorbeelden: zwSequences.slice(0, 3),
      bit_decodering_poging: decoded
    });
  }

  // 6c. Verborgen tekst via CSS
  const cssHidden = [];
  const rxs = [
    { rx: /<[^>]+style="[^"]*display\s*:\s*none[^"]*"[^>]*>([\s\S]{2,400}?)</gi, kenmerk: "display:none" },
    { rx: /<[^>]+style="[^"]*visibility\s*:\s*hidden[^"]*"[^>]*>([\s\S]{2,400}?)</gi, kenmerk: "visibility:hidden" },
    { rx: /<[^>]+style="[^"]*opacity\s*:\s*0[^"]*"[^>]*>([\s\S]{2,400}?)</gi, kenmerk: "opacity:0" },
    { rx: /<[^>]+style="[^"]*font-size\s*:\s*0[^"]*"[^>]*>([\s\S]{2,400}?)</gi, kenmerk: "font-size:0" },
    { rx: /<[^>]+style="[^"]*color\s*:\s*transparent[^"]*"[^>]*>([\s\S]{2,400}?)</gi, kenmerk: "color:transparent" },
    { rx: /<[^>]+style="[^"]*color\s*:\s*white[^"]*"[^>]*>([\s\S]{2,400}?)</gi, kenmerk: "color:white (tekst op witte achtergrond)" },
    { rx: /<[^>]+style="[^"]*left\s*:\s*-?\d{4,}px[^"]*"[^>]*>([\s\S]{2,400}?)</gi, kenmerk: "off-screen (left:-9999px)" },
    { rx: /<[^>]+style="[^"]*clip-path\s*:\s*inset\(100%\)[^"]*"[^>]*>([\s\S]{2,400}?)</gi, kenmerk: "clip-path:inset(100%)" },
    { rx: /<[^>]+\baria-hidden="true"[^>]*>([\s\S]{2,400}?)</gi, kenmerk: "aria-hidden=true" },
    { rx: /<[^>]+\bhidden\b[^>]*>([\s\S]{2,400}?)</gi, kenmerk: "hidden attribuut" },
    { rx: /<template[^>]*>([\s\S]{2,400}?)</gi, kenmerk: "<template> — niet gerenderd" },
    { rx: /<noscript[^>]*>([\s\S]{2,400}?)</gi, kenmerk: "<noscript> — alleen bij JS-uit" }
  ];
  for (const { rx, kenmerk } of rxs) {
    let m; rx.lastIndex = 0;
    while ((m = rx.exec(text)) !== null && cssHidden.length < 60) {
      const inner = m[1].replace(/<[^>]+>/g, "").trim();
      if (inner.length > 2) cssHidden.push({ methode: kenmerk, verborgen_tekst: inner.slice(0, 300) });
    }
  }
  if (cssHidden.length) {
    findings.push({
      soort: "verborgen-tekst-via-CSS",
      aantal: cssHidden.length,
      voorbeelden: cssHidden.slice(0, 20)
    });
  }

  // 6d. HTML-comments met inhoud (technisch verborgen voor lezer)
  const comments = [];
  const commentRx = /<!--([\s\S]{5,500}?)-->/g;
  let cm;
  while ((cm = commentRx.exec(text)) !== null && comments.length < 40) {
    const t = cm[1].trim();
    if (t.length > 5) comments.push(t.slice(0, 300));
  }
  if (comments.length) {
    findings.push({
      soort: "HTML/XML-comments (verborgen voor lezer, wel in bestand)",
      aantal: comments.length,
      voorbeelden: comments.slice(0, 10)
    });
  }

  // 6e. Onzichtbare Unicode tekens los in tekst (geen bit-stego, maar wel verhulling)
  const zwBare = [];
  for (let i = 0; i < text.length && zwBare.length < 30; i++) {
    if (zwSet.has(text.charCodeAt(i))) {
      const cc = text.charCodeAt(i);
      zwBare.push({
        offset: i,
        codepoint: "U+" + cc.toString(16).toUpperCase().padStart(4, "0"),
        naam: zwNames[cc] || "?",
        context: text.slice(Math.max(0, i - 30), i + 30).replace(/[\r\n]/g, " ")
      });
    }
  }
  if (zwBare.length) {
    findings.push({
      soort: "onzichtbare-Unicode-tekens (los)",
      aantal: zwBare.length,
      voorbeelden: zwBare.slice(0, 10)
    });
  }

  // 6f. Homoglyphs
  const hg = [];
  for (let i = 0; i < text.length && hg.length < 30; i++) {
    const cc = text.charCodeAt(i);
    if (homoglyphMap[cc]) {
      hg.push({
        offset: i,
        gevonden: text[i],
        codepoint: "U+" + cc.toString(16).toUpperCase().padStart(4, "0"),
        lijkt_op_ASCII: homoglyphMap[cc],
        context: text.slice(Math.max(0, i - 20), i + 20).replace(/[\r\n]/g, " ")
      });
    }
  }
  if (hg.length) {
    findings.push({
      soort: "homoglyph-substitutie (Cyrillisch/Grieks in ASCII-context)",
      aantal: hg.length,
      voorbeelden: hg.slice(0, 10)
    });
  }

  return findings;
}

// ---------- 7. ZICHTBAARHEID-CLASSIFICATIE ----------
// Splitst CDA/HTML in narrative (<text>-blok = zichtbaar in portaal) versus
// buiten narrative (entries, attributes, comments, scripts = onzichtbaar in
// portaal, wel gedeeld met andere systemen).
function splitByVisibility(text) {
  // Narrative in HL7 CDA staat tussen <text> ... </text> per sectie.
  // In HTML: alles buiten <script>/<style>/<template>/<noscript>/comment.
  const narratives = [];
  let m;
  const rxText = /<text[^>]*>([\s\S]*?)<\/text>/gi;
  while ((m = rxText.exec(text)) !== null) narratives.push(m[1]);
  const narrativeCombined = narratives.join("\n---sectie---\n");
  // Rest = alles buiten narrative
  const rest = text.replace(rxText, "");
  return { narrative: narrativeCombined, buiten_narrative: rest, aantal_narratives: narratives.length };
}

function extractInvisibleValues(text) {
  // Vind gestructureerde data die NIET in narrative zichtbaar wordt gerenderd.
  // - <value ...> in entries
  // - nullFlavor-attributen
  // - script/style content
  const results = [];

  // HL7 CDA entry-values
  const rxVal = /<value[^>]*(?:code|codeSystem|displayName)="([^"]{2,200})"/g;
  const seen = new Set();
  let m;
  while ((m = rxVal.exec(text)) !== null && results.length < 40) {
    if (!seen.has(m[1])) { seen.add(m[1]); results.push({ soort: "CDA <value> attribuut", waarde: m[1] }); }
  }

  // nullFlavor markers
  const nfMap = {};
  const rxNf = /nullFlavor="([A-Z]+)"/g;
  while ((m = rxNf.exec(text)) !== null) nfMap[m[1]] = (nfMap[m[1]] || 0) + 1;
  const nfTotal = Object.values(nfMap).reduce((s, n) => s + n, 0);
  if (nfTotal) {
    results.push({ soort: "nullFlavor-tellingen (data die leeg naar buiten gaat)", waarde: JSON.stringify(nfMap), totaal: nfTotal });
  }

  // <script>-inhoud
  const rxScr = /<script[^>]*>([\s\S]{5,400}?)<\/script>/gi;
  while ((m = rxScr.exec(text)) !== null && results.length < 80) {
    results.push({ soort: "inline <script>-inhoud", waarde: m[1].trim().slice(0, 300) });
  }

  return results;
}

// ---------- 8. CDA-HEURISTIEKEN (v9.1) ----------
function cdaForensicHeuristics(s) {
  const out = {};
  const selfClose = [];
  const rxSc = /<td[^>]+ID="([a-zA-Z]+\d*)(reaction|severity|end|dose|value)"[^>]*\/>/g;
  let m;
  while ((m = rxSc.exec(s)) !== null && selfClose.length < 60) {
    selfClose.push({ veld: m[1] + m[2], offset: m.index });
  }
  if (selfClose.length) out.zelfsluitende_datavelden = selfClose;

  const allergs = {};
  const arx = /<td\s+ID="allergy(\d+)allergen"[^>]*>([^<]{3,100})</g;
  let am;
  while ((am = arx.exec(s)) !== null) {
    const key = am[2].trim().toLowerCase();
    if (!allergs[key]) allergs[key] = [];
    allergs[key].push({ id: "allergy" + am[1], offset: am.index });
  }
  const reCoded = Object.entries(allergs).filter(([_, arr]) => arr.length > 1);
  if (reCoded.length) {
    out.re_codering_allergieen = reCoded.map(([naam, arr]) => ({
      allergen: naam, aantal_recoderingen: arr.length,
      interpretatie: "één werkelijke allergie, " + (arr.length - 1) + " re-codering(en) door actor",
      ids: arr
    }));
  }

  const hn = s.match(/<houseNumber>(999|000|9999)<\/houseNumber>/gi);
  if (hn) out.placeholder_huisnummers = hn;
  const pc = s.match(/<postalCode>\d{4}\s+[A-Z]{2}<\/postalCode>/g);
  if (pc) out.postcode_ZIB_schending = { aantal: pc.length, voorbeelden: Array.from(new Set(pc)).slice(0,10) };

  const streetNames = [...s.matchAll(/<streetName>\s*([^<]+?)\s*<\/streetName>/g)].map(x => x[1]);
  const trunc = [];
  const seen = new Set();
  for (const sn of streetNames) {
    if (!sn) continue;
    if (sn.length === 10 && !seen.has(sn) && sn === sn.toUpperCase()) {
      seen.add(sn); trunc.push({ waarde: sn, reden: "VARCHAR(10) legacy truncatie" });
    }
  }
  if (trunc.length) out.legacy_truncatie = trunc;

  const versies = [...s.matchAll(/<versionNumber\s+value="(\d+)"/g)].map(x => parseInt(x[1], 10));
  if (versies.length) {
    const hoogste = Math.max(...versies);
    if (hoogste >= 20) out.versienummer_explosie = { hoogste, alle: Array.from(new Set(versies)).sort((a,b)=>a-b) };
  }

  const times = [...s.matchAll(/<effectiveTime\s+value="(\d{14})/g)].map(x => x[1]);
  if (times.length >= 3) {
    const parsed = times.map(t => {
      const dt = new Date(Date.UTC(+t.substr(0,4), +t.substr(4,2)-1, +t.substr(6,2),
        +t.substr(8,2), +t.substr(10,2), +t.substr(12,2)));
      return { raw: t, ms: dt.getTime() };
    }).sort((a,b) => a.ms - b.ms);
    const clusters = [];
    let cur = [parsed[0]];
    for (let i = 1; i < parsed.length; i++) {
      if (parsed[i].ms - cur[cur.length-1].ms <= 15 * 60 * 1000) cur.push(parsed[i]);
      else { if (cur.length >= 3) clusters.push(cur); cur = [parsed[i]]; }
    }
    if (cur.length >= 3) clusters.push(cur);
    if (clusters.length) {
      out.batch_mutatie_clusters = clusters.map(c => ({
        aantal: c.length, van: c[0].raw, tot: c[c.length-1].raw,
        span_seconden: Math.round((c[c.length-1].ms - c[0].ms) / 1000)
      }));
    }
  }

  const patNames = [...s.matchAll(/<name>(GROTHE[^<]{0,40})<\/name>/g)].map(x => x[1]);
  const uniqPat = Array.from(new Set(patNames));
  if (uniqPat.length > 1) out.patient_naam_varianten = uniqPat;

  const custody = [];
  if (/http:\/\/localhost/i.test(s)) custody.push("localhost-URL");
  if (/sodipodi|inkscape/i.test(s)) custody.push("Inkscape/Sodipodi metadata");
  if (/textastic/i.test(s)) custody.push("Textastic preview-URL");
  if (/claude\.ai|anthropic/i.test(s)) custody.push("Claude/Anthropic-referentie");
  if (custody.length) out.chain_of_custody_signalen = custody;

  return out;
}

// ---------- 9. NL ZORG IDENTIFIERS ----------
function nlZorgIds(s) {
  const out = {};
  const bsn = (s.match(/\b\d{9}\b/g) || []).filter(n => {
    if (n === "000000000") return false;
    let x = 0; for (let i=0;i<8;i++) x += parseInt(n[i],10)*(9-i); x -= parseInt(n[8],10);
    return x % 11 === 0;
  });
  if (bsn.length) out.bsn_11proef = Array.from(new Set(bsn)).slice(0,30);
  const agb = s.match(/\bAGB[- ]?\d{8}\b/gi); if (agb) out.agb = Array.from(new Set(agb));
  const big = s.match(/\b\d{11}\s*BIG\b/gi); if (big) out.big = Array.from(new Set(big));
  const uzi = s.match(/\bUZI[- ]?\d{9,}\b/gi); if (uzi) out.uzi = Array.from(new Set(uzi));
  const oids = s.match(/\b2\.16\.\d+(?:\.\d+){2,}\b/g); if (oids) out.oids = Array.from(new Set(oids)).slice(0,50);
  const urls = s.match(/https?:\/\/[^\s"'<>)]+/gi); if (urls) out.urls = Array.from(new Set(urls)).slice(0,100);
  const emails = s.match(/[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g); if (emails) out.emails = Array.from(new Set(emails)).slice(0,30);
  const fhir = s.match(/"resourceType"\s*:\s*"[A-Z][A-Za-z]+"/g); if (fhir) out.fhir_resources = Array.from(new Set(fhir)).slice(0,30);
  return out;
}

// ---------- 10. HOOFDVERWERKING ----------
function processFile(text, fileInfo) {
  // Magic-byte check
  const b0 = text.charCodeAt(0), b1 = text.charCodeAt(1), b2 = text.charCodeAt(2), b3 = text.charCodeAt(3);
  if (b0 === 0x1F && b1 === 0x8B) { fileInfo.container = "gzip"; fileInfo.instructie = "gzip; op Mac: gunzip"; return; }
  if (b0 === 0x50 && b1 === 0x4B && b2 === 0x03 && b3 === 0x04) { fileInfo.container = "zip"; fileInfo.instructie = "ZIP; op Mac: unzip"; return; }
  if (b0 === 0x25 && b1 === 0x50 && b2 === 0x44 && b3 === 0x46) fileInfo.container = "pdf";

  const body = text.length > SCAN_HEAD ? text.slice(0, SCAN_HEAD) : text;

  // Zichtbaarheids-classificatie
  const vis = splitByVisibility(body);
  const invisibleValues = extractInvisibleValues(body);

  // Steganografie sweep
  const stego = detectSteganography(body);

  // Matroesjka-decodering op complete body
  const matroesjkaLog = [];
  const fullyDecoded = matroesjkaDecode(body, 0, matroesjkaLog);

  // Normalisatie: homoglyph + zw strippen ná stego-registratie
  const normalized = normalizeHomoglyphs(stripZeroWidth(body));

  // NL zorg identifiers over volledige tekst
  const nlz = nlZorgIds(body);

  // CDA-heuristieken alleen op HL7-bestanden
  let cda = null;
  if (/<ClinicalDocument|urn:hl7-org:v3/i.test(body)) {
    cda = cdaForensicHeuristics(body);
  }

  fileInfo.zichtbaarheid = {
    aantal_narrative_secties: vis.aantal_narratives,
    zichtbaar_in_narrative_preview: vis.narrative.slice(0, 4000),
    alleen_in_structuur_of_binair: {
      aantal_verborgen_datapunten: invisibleValues.length,
      voorbeelden: invisibleValues.slice(0, 30)
    }
  };
  fileInfo.matroesjka = {
    diepste_laag_bereikt: matroesjkaLog.length ? Math.max(...matroesjkaLog.map(l => l.diepte)) : 0,
    lagen_toegepast: matroesjkaLog,
    volledig_gedecodeerde_tekst: fullyDecoded.slice(0, 20000)
  };
  fileInfo.steganografie = stego;
  fileInfo.nl_zorg_identifiers = nlz;
  if (cda) fileInfo.cda_heuristieken = cda;
  fileInfo.rauwe_tekst_normalized = normalized.slice(0, 30000);
}

// ---------- 11. LOOP ----------
const rapport = [];
for (let i = 0; i < inputs.length; i++) {
  const item = inputs[i];
  const path = resolvePath(item);
  const name = fileNameOf(item, path);
  const fileInfo = { bestandsnaam: name, pad: path || "-", status: "OK" };

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
        fileInfo.reden = "> " + Math.round(MAX_BYTES / 1024 / 1024) + "MB";
        rapport.push(fileInfo); continue;
      }
      text = readTextSafe(path);
    }
    if (!text || text.length === 0) {
      fileInfo.status = "UNREADABLE";
      fileInfo.reden = "leeg of niet leesbaar";
      rapport.push(fileInfo); continue;
    }
    processFile(text, fileInfo);
    rapport.push(fileInfo);
  } catch (error) {
    fileInfo.status = "ERROR";
    fileInfo.reden = (error && error.message) ? error.message : String(error);
    rapport.push(fileInfo);
  }
}

const output = {
  gegenereerd: new Date().toISOString(),
  script_versie: "v10-matroesjka-stego-zichtbaarheid",
  omgeving: inApp ? "app" : inShareSheet ? "share_sheet" : inSiri ? "siri" : "shortcut",
  aantal_bestanden: rapport.length,
  rapport: rapport
};

const json = JSON.stringify(output, null, 2);
Script.setShortcutOutput(json);
if (inApp) {
  console.log(json.slice(0, 3000));
  QuickLook.present(json).catch(() => {});
}
Script.complete();
}
