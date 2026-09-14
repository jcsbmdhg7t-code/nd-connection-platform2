// ============================================================
// FORENSIC FILE INSPECTOR v8 — MET INFLATE-DECOMPRESSIE
// Nu ook binair: gzip, zlib/deflate, ZIP-entries, PDF FlateDecode.
// tiny-inflate port (public domain / MIT — foliojs) inline embedded.
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
const INFLATE_MAX_OUT = 32 * 1024 * 1024; // 32 MB max per inflate

// ============================================================
// TINY-INFLATE (pure JS DEFLATE decoder)
// Origineel: https://github.com/foliojs/tiny-inflate (MIT)
// Aangepast: werkt op Uint8Array-equivalent (gewoon array van bytes),
// geeft byte-array terug.
// ============================================================
function makeInflate() {
  const TINF_OK = 0, TINF_DATA_ERROR = -3;
  function Tree() { this.table = new Uint16Array(16); this.trans = new Uint16Array(288); }
  function Data(source, dest) {
    this.source = source; this.sourceIndex = 0; this.tag = 0; this.bitcount = 0;
    this.dest = dest; this.destLen = 0;
    this.ltree = new Tree(); this.dtree = new Tree();
  }
  const sltree = new Tree(), sdtree = new Tree();
  const length_bits = new Uint8Array(30), length_base = new Uint16Array(30);
  const dist_bits = new Uint8Array(30), dist_base = new Uint16Array(30);
  const clcidx = new Uint8Array([16,17,18,0,8,7,9,6,10,5,11,4,12,3,13,2,14,1,15]);
  const code_tree = new Tree(), lengths = new Uint8Array(288+32);

  function tinf_build_bits_base(bits, base, delta, first) {
    let i, sum;
    for (i = 0; i < delta; i++) bits[i] = 0;
    for (i = 0; i < 30 - delta; i++) bits[i + delta] = (i / delta) | 0;
    for (sum = first, i = 0; i < 30; i++) { base[i] = sum; sum += 1 << bits[i]; }
  }
  function tinf_build_fixed_trees(lt, dt) {
    let i;
    for (i = 0; i < 7; i++) lt.table[i] = 0;
    lt.table[7] = 24; lt.table[8] = 152; lt.table[9] = 112;
    for (i = 0; i < 24; i++) lt.trans[i] = 256 + i;
    for (i = 0; i < 144; i++) lt.trans[24 + i] = i;
    for (i = 0; i < 8; i++) lt.trans[24 + 144 + i] = 280 + i;
    for (i = 0; i < 112; i++) lt.trans[24 + 144 + 8 + i] = 144 + i;
    for (i = 0; i < 5; i++) dt.table[i] = 0;
    dt.table[5] = 32;
    for (i = 0; i < 32; i++) dt.trans[i] = i;
  }
  const offs = new Uint16Array(16);
  function tinf_build_tree(t, lens, off, num) {
    let i, sum;
    for (i = 0; i < 16; i++) t.table[i] = 0;
    for (i = 0; i < num; i++) t.table[lens[off + i]]++;
    t.table[0] = 0;
    for (sum = 0, i = 0; i < 16; i++) { offs[i] = sum; sum += t.table[i]; }
    for (i = 0; i < num; i++) {
      if (lens[off + i]) t.trans[offs[lens[off + i]]++] = i;
    }
  }
  function tinf_getbit(d) {
    if (!d.bitcount--) { d.tag = d.source[d.sourceIndex++]; d.bitcount = 7; }
    const bit = d.tag & 1; d.tag >>>= 1; return bit;
  }
  function tinf_read_bits(d, num, base) {
    if (!num) return base;
    while (d.bitcount < 24) { d.tag |= d.source[d.sourceIndex++] << d.bitcount; d.bitcount += 8; }
    const val = d.tag & (0xffff >>> (16 - num));
    d.tag >>>= num; d.bitcount -= num; return val + base;
  }
  function tinf_decode_symbol(d, t) {
    while (d.bitcount < 24) { d.tag |= d.source[d.sourceIndex++] << d.bitcount; d.bitcount += 8; }
    let sum = 0, cur = 0, len = 0, tag = d.tag;
    do {
      cur = 2 * cur + (tag & 1); tag >>>= 1; ++len;
      sum += t.table[len]; cur -= t.table[len];
    } while (cur >= 0);
    d.tag = tag; d.bitcount -= len;
    return t.trans[sum + cur];
  }
  function tinf_decode_trees(d, lt, dt) {
    let i, num, length;
    const hlit = tinf_read_bits(d, 5, 257);
    const hdist = tinf_read_bits(d, 5, 1);
    const hclen = tinf_read_bits(d, 4, 4);
    for (i = 0; i < 19; i++) lengths[i] = 0;
    for (i = 0; i < hclen; i++) lengths[clcidx[i]] = tinf_read_bits(d, 3, 0);
    tinf_build_tree(code_tree, lengths, 0, 19);
    for (num = 0; num < hlit + hdist;) {
      const sym = tinf_decode_symbol(d, code_tree);
      switch (sym) {
        case 16: {
          const prev = lengths[num - 1];
          for (length = tinf_read_bits(d, 2, 3); length; --length) lengths[num++] = prev;
          break;
        }
        case 17:
          for (length = tinf_read_bits(d, 3, 3); length; --length) lengths[num++] = 0;
          break;
        case 18:
          for (length = tinf_read_bits(d, 7, 11); length; --length) lengths[num++] = 0;
          break;
        default:
          lengths[num++] = sym; break;
      }
    }
    tinf_build_tree(lt, lengths, 0, hlit);
    tinf_build_tree(dt, lengths, hlit, hdist);
  }
  function tinf_inflate_block_data(d, lt, dt) {
    while (1) {
      const sym = tinf_decode_symbol(d, lt);
      if (sym === 256) return TINF_OK;
      if (sym < 256) { d.dest[d.destLen++] = sym; }
      else {
        const s = sym - 257;
        const length = tinf_read_bits(d, length_bits[s], length_base[s]);
        const distSym = tinf_decode_symbol(d, dt);
        const offs2 = d.destLen - tinf_read_bits(d, dist_bits[distSym], dist_base[distSym]);
        for (let i = offs2; i < offs2 + length; i++) d.dest[d.destLen++] = d.dest[i];
      }
      if (d.destLen > INFLATE_MAX_OUT) throw new Error("inflate output too large");
    }
  }
  function tinf_inflate_uncompressed_block(d) {
    while (d.bitcount > 8) { d.sourceIndex--; d.bitcount -= 8; }
    let length = d.source[d.sourceIndex + 1]; length = 256 * length + d.source[d.sourceIndex];
    let invlength = d.source[d.sourceIndex + 3]; invlength = 256 * invlength + d.source[d.sourceIndex + 2];
    if (length !== (~invlength & 0x0000ffff)) return TINF_DATA_ERROR;
    d.sourceIndex += 4;
    for (let i = length; i; i--) d.dest[d.destLen++] = d.source[d.sourceIndex++];
    d.bitcount = 0;
    return TINF_OK;
  }
  tinf_build_fixed_trees(sltree, sdtree);
  tinf_build_bits_base(length_bits, length_base, 4, 3); length_bits[28] = 0; length_base[28] = 258;
  tinf_build_bits_base(dist_bits, dist_base, 2, 1);

  return function inflate(source, dest) {
    const d = new Data(source, dest || new Uint8Array(source.length * 8));
    let bfinal, btype, res;
    do {
      bfinal = tinf_getbit(d);
      btype = tinf_read_bits(d, 2, 0);
      switch (btype) {
        case 0: res = tinf_inflate_uncompressed_block(d); break;
        case 1: res = tinf_inflate_block_data(d, sltree, sdtree); break;
        case 2: tinf_decode_trees(d, d.ltree, d.dtree); res = tinf_inflate_block_data(d, d.ltree, d.dtree); break;
        default: res = TINF_DATA_ERROR;
      }
      if (res !== TINF_OK) throw new Error("inflate failed");
    } while (!bfinal);
    return d.dest.slice(0, d.destLen);
  };
}
const inflate = makeInflate();

// gzip wrapper: strip 10-byte header + optional fields
function gunzip(bytes) {
  if (bytes[0] !== 0x1F || bytes[1] !== 0x8B) throw new Error("not gzip");
  let i = 10;
  const flg = bytes[3];
  if (flg & 0x04) { // FEXTRA
    const xlen = bytes[i] | (bytes[i+1] << 8); i += 2 + xlen;
  }
  if (flg & 0x08) { // FNAME
    while (bytes[i] !== 0) i++; i++;
  }
  if (flg & 0x10) { // FCOMMENT
    while (bytes[i] !== 0) i++; i++;
  }
  if (flg & 0x02) i += 2; // FHCRC
  const raw = bytes.subarray ? bytes.subarray(i) : bytes.slice(i);
  return inflate(raw);
}
// zlib wrapper: 2-byte header
function zlibInflate(bytes) {
  const cmf = bytes[0], flg = bytes[1];
  if ((cmf & 0x0F) !== 8) throw new Error("not zlib");
  const raw = bytes.subarray ? bytes.subarray(2) : bytes.slice(2);
  return inflate(raw);
}

// ---------- INPUT ----------
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

// ---------- MAPS ----------
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
const htmlEntities = { amp:"&",lt:"<",gt:">",quot:'"',apos:"'",nbsp:" ",
  hellip:"…",mdash:"—",ndash:"–",lsquo:"‘",rsquo:"’",
  ldquo:"“",rdquo:"”",copy:"©",reg:"®",trade:"™",euro:"€"};

// ---------- HELPERS ----------
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
// Lees als Uint8Array (echte bytes!)
function readBytes(path) {
  try {
    const d = Data.fromFile(path);
    if (!d) return null;
    const arr = d.getBytes();
    return new Uint8Array(arr);
  } catch (e) { return null; }
}
// Bytes → UTF-8 string
function bytesToUtf8(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b < 0x80) s += String.fromCharCode(b);
    else if ((b & 0xE0) === 0xC0 && i+1 < bytes.length) {
      s += String.fromCharCode(((b & 0x1F) << 6) | (bytes[i+1] & 0x3F)); i++;
    } else if ((b & 0xF0) === 0xE0 && i+2 < bytes.length) {
      s += String.fromCharCode(((b & 0x0F) << 12) | ((bytes[i+1] & 0x3F) << 6) | (bytes[i+2] & 0x3F)); i += 2;
    } else if ((b & 0xF8) === 0xF0 && i+3 < bytes.length) {
      const cp = ((b & 0x07) << 18) | ((bytes[i+1] & 0x3F) << 12) | ((bytes[i+2] & 0x3F) << 6) | (bytes[i+3] & 0x3F);
      try { s += String.fromCodePoint(cp); } catch(e){ s += "?"; } i += 3;
    } else s += String.fromCharCode(b);
  }
  return s;
}
function hexDump(bytes, n) {
  const lim = Math.min(bytes.length, n || 128);
  const out = [];
  for (let i = 0; i < lim; i++) out.push(bytes[i].toString(16).padStart(2,"0"));
  return out.join(" ");
}

// ---------- MAGIC DETECTIE (op bytes) ----------
function detectContainer(bytes) {
  if (!bytes || bytes.length < 4) return null;
  const b0=bytes[0], b1=bytes[1], b2=bytes[2], b3=bytes[3];
  if (b0===0x1F && b1===0x8B) return { type:"gzip", inflatable:true };
  if (b0===0x78 && (b1===0x9C || b1===0xDA || b1===0x01)) return { type:"zlib", inflatable:true };
  if (b0===0x50 && b1===0x4B && b2===0x03 && b3===0x04) return { type:"zip", inflatable:true };
  if (b0===0x25 && b1===0x50 && b2===0x44 && b3===0x46) return { type:"pdf", inflatable:"streams" };
  if (b0===0x37 && b1===0x7A && b2===0xBC && b3===0xAF) return { type:"7z", inflatable:false };
  if (b0===0x52 && b1===0x61 && b2===0x72 && b3===0x21) return { type:"rar", inflatable:false };
  if (b0===0x28 && b1===0xB5 && b2===0x2F && b3===0xFD) return { type:"zstd", inflatable:false };
  if (b0===0x89 && b1===0x50 && b2===0x4E && b3===0x47) return { type:"png", inflatable:"idat" };
  if (b0===0xFF && b1===0xD8 && b2===0xFF) return { type:"jpeg", inflatable:false };
  return null;
}

// ---------- ZIP UITPAKKEN ----------
function unzip(bytes) {
  const files = [];
  let i = 0;
  while (i < bytes.length - 4) {
    if (bytes[i]===0x50 && bytes[i+1]===0x4B && bytes[i+2]===0x03 && bytes[i+3]===0x04) {
      const method = bytes[i+8] | (bytes[i+9]<<8);
      const compSize = bytes[i+18] | (bytes[i+19]<<8) | (bytes[i+20]<<16) | (bytes[i+21]<<24);
      const uncompSize = bytes[i+22] | (bytes[i+23]<<8) | (bytes[i+24]<<16) | (bytes[i+25]<<24);
      const nameLen = bytes[i+26] | (bytes[i+27]<<8);
      const extraLen = bytes[i+28] | (bytes[i+29]<<8);
      const nameStart = i + 30;
      const name = bytesToUtf8(bytes.subarray(nameStart, nameStart + nameLen));
      const dataStart = nameStart + nameLen + extraLen;
      const dataEnd = dataStart + compSize;
      try {
        const raw = bytes.subarray(dataStart, dataEnd);
        let out;
        if (method === 0) out = raw;
        else if (method === 8) out = inflate(raw, new Uint8Array(Math.max(uncompSize, raw.length * 8)));
        else { files.push({ naam:name, methode:method, fout:"onbekende compressie-methode" }); i = dataEnd; continue; }
        files.push({ naam:name, methode:method===0?"stored":"deflate", bytes:out });
      } catch (e) {
        files.push({ naam:name, fout:e.message });
      }
      i = dataEnd;
    } else i++;
    if (files.length > 200) break;
  }
  return files;
}

// ---------- PDF FLATEDECODE STREAMS ----------
function extractPdfStreams(bytes) {
  const results = [];
  const s = bytesToUtf8(bytes);
  const streamRx = /stream\r?\n([\s\S]*?)\r?\nendstream/g;
  let m; let idx = 0;
  while ((m = streamRx.exec(s)) !== null && results.length < 100) {
    const raw = m[1];
    // Zoek naar zlib-header 0x78 als eerste byte
    const bs = [];
    for (let i = 0; i < raw.length; i++) bs.push(raw.charCodeAt(i) & 0xFF);
    const u8 = new Uint8Array(bs);
    if (u8[0] === 0x78) {
      try {
        const dec = zlibInflate(u8);
        results.push({ offset: m.index, gedecomprimeerd_lengte: dec.length, tekst: bytesToUtf8(dec).slice(0, 4000) });
      } catch (e) {
        results.push({ offset: m.index, fout: e.message });
      }
    }
    idx++;
  }
  return results;
}

// ---------- TEKST-DEOBFUSCATIE (v7-logica op string) ----------
function stripZeroWidth(s) {
  let out = ""; for (let i = 0; i < s.length; i++) if (!zwSet.has(s.charCodeAt(i))) out += s[i];
  return out;
}
function normalizeHomoglyphs(s) {
  let out = "";
  for (let i = 0; i < s.length; i++) out += homoglyphMap[s.charCodeAt(i)] || s[i];
  return out;
}
function decodeHtmlEntities(s) {
  return s
    .replace(/&#x([0-9a-fA-F]+);/g, (_, h) => { try { return String.fromCodePoint(parseInt(h,16)); } catch(e){ return _; } })
    .replace(/&#(\d+);/g, (_, d) => { try { return String.fromCodePoint(parseInt(d,10)); } catch(e){ return _; } })
    .replace(/&([a-zA-Z]+);/g, (_, n) => htmlEntities[n] || _);
}
function decodeJsEscapes(s) {
  return s.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h,16)))
          .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h,16)));
}
function decodeUrlRecursive(s) {
  let out = s, prev = null, d = 0;
  while (out !== prev && d < 3) { prev = out; try { out = decodeURIComponent(out.replace(/\+/g, "%20")); } catch(e){ break; } d++; }
  return out;
}
function decodeQP(s) {
  return s.replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h,16))).replace(/=\r?\n/g, "");
}
function decodeB64Str(str) {
  try {
    const d = Data.fromBase64String(str.replace(/-/g,"+").replace(/_/g,"/"));
    if (!d) return null;
    const bytes = new Uint8Array(d.getBytes());
    return bytesToUtf8(bytes);
  } catch (e) { return null; }
}
function extractHiddenHtml(s) {
  const hits = [];
  const rxs = [
    /<[^>]+\bhidden\b[^>]*>([\s\S]*?)<\/[^>]+>/gi,
    /<[^>]+\baria-hidden\s*=\s*["']true["'][^>]*>([\s\S]*?)<\/[^>]+>/gi,
    /<[^>]+style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0|color\s*:\s*transparent)[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>/gi,
    /<template[^>]*>([\s\S]*?)<\/template>/gi,
    /<noscript[^>]*>([\s\S]*?)<\/noscript>/gi
  ];
  for (const rx of rxs) {
    let m; rx.lastIndex = 0;
    while ((m = rx.exec(s)) !== null) {
      const inner = m[1].replace(/<[^>]+>/g," ").trim();
      if (inner && inner.length > 2) hits.push(inner);
    }
  }
  return hits;
}
function extractStringsFromBytes(bytes, minLen) {
  const out = []; let cur = "";
  for (let i = 0; i < bytes.length; i++) {
    const c = bytes[i];
    if ((c >= 0x20 && c < 0x7F) || c === 0x09) cur += String.fromCharCode(c);
    else { if (cur.length >= minLen) out.push(cur); cur = ""; }
  }
  if (cur.length >= minLen) out.push(cur);
  return out;
}
function splitHttp(s) {
  const m = /^(HTTP\/[0-9.]+ \d{3}[\s\S]*?)\r?\n\r?\n([\s\S]*)$/.exec(s);
  return m ? { headers: m[1], body: m[2] } : null;
}
function nlZorgIds(s) {
  const out = {};
  const bsn = (s.match(/\b\d{9}\b/g) || []).filter(n => {
    let x = 0; for (let i=0;i<8;i++) x += parseInt(n[i],10)*(9-i); x -= parseInt(n[8],10);
    return x % 11 === 0 && n !== "000000000";
  });
  if (bsn.length) out.bsn_11proef = Array.from(new Set(bsn)).slice(0,30);
  const agb = s.match(/\bAGB[- ]?\d{8}\b/gi); if (agb) out.agb = Array.from(new Set(agb));
  const big = s.match(/\b\d{11}\s*BIG\b/gi); if (big) out.big = Array.from(new Set(big));
  const uzi = s.match(/\bUZI[- ]?\d{9,}\b/gi); if (uzi) out.uzi = Array.from(new Set(uzi));
  const oids = s.match(/\b2\.16\.\d+(?:\.\d+){2,}\b/g); if (oids) out.oids = Array.from(new Set(oids)).slice(0,50);
  const urls = s.match(/https?:\/\/[^\s"'<>)]+/gi); if (urls) out.urls = Array.from(new Set(urls)).slice(0,100);
  const emails = s.match(/[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g); if (emails) out.emails = Array.from(new Set(emails)).slice(0,30);
  const cda = s.match(/<ClinicalDocument[^>]*/gi); if (cda) out.hl7_cda = cda.slice(0,5);
  const fhir = s.match(/"resourceType"\s*:\s*"[A-Z][A-Za-z]+"/g); if (fhir) out.fhir_resources = Array.from(new Set(fhir)).slice(0,30);
  const xdm = s.match(/METADATA\.XML|IHE_XDM|SUBSET\d+/gi); if (xdm) out.ihe_xdm = Array.from(new Set(xdm));
  return out;
}

// ---------- HOOFDEXTRACTIE (bytes-first) ----------
function processBytes(bytes, fileInfo) {
  fileInfo.grootte_bytes = bytes.length;
  const container = detectContainer(bytes);
  fileInfo.container = container ? container.type : "plain_text";

  let workBytes = bytes;
  const layers = [];

  // DECOMPRESSIE
  if (container && container.type === "gzip") {
    try { workBytes = gunzip(bytes); layers.push("gzip → geïnflateerd (" + workBytes.length + " bytes)"); }
    catch (e) { fileInfo.gzip_fout = e.message; return finalizeBytesOnly(bytes, fileInfo, layers); }
  } else if (container && container.type === "zlib") {
    try { workBytes = zlibInflate(bytes); layers.push("zlib → geïnflateerd"); }
    catch (e) { fileInfo.zlib_fout = e.message; return finalizeBytesOnly(bytes, fileInfo, layers); }
  } else if (container && container.type === "zip") {
    const entries = unzip(bytes);
    fileInfo.zip_entries = entries.map(e => ({
      naam: e.naam, methode: e.methode, lengte_uncompressed: e.bytes ? e.bytes.length : null, fout: e.fout
    }));
    // Verwerk elke entry apart
    fileInfo.zip_content = [];
    for (const entry of entries) {
      if (!entry.bytes) continue;
      const sub = { naam: entry.naam, grootte_bytes: entry.bytes.length };
      processBytes(entry.bytes, sub);
      fileInfo.zip_content.push(sub);
    }
    layers.push("ZIP → " + entries.length + " entries uitgepakt");
    fileInfo.layers_toegepast = layers;
    return;
  } else if (container && container.type === "pdf") {
    fileInfo.pdf_streams = extractPdfStreams(bytes);
    layers.push("PDF → " + fileInfo.pdf_streams.length + " FlateDecode-streams geïnflateerd");
    // Ga door met tekst-analyse van de PDF-tekst (tussen streams)
  } else if (container && (container.type === "7z" || container.type === "rar" || container.type === "zstd")) {
    fileInfo.instructie = container.type + " kan Scriptable niet native uitpakken. Voer op je Mac/iSH: `7z x bestand` / `unrar x` / `zstd -d` — deel daarna de output.";
    fileInfo.hex_dump_128 = hexDump(bytes, 128);
    fileInfo.strings_uit_binary = extractStringsFromBytes(bytes, MIN_STRING_LEN).slice(0, 500);
    fileInfo.layers_toegepast = layers;
    return;
  } else if (container && (container.type === "png" || container.type === "jpeg")) {
    fileInfo.instructie = "Image-bestand. Strings-scan uitgevoerd; voor EXIF/XMP een aparte tool.";
    fileInfo.hex_dump_128 = hexDump(bytes, 128);
    fileInfo.strings_uit_binary = extractStringsFromBytes(bytes, 6).slice(0, 200);
    fileInfo.layers_toegepast = layers;
    return;
  }

  // TEKST-ANALYSE op workBytes
  const text = bytesToUtf8(workBytes);
  if (workBytes[0] === 0xFEFF || text.charCodeAt(0) === 0xFEFF) layers.push("BOM aanwezig");

  // Zero-width & homoglyph bewijs
  const zwFindings = [], hgFindings = [];
  for (let i = 0; i < text.length; i++) {
    const c = text.charCodeAt(i);
    if (zwSet.has(c) && zwFindings.length < 40) zwFindings.push({ offset:i, codepoint:"U+"+c.toString(16).toUpperCase().padStart(4,"0") });
    if (homoglyphMap[c] && hgFindings.length < 40) hgFindings.push({ offset:i, gevonden:text[i], lijkt_op:homoglyphMap[c] });
  }
  const normalized = normalizeHomoglyphs(stripZeroWidth(text));
  if (zwFindings.length) layers.push("zero-width/BIDI gestript");
  if (hgFindings.length) layers.push("homoglyphs → ASCII");

  const revealed = {};
  if (zwFindings.length) revealed.onzichtbare_unicode = zwFindings;
  if (hgFindings.length) revealed.homoglyphs = hgFindings;

  // HTTP splitten
  const http = splitHttp(normalized);
  const bodyText = http ? http.body : normalized;
  if (http) { revealed.http_headers = http.headers; layers.push("HTTP-response gesplitst"); }

  // HTML/XML comments + verborgen tekst
  const comments = [];
  { const rx = /<!--([\s\S]*?)-->/g; let m;
    while ((m = rx.exec(bodyText)) !== null && comments.length < 100) {
      const t = m[1].trim(); if (t.length > 2) comments.push(t);
    }
  }
  if (comments.length) { revealed.html_xml_comments = comments; layers.push("HTML/XML-comments"); }
  const hidden = extractHiddenHtml(bodyText);
  if (hidden.length) { revealed.verborgen_html_tekst = hidden.slice(0,60); layers.push("verborgen HTML/CSS tekst"); }

  // Base64 in tekst → decoderen (bovenop de al gedecodeerde binaire content)
  const b64Rx = /[A-Za-z0-9+/_-]{40,}={0,2}/g;
  const b64Hits = []; let bm; let bc = 0;
  while ((bm = b64Rx.exec(bodyText)) !== null && bc < 40) {
    const dec = decodeB64Str(bm[0]);
    if (dec && /[\x20-\x7E]{6,}/.test(dec)) { b64Hits.push({ offset:bm.index, tekst:dec.slice(0,600) }); bc++; }
  }
  if (b64Hits.length) { revealed.base64_gedecodeerd = b64Hits; layers.push("base64-blobs (" + bc + ")"); }

  // JWT
  const jwts = [];
  { const rx = /\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)?/g; let m;
    while ((m = rx.exec(bodyText)) !== null && jwts.length < 20) {
      const p = m[0].split(".");
      jwts.push({ header: decodeB64Str(p[0]), payload: decodeB64Str(p[1]) });
    }
  }
  if (jwts.length) { revealed.jwt_tokens = jwts; layers.push("JWT gedecodeerd (" + jwts.length + ")"); }

  // Andere text-decoders
  if (/&(?:#\d+|#x[0-9A-Fa-f]+|[a-zA-Z]+);/.test(bodyText)) {
    revealed.html_entities_decoded = decodeHtmlEntities(bodyText.slice(0, 20000));
    layers.push("HTML entities");
  }
  if (/\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}/.test(bodyText)) {
    revealed.js_escapes_decoded = decodeJsEscapes(bodyText.slice(0, 20000));
    layers.push("JS-escapes");
  }
  if (/%[0-9A-Fa-f]{2}/.test(bodyText)) {
    revealed.url_encoded_decoded = decodeUrlRecursive(bodyText.slice(0, 20000));
    layers.push("URL-encoding (recursief)");
  }
  if (/=[0-9A-Fa-f]{2}(?:=[0-9A-Fa-f]{2}){2,}/.test(bodyText)) {
    revealed.quoted_printable_decoded = decodeQP(bodyText.slice(0, 20000));
    layers.push("quoted-printable");
  }

  // NL zorg identifiers
  const nlz = nlZorgIds(bodyText);
  if (Object.keys(nlz).length) revealed.nl_zorg_identifiers = nlz;

  // Strings uit ALLE bytes (inclusief oorspronkelijke)
  revealed.strings_uit_body = extractStringsFromBytes(workBytes, MIN_STRING_LEN).slice(0, 800);

  // Consolidatie
  const parts = [];
  parts.push("=== NORMALIZED TEKST ===\n" + normalized.slice(0, 60000));
  if (http) parts.push("=== HTTP HEADERS ===\n" + http.headers);
  if (comments.length) parts.push("=== HTML/XML COMMENTS ===\n" + comments.join("\n---\n"));
  if (hidden.length) parts.push("=== VERBORGEN HTML/CSS TEKST ===\n" + hidden.join("\n---\n"));
  if (b64Hits.length) parts.push("=== BASE64 GEDECODEERD ===\n" + b64Hits.map(h=>"[@"+h.offset+"]\n"+h.tekst).join("\n---\n"));
  if (jwts.length) parts.push("=== JWT ===\n" + jwts.map(j=>"header="+j.header+"\npayload="+j.payload).join("\n---\n"));
  if (fileInfo.pdf_streams) parts.push("=== PDF FLATE STREAMS ===\n" + fileInfo.pdf_streams.map(p=>p.tekst||("fout: "+p.fout)).join("\n---\n"));

  fileInfo.deobfuscated_text = parts.join("\n\n");
  fileInfo.layers_toegepast = layers;
  fileInfo.revealed = revealed;
}

function finalizeBytesOnly(bytes, fileInfo, layers) {
  fileInfo.hex_dump_128 = hexDump(bytes, 128);
  fileInfo.strings_uit_binary = extractStringsFromBytes(bytes, MIN_STRING_LEN).slice(0, 500);
  fileInfo.layers_toegepast = layers;
}

// ---------- HOOFDLOOP ----------
const rapport = [];
for (let i = 0; i < inputs.length; i++) {
  const item = inputs[i];
  const path = resolvePath(item);
  const name = fileNameOf(item, path);
  const fileInfo = { bestandsnaam: name, pad: path || "-", status: "OK" };

  try {
    let bytes = null;
    if (item && item.__inlineText) {
      // string → bytes voor uniforme flow
      const arr = [];
      for (let j = 0; j < item.__inlineText.length; j++) arr.push(item.__inlineText.charCodeAt(j) & 0xFF);
      bytes = new Uint8Array(arr);
    } else {
      if (!path) { fileInfo.status="ERROR"; fileInfo.reden="geen pad"; rapport.push(fileInfo); continue; }
      if (!fmLocal.fileExists(path)) { fileInfo.status="ERROR"; fileInfo.reden="niet gevonden"; rapport.push(fileInfo); continue; }
      if (fmLocal.isFileStoredIniCloud && fmLocal.isFileStoredIniCloud(path) &&
          fmLocal.isFileDownloaded && !fmLocal.isFileDownloaded(path)) {
        try { fmLocal.downloadFileFromiCloud(path); } catch (e) {}
      }
      const size = fmLocal.fileSize(path) * 1024;
      if (size > MAX_BYTES) {
        fileInfo.status="SKIPPED"; fileInfo.reden="> " + Math.round(MAX_BYTES/1024/1024) + "MB";
        rapport.push(fileInfo); continue;
      }
      bytes = readBytes(path);
    }
    if (!bytes || bytes.length === 0) {
      fileInfo.status="UNREADABLE"; fileInfo.reden="leeg of niet leesbaar";
      rapport.push(fileInfo); continue;
    }
    processBytes(bytes, fileInfo);
    rapport.push(fileInfo);
  } catch (error) {
    fileInfo.status = "ERROR";
    fileInfo.reden = (error && error.message) ? error.message : String(error);
    rapport.push(fileInfo);
  }
}

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
