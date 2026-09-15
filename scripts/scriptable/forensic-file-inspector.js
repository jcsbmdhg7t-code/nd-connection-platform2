// ============================================================
// FORENSIC FILE INSPECTOR v11 — GECONSOLIDEERD
// v11 = v10-features (matroesjka + steganografie + zichtbaarheid-
//       splitsing + CDA-heuristieken + auto-decode) BOVENOP de rijke
//       v9.1-basislaag die in v10 was afgeslankt.
//
// Teruggebracht uit v9.1 (t.o.v. v10):
//   - UTF-16 LE/BE + Windows-1252 encoding-detect en decoders
//   - Magic-byte containerdetectie (gzip/zlib/zip/pdf/png/jpeg/7z/rar/
//     zstd/executables/bplist/sqlite/rtf/appledouble)
//   - ZIP central-directory scanner + Office (DOCX/XLSX/PPTX) tekst
//   - PDF /Info, XMP en gedecomprimeerde FlateDecode-streams
//   - PNG tEXt/zTXt/iTXt + JPEG COM/APP1/APP13 metadata
//   - HTTP splitsen, chunked-decoding, multipart/form-data, cookies
//   - HAR (Chrome/Safari/Proxyman) parsing
//   - Data-URI extractie, meta-tags, meta-refresh, source-map URLs
//   - Base32, punycode xn--, ROT13 auto, JWT triple-splits
//   - Signed-URL params, line-ending anomalie, whitespace-stego,
//     timestamps, strings-uit-binary
//   - IHE XDM markers, IPv4-filter dat HL7-OIDs uitsluit
//   - TinyInflate/DEFLATE-inflater (v9-tak) — GEGUARD in try/catch
//     zodat een JSC-crash op oudere toestellen niet het hele rapport
//     sloopt: falen wordt als 'inflate_unavailable'-laag gemeld.
//
// Behouden uit v10:
//   - Matroesjka-recursie (tot 6 lagen diep)
//   - Steganografie-detectie (whitespace/zero-width/CSS/comments/
//     bare zw-tekens/homoglyphs)
//   - Zichtbaarheid-splitsing (narrative vs entries)
//   - CDA-heuristieken (self-close, re-codering, versie-explosie,
//     batch-mutaties, placeholder-adressen, chain-of-custody)
//   - NL-zorg-identifiers (BSN-11-proef, AGB/BIG/UZI, OIDs, FHIR)
// ============================================================

const fm      = FileManager.iCloud ? FileManager.iCloud() : FileManager.local();
const fmLocal = FileManager.local();

const inApp        = config.runsInApp;
const inShareSheet = config.runsInActionExtension;
const inSiri       = config.runsWithSiri;

const MAX_BYTES  = (inShareSheet || inSiri) ? 50 * 1024 * 1024 : 500 * 1024 * 1024;
const SCAN_HEAD  = (inShareSheet || inSiri) ? 512 * 1024        : 8  * 1024 * 1024;
const MATROESJKA_MAX_DEPTH = 6;
const MIN_STRING_LEN = 4;
const INFLATE_MAX_OUT = 32 * 1024 * 1024;

// ============================================================
// TINY-INFLATE (MIT, foliojs) — DEFLATE decoder, GEGUARD
// Op oude JSC-versies kan de initialisatie of het gebruik van deze
// tak crashen. We isoleren alles in try/catch en vallen anders terug
// op een stub die netjes een fout gooit — het rapport gaat door.
// ============================================================
let inflate = null;
let gunzip = null;
let zlibInflate = null;
let tinyinflateStatus = "unavailable";
let tinyinflateFout = null;
try {
  function makeInflate() {
    const TINF_OK = 0, TINF_DATA_ERROR = -3;
    function Tree() { this.table = new Uint16Array(16); this.trans = new Uint16Array(288); }
    function DataCtx(source, dest) {
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
      for (i = 0; i < num; i++) { if (lens[off + i]) t.trans[offs[lens[off + i]]++] = i; }
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
          case 16: { const prev = lengths[num - 1]; for (length = tinf_read_bits(d, 2, 3); length; --length) lengths[num++] = prev; break; }
          case 17: for (length = tinf_read_bits(d, 3, 3); length; --length) lengths[num++] = 0; break;
          case 18: for (length = tinf_read_bits(d, 7, 11); length; --length) lengths[num++] = 0; break;
          default: lengths[num++] = sym; break;
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
      const d = new DataCtx(source, dest || new Uint8Array(source.length * 8));
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
  inflate = makeInflate();
  gunzip = function (bytes) {
    if (bytes[0] !== 0x1F || bytes[1] !== 0x8B) throw new Error("not gzip");
    let i = 10; const flg = bytes[3];
    if (flg & 0x04) { const xlen = bytes[i] | (bytes[i+1] << 8); i += 2 + xlen; }
    if (flg & 0x08) { while (bytes[i] !== 0) i++; i++; }
    if (flg & 0x10) { while (bytes[i] !== 0) i++; i++; }
    if (flg & 0x02) i += 2;
    return inflate(bytes.subarray(i));
  };
  zlibInflate = function (bytes) {
    if ((bytes[0] & 0x0F) !== 8) throw new Error("not zlib");
    return inflate(bytes.subarray(2));
  };
  tinyinflateStatus = "available";
} catch (e) {
  tinyinflateFout = (e && e.message) ? e.message : String(e);
  const stub = function () { throw new Error("tinyinflate niet beschikbaar in deze JSC: " + tinyinflateFout); };
  inflate = stub; gunzip = stub; zlibInflate = stub;
}

// ============================================================
// INPUT
// ============================================================
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
} else {

// ============================================================
// UNICODE MAPS
// ============================================================
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
const win1252 = {
  0x80:'€',0x82:'‚',0x83:'ƒ',0x84:'„',0x85:'…',0x86:'†',0x87:'‡',0x88:'ˆ',0x89:'‰',
  0x8A:'Š',0x8B:'‹',0x8C:'Œ',0x8E:'Ž',0x91:'‘',0x92:'’',0x93:'“',0x94:'”',
  0x95:'•',0x96:'–',0x97:'—',0x98:'˜',0x99:'™',0x9A:'š',0x9B:'›',0x9C:'œ',0x9E:'ž',0x9F:'Ÿ'
};

// ============================================================
// HELPERS
// ============================================================
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
function readBytes(path) {
  try {
    const d = Data.fromFile(path); if (!d) return null;
    return new Uint8Array(d.getBytes());
  } catch (e) { return null; }
}

// ---------- ENCODING DETECT + DECODE ----------
function detectEncoding(bytes) {
  if (bytes.length >= 3 && bytes[0] === 0xEF && bytes[1] === 0xBB && bytes[2] === 0xBF) return { enc:"utf-8-bom", skip:3 };
  if (bytes.length >= 2 && bytes[0] === 0xFF && bytes[1] === 0xFE) return { enc:"utf-16le", skip:2 };
  if (bytes.length >= 2 && bytes[0] === 0xFE && bytes[1] === 0xFF) return { enc:"utf-16be", skip:2 };
  let evenZero = 0, oddZero = 0, sample = Math.min(bytes.length, 200);
  for (let i = 0; i < sample; i++) {
    if (bytes[i] === 0) { if (i % 2 === 0) evenZero++; else oddZero++; }
  }
  if (oddZero > sample * 0.3) return { enc:"utf-16le", skip:0 };
  if (evenZero > sample * 0.3) return { enc:"utf-16be", skip:0 };
  let high1252 = 0;
  for (let i = 0; i < sample; i++) if (bytes[i] >= 0x80 && bytes[i] <= 0x9F) high1252++;
  if (high1252 > 5) return { enc:"windows-1252", skip:0 };
  return { enc:"utf-8", skip:0 };
}
function bytesToUtf8(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b < 0x80) s += String.fromCharCode(b);
    else if ((b & 0xE0) === 0xC0 && i+1 < bytes.length) { s += String.fromCharCode(((b & 0x1F) << 6) | (bytes[i+1] & 0x3F)); i++; }
    else if ((b & 0xF0) === 0xE0 && i+2 < bytes.length) { s += String.fromCharCode(((b & 0x0F) << 12) | ((bytes[i+1] & 0x3F) << 6) | (bytes[i+2] & 0x3F)); i += 2; }
    else if ((b & 0xF8) === 0xF0 && i+3 < bytes.length) {
      const cp = ((b & 0x07) << 18) | ((bytes[i+1] & 0x3F) << 12) | ((bytes[i+2] & 0x3F) << 6) | (bytes[i+3] & 0x3F);
      try { s += String.fromCodePoint(cp); } catch(e){ s += "?"; } i += 3;
    } else s += String.fromCharCode(b);
  }
  return s;
}
function bytesToUtf16(bytes, be) {
  let s = "";
  for (let i = 0; i + 1 < bytes.length; i += 2) {
    const c = be ? (bytes[i] << 8) | bytes[i+1] : (bytes[i+1] << 8) | bytes[i];
    if (c) s += String.fromCharCode(c);
  }
  return s;
}
function bytesToWin1252(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    s += (b < 0x80) ? String.fromCharCode(b) : (win1252[b] || String.fromCharCode(b));
  }
  return s;
}
function bytesToStringAuto(bytes) {
  const enc = detectEncoding(bytes);
  const body = bytes.subarray(enc.skip);
  let text;
  if (enc.enc.startsWith("utf-16")) text = bytesToUtf16(body, enc.enc === "utf-16be");
  else if (enc.enc === "windows-1252") text = bytesToWin1252(body);
  else text = bytesToUtf8(body);
  return { text: text, encoding: enc.enc };
}
function hexDump(bytes, n) {
  const lim = Math.min(bytes.length, n || 128);
  const out = [];
  for (let i = 0; i < lim; i++) out.push(bytes[i].toString(16).padStart(2,"0"));
  return out.join(" ");
}

// ============================================================
// MAGIC BYTES
// ============================================================
function detectContainer(bytes) {
  if (!bytes || bytes.length < 4) return null;
  const b0=bytes[0], b1=bytes[1], b2=bytes[2], b3=bytes[3];
  if (b0===0x1F && b1===0x8B) return { type:"gzip" };
  if (b0===0x78 && (b1===0x9C || b1===0xDA || b1===0x01)) return { type:"zlib" };
  if (b0===0x50 && b1===0x4B && b2===0x03 && b3===0x04) return { type:"zip" };
  if (b0===0x25 && b1===0x50 && b2===0x44 && b3===0x46) return { type:"pdf" };
  if (b0===0x37 && b1===0x7A && b2===0xBC && b3===0xAF) return { type:"7z" };
  if (b0===0x52 && b1===0x61 && b2===0x72 && b3===0x21) return { type:"rar" };
  if (b0===0x28 && b1===0xB5 && b2===0x2F && b3===0xFD) return { type:"zstd" };
  if (b0===0x89 && b1===0x50 && b2===0x4E && b3===0x47) return { type:"png" };
  if (b0===0xFF && b1===0xD8 && b2===0xFF) return { type:"jpeg" };
  if (b0===0x4D && b1===0x5A) return { type:"executable-mz" };
  if (b0===0x7F && b1===0x45 && b2===0x4C && b3===0x46) return { type:"executable-elf" };
  if (b0===0xFE && b1===0xED && b2===0xFA) return { type:"executable-macho" };
  if (b0===0xCA && b1===0xFE && b2===0xBA && b3===0xBE) return { type:"java-class" };
  if (b0===0x62 && b1===0x70 && b2===0x6C && b3===0x69) return { type:"bplist" };
  if (b0===0x30 && b1===0x0D && b2===0x30 && b3===0x0A) return { type:"appledouble" };
  if (b0===0x00 && b1===0x05 && b2===0x16 && b3===0x07) return { type:"appledouble" };
  if (b0===0x7B && b1===0x5C && b2===0x72 && b3===0x74) return { type:"rtf" };
  if (b0===0x53 && b1===0x51 && b2===0x4C && b3===0x69) return { type:"sqlite" };
  return null;
}

// ============================================================
// ZIP + OFFICE XML
// ============================================================
function unzip(bytes) {
  const files = []; let i = 0;
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
        else if (method === 8) {
          try { out = inflate(raw, new Uint8Array(Math.max(uncompSize, raw.length * 8))); }
          catch (ie) { files.push({ naam:name, methode:"deflate", fout:"tinyinflate: " + ie.message }); i = dataEnd; continue; }
        }
        else { files.push({ naam:name, methode:method, fout:"onbekende compressie" }); i = dataEnd; continue; }
        files.push({ naam:name, methode:method===0?"stored":"deflate", bytes:out });
      } catch (e) { files.push({ naam:name, fout:e.message }); }
      i = dataEnd;
    } else i++;
    if (files.length > 500) break;
  }
  return files;
}
function extractOfficeXmlText(xmlStr) {
  const texts = [];
  let m; const wRx = /<w:t(?:\s[^>]*)?>([\s\S]*?)<\/w:t>/g;
  while ((m = wRx.exec(xmlStr)) !== null) texts.push(m[1]);
  const tRx = /<t(?:\s[^>]*)?>([\s\S]*?)<\/t>/g;
  while ((m = tRx.exec(xmlStr)) !== null) texts.push(m[1]);
  const aRx = /<a:t(?:\s[^>]*)?>([\s\S]*?)<\/a:t>/g;
  while ((m = aRx.exec(xmlStr)) !== null) texts.push(m[1]);
  return texts;
}

// ============================================================
// PDF DIEP
// ============================================================
function extractPdfInfo(bytes) {
  const info = {};
  const s = bytesToUtf8(bytes);
  const rx = /\/(Title|Author|Producer|Creator|Subject|Keywords|CreationDate|ModDate)\s*(\(([^)]*)\)|<([0-9A-Fa-f\s]+)>)/g;
  let m;
  while ((m = rx.exec(s)) !== null) {
    let v = m[3];
    if (!v && m[4]) {
      const hex = m[4].replace(/\s/g, "");
      let out = "";
      for (let i = 0; i + 1 < hex.length; i += 2) out += String.fromCharCode(parseInt(hex.substr(i,2),16));
      v = out;
    }
    info[m[1]] = v;
  }
  const xmp = /<x:xmpmeta[\s\S]*?<\/x:xmpmeta>/.exec(s);
  if (xmp) info.__xmp = xmp[0];
  return info;
}
function extractPdfStreams(bytes) {
  const results = [];
  if (tinyinflateStatus !== "available") {
    return [{ status: "SKIP", reden: "tinyinflate niet beschikbaar; PDF FlateDecode-streams niet uitgepakt", tinyinflate_fout: tinyinflateFout }];
  }
  const s = bytesToUtf8(bytes);
  const rx = /stream\r?\n([\s\S]*?)\r?\nendstream/g;
  let m;
  while ((m = rx.exec(s)) !== null && results.length < 200) {
    const raw = m[1];
    const bs = new Uint8Array(raw.length);
    for (let i = 0; i < raw.length; i++) bs[i] = raw.charCodeAt(i) & 0xFF;
    if (bs[0] === 0x78) {
      try {
        const dec = zlibInflate(bs);
        const text = bytesToUtf8(dec);
        const isObjStm = /^\d+\s+\d+\s+/.test(text);
        results.push({
          offset: m.index,
          type: isObjStm ? "ObjStm (compressed objects)" : "content",
          lengte_uncompressed: dec.length,
          tekst: text.slice(0, 6000)
        });
      } catch (e) { results.push({ offset: m.index, fout: e.message }); }
    }
  }
  return results;
}

// ============================================================
// PNG / JPEG METADATA
// ============================================================
function extractPngMetadata(bytes) {
  const chunks = [];
  let i = 8;
  while (i < bytes.length - 12) {
    const len = (bytes[i]<<24) | (bytes[i+1]<<16) | (bytes[i+2]<<8) | bytes[i+3];
    const type = String.fromCharCode(bytes[i+4], bytes[i+5], bytes[i+6], bytes[i+7]);
    const dataStart = i + 8;
    if (type === "tEXt") {
      const chunk = bytes.subarray(dataStart, dataStart + len);
      let k = 0; while (k < chunk.length && chunk[k] !== 0) k++;
      chunks.push({ type:"tEXt", key: bytesToUtf8(chunk.subarray(0, k)), value: bytesToUtf8(chunk.subarray(k+1)) });
    } else if (type === "zTXt") {
      const chunk = bytes.subarray(dataStart, dataStart + len);
      let k = 0; while (k < chunk.length && chunk[k] !== 0) k++;
      const key = bytesToUtf8(chunk.subarray(0, k));
      if (tinyinflateStatus === "available") {
        try {
          const dec = zlibInflate(chunk.subarray(k + 2));
          chunks.push({ type:"zTXt", key: key, value: bytesToUtf8(dec) });
        } catch (e) { chunks.push({ type:"zTXt", key: key, fout: e.message }); }
      } else {
        chunks.push({ type:"zTXt", key: key, fout: "tinyinflate niet beschikbaar" });
      }
    } else if (type === "iTXt") {
      const chunk = bytes.subarray(dataStart, dataStart + len);
      chunks.push({ type:"iTXt", raw: bytesToUtf8(chunk).slice(0, 500) });
    } else if (type === "IEND") break;
    i = dataStart + len + 4;
    if (chunks.length > 40) break;
  }
  return chunks;
}
function extractJpegMetadata(bytes) {
  const segments = [];
  let i = 2;
  while (i < bytes.length - 4) {
    if (bytes[i] !== 0xFF) break;
    const marker = bytes[i+1];
    if (marker === 0xD9 || marker === 0xDA) break;
    const len = (bytes[i+2]<<8) | bytes[i+3];
    if (marker === 0xFE) {
      segments.push({ type:"COM (comment)", text: bytesToUtf8(bytes.subarray(i+4, i+2+len)) });
    } else if (marker === 0xE1) {
      const head = bytesToUtf8(bytes.subarray(i+4, i+4+30));
      if (head.indexOf("Exif") === 0) segments.push({ type:"APP1 EXIF", note:"EXIF blok aanwezig; volledige parsing buiten scope" });
      else if (head.indexOf("http://ns.adobe.com/xap") === 0) segments.push({ type:"APP1 XMP", xmp: bytesToUtf8(bytes.subarray(i+4, i+2+len)).slice(0, 3000) });
    } else if (marker === 0xED) {
      segments.push({ type:"APP13 IPTC", note:"IPTC blok aanwezig" });
    }
    i += 2 + len;
    if (segments.length > 20) break;
  }
  return segments;
}

// ============================================================
// HTTP / HAR / MULTIPART
// ============================================================
function splitHttp(s) {
  const m = /^(HTTP\/[0-9.]+ \d{3}[\s\S]*?)\r?\n\r?\n([\s\S]*)$/.exec(s);
  return m ? { headers: m[1], body: m[2] } : null;
}
function parseHeaders(headerBlock) {
  const h = {};
  const lines = headerBlock.split(/\r?\n/);
  for (const line of lines) {
    const idx = line.indexOf(":");
    if (idx > 0) h[line.slice(0, idx).trim().toLowerCase()] = line.slice(idx+1).trim();
  }
  return h;
}
function dechunk(body) {
  let out = ""; let i = 0;
  while (i < body.length) {
    const nl = body.indexOf("\r\n", i);
    if (nl < 0) break;
    const size = parseInt(body.slice(i, nl), 16);
    if (isNaN(size) || size === 0) break;
    i = nl + 2;
    out += body.slice(i, i + size);
    i += size + 2;
  }
  return out;
}
function parseMultipart(body, boundary) {
  const parts = [];
  const sep = "--" + boundary;
  const chunks = body.split(sep);
  for (let k = 1; k < chunks.length - 1; k++) {
    const chunk = chunks[k];
    const idx = chunk.indexOf("\r\n\r\n");
    if (idx > 0) parts.push({ headers: chunk.slice(0, idx).trim(), body: chunk.slice(idx+4).trim() });
  }
  return parts;
}
function parseHar(jsonStr) {
  try {
    const har = JSON.parse(jsonStr);
    if (!har.log || !har.log.entries) return null;
    return har.log.entries.map(e => ({
      startedDateTime: e.startedDateTime,
      method: e.request && e.request.method,
      url: e.request && e.request.url,
      status: e.response && e.response.status,
      mimeType: e.response && e.response.content && e.response.content.mimeType,
      cookies: (e.request && e.request.cookies || []).map(c => c.name + "=" + c.value),
      requestHeaders: (e.request && e.request.headers || []).slice(0, 20),
      responseSize: e.response && e.response.bodySize,
      responseText: e.response && e.response.content && e.response.content.text ? String(e.response.content.text).slice(0, 2000) : null
    }));
  } catch (e) { return null; }
}
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

// ============================================================
// TEXT DEOBFUSCATION
// ============================================================
function stripZeroWidth(s) {
  let out = ""; for (let i = 0; i < s.length; i++) if (!zwSet.has(s.charCodeAt(i))) out += s[i]; return out;
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
          .replace(/\\x([0-9a-fA-F]{2})/g, (_, h) => String.fromCharCode(parseInt(h,16)))
          .replace(/\\u\{([0-9a-fA-F]{1,6})\}/g, (_, h) => { try { return String.fromCodePoint(parseInt(h,16)); } catch(e){ return _; } });
}
function decodeUrlOnce(s) { try { return decodeURIComponent(s.replace(/\+/g, "%20")); } catch (e) { return s; } }
function decodeUrlRecursive(s) {
  let out = s, prev = null, d = 0;
  while (out !== prev && d < 4) { prev = out; try { out = decodeURIComponent(out.replace(/\+/g, "%20")); } catch(e){ break; } d++; }
  return out;
}
function decodeQP(s) {
  return s.replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h,16))).replace(/=\r?\n/g, "");
}
function decodeB64Str(str) {
  try {
    const d = Data.fromBase64String(str.replace(/-/g,"+").replace(/_/g,"/"));
    if (!d) return null;
    return bytesToUtf8(new Uint8Array(d.getBytes()));
  } catch (e) { return null; }
}
function decodeHex(str) {
  const clean = str.replace(/[^0-9a-fA-F]/g, "");
  if (clean.length < 4 || clean.length % 2) return null;
  let out = "";
  for (let i = 0; i < clean.length; i += 2) out += String.fromCharCode(parseInt(clean.substr(i,2),16));
  return out;
}
function decodeBase32(str) {
  const alph = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  str = str.replace(/=+$/, "").toUpperCase();
  let bits = "";
  for (const c of str) { const v = alph.indexOf(c); if (v < 0) return null; bits += v.toString(2).padStart(5, "0"); }
  let out = "";
  for (let i = 0; i + 8 <= bits.length; i += 8) out += String.fromCharCode(parseInt(bits.substr(i, 8), 2));
  return out;
}
function decodePunycode(label) {
  try {
    if (!label.startsWith("xn--")) return null;
    const input = label.slice(4);
    const base = 36, tmin = 1, tmax = 26, skew = 38, damp = 700, initialBias = 72, initialN = 0x80;
    let n = initialN, i = 0, bias = initialBias, output = [];
    const delim = input.lastIndexOf("-");
    if (delim > 0) { for (let j = 0; j < delim; j++) output.push(input.charCodeAt(j)); }
    let idx = delim >= 0 ? delim + 1 : 0;
    while (idx < input.length) {
      const oldi = i; let w = 1, k = base;
      while (idx < input.length) {
        const c = input.charCodeAt(idx++);
        const digit = c - 48 < 10 ? c - 22 : (c - 65 < 26 ? c - 65 : (c - 97 < 26 ? c - 97 : base));
        if (digit >= base) return null;
        i += digit * w;
        const t = k <= bias ? tmin : (k >= bias + tmax ? tmax : k - bias);
        if (digit < t) break;
        w *= (base - t); k += base;
      }
      const outLen = output.length + 1;
      let delta = i - oldi; delta = oldi === 0 ? Math.floor(delta / damp) : delta >> 1;
      delta += Math.floor(delta / outLen);
      let kk = 0;
      while (delta > 455) { delta = Math.floor(delta / 35); kk += base; }
      bias = kk + Math.floor((36 * delta) / (delta + skew));
      n += Math.floor(i / outLen); i %= outLen;
      output.splice(i++, 0, n);
    }
    return String.fromCodePoint(...output);
  } catch (e) { return null; }
}
function rot13Auto(s) {
  const commonWords = /\b(the|and|van|de|het|een|ik|is|niet|of|op|te|dat|met|voor)\b/gi;
  const before = (s.match(commonWords) || []).length;
  const rotd = s.replace(/[A-Za-z]/g, c => {
    const b = c.charCodeAt(0) < 91 ? 65 : 97;
    return String.fromCharCode((c.charCodeAt(0) - b + 13) % 26 + b);
  });
  const after = (rotd.match(commonWords) || []).length;
  return after > before * 2 ? rotd : null;
}
function extractHiddenHtml(s) {
  const hits = [];
  const rxs = [
    /<[^>]+\bhidden\b[^>]*>([\s\S]*?)<\/[^>]+>/gi,
    /<[^>]+\baria-hidden\s*=\s*["']true["'][^>]*>([\s\S]*?)<\/[^>]+>/gi,
    /<[^>]+style\s*=\s*["'][^"']*(?:display\s*:\s*none|visibility\s*:\s*hidden|opacity\s*:\s*0|font-size\s*:\s*0|color\s*:\s*transparent|clip-path\s*:\s*inset\(100%\)|left\s*:\s*-9999px|position\s*:\s*absolute[^"']*top\s*:\s*-\d+)[^"']*["'][^>]*>([\s\S]*?)<\/[^>]+>/gi,
    /<template[^>]*>([\s\S]*?)<\/template>/gi,
    /<noscript[^>]*>([\s\S]*?)<\/noscript>/gi
  ];
  for (const rx of rxs) {
    let m; rx.lastIndex = 0;
    while ((m = rx.exec(s)) !== null) {
      const inner = (m[1] || m[2] || "").replace(/<[^>]+>/g," ").trim();
      if (inner && inner.length > 2) hits.push(inner);
    }
  }
  return hits;
}
function extractDataUris(s) {
  const hits = [];
  const rx = /data:([a-zA-Z0-9.+\-/]+);base64,([A-Za-z0-9+/=]+)/g;
  let m;
  while ((m = rx.exec(s)) !== null && hits.length < 20) {
    const dec = decodeB64Str(m[2]);
    hits.push({ mime: m[1], lengte_encoded: m[2].length, decoded_preview: dec ? dec.slice(0, 300) : null });
  }
  return hits;
}
function extractMetaTags(s) {
  const tags = [];
  const rx = /<meta[^>]+>/gi;
  let m;
  while ((m = rx.exec(s)) !== null && tags.length < 40) {
    const t = m[0];
    const name = /(?:name|property|http-equiv)\s*=\s*["']([^"']+)["']/i.exec(t);
    const content = /content\s*=\s*["']([^"']*)["']/i.exec(t);
    if (name && content) tags.push({ naam: name[1], inhoud: content[1] });
  }
  return tags;
}
function extractMetaRefresh(s) {
  const hits = [];
  const rx = /<meta[^>]+http-equiv\s*=\s*["']refresh["'][^>]+content\s*=\s*["'][^"']*url=([^"']+)["']/gi;
  let m; while ((m = rx.exec(s)) !== null) hits.push(m[1]);
  return hits;
}
function extractSourceMaps(s) {
  const hits = [];
  const rx = /\/\/[#@]\s*sourceMappingURL=([^\s]+)/g;
  let m; while ((m = rx.exec(s)) !== null) hits.push(m[1]);
  return hits;
}
function unwrapJsonp(s) {
  const m = /^([a-zA-Z_$][\w$]*)\s*\(([\s\S]+?)\)\s*;?\s*$/.exec(s.trim());
  if (m) { try { return { callback: m[1], data: JSON.parse(m[2]) }; } catch (e) {} }
  return null;
}
function extractSignedUrlParams(s) {
  const hits = [];
  const rx = /[?&](X-Amz-[A-Za-z\-]+|Signature|Expires|Policy|KeyId|Credential)=([^&\s"'<>]+)/g;
  let m; while ((m = rx.exec(s)) !== null && hits.length < 30) hits.push({ param: m[1], waarde: m[2] });
  return hits;
}
function analyzeLineEndings(s) {
  const cr = (s.match(/\r(?!\n)/g) || []).length;
  const lf = (s.match(/(?<!\r)\n/g) || []).length;
  const crlf = (s.match(/\r\n/g) || []).length;
  return { crlf: crlf, cr_only: cr, lf_only: lf, mixed: (cr && lf) || (crlf && cr) || (crlf && lf && cr) };
}
function extractTimestamps(s) {
  const iso = s.match(/\b(19|20)\d{2}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?(?:Z|[+\-]\d{2}:?\d{2})?)?/g) || [];
  const nl = s.match(/\b\d{1,2}[-/]\d{1,2}[-/](?:19|20)\d{2}/g) || [];
  return { iso: iso.slice(0, 30), nl: nl.slice(0, 30) };
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

// ============================================================
// MATROESJKA — RECURSIEVE ONTLEDING (v10)
// ============================================================
function matroesjkaDecode(text, depth, log) {
  if (depth >= MATROESJKA_MAX_DEPTH || !text || text.length < 20) return text;
  let changed = false;
  let cur = text;

  if (/&(?:#\d+|#x[0-9A-Fa-f]+|[a-zA-Z]+);/.test(cur)) {
    const n = decodeHtmlEntities(cur);
    if (n !== cur) { log.push({ diepte: depth + 1, laag: "html-entities" }); cur = n; changed = true; }
  }
  if (/\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}/.test(cur)) {
    const n = decodeJsEscapes(cur);
    if (n !== cur) { log.push({ diepte: depth + 1, laag: "js-escapes (\\uNNNN/\\xNN)" }); cur = n; changed = true; }
  }
  if (/%[0-9A-Fa-f]{2}/.test(cur)) {
    const n = decodeUrlOnce(cur);
    if (n !== cur) { log.push({ diepte: depth + 1, laag: "url-encoding" }); cur = n; changed = true; }
  }
  if (/=[0-9A-Fa-f]{2}(?:=[0-9A-Fa-f]{2}){2,}/.test(cur)) {
    const n = decodeQP(cur);
    if (n !== cur) { log.push({ diepte: depth + 1, laag: "quoted-printable" }); cur = n; changed = true; }
  }
  const b64match = cur.match(/[A-Za-z0-9+/_-]{80,}={0,2}/);
  if (b64match) {
    const dec = decodeB64Str(b64match[0]);
    if (dec && /[\x20-\x7E]{6,}/.test(dec)) {
      const n = cur.replace(b64match[0], "[[B64→" + dec.slice(0, 400) + "]]");
      log.push({ diepte: depth + 1, laag: "base64", encoded_start: b64match[0].slice(0, 40) + "…", decoded_preview: dec.slice(0, 200) });
      cur = n; changed = true;
    }
  }
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

// ============================================================
// STEGANOGRAFIE (v10)
// ============================================================
function detectSteganography(text) {
  const findings = [];

  // 6a. whitespace-stego
  const lines = text.split(/\n/);
  const trailingBits = [];
  let bitStream = "";
  for (let i = 0; i < lines.length && trailingBits.length < 100; i++) {
    const m = /([ \t]+)$/.exec(lines[i]);
    if (m) {
      trailingBits.push({ regel: i + 1, aantal_tekens: m[1].length, is_tab_dominated: /\t/.test(m[1]) });
      for (const c of m[1]) bitStream += (c === "\t" ? "1" : "0");
    }
  }
  if (trailingBits.length >= 8) {
    let decoded = "";
    for (let i = 0; i + 7 < bitStream.length; i += 8) {
      const byte = parseInt(bitStream.substr(i, 8), 2);
      if (byte >= 0x20 && byte < 0x7F) decoded += String.fromCharCode(byte);
      else if (byte === 0x0A || byte === 0x0D || byte === 0x09) decoded += " ";
      else decoded += ".";
    }
    findings.push({ soort: "whitespace-steganografie", aantal_regels_met_trailing: trailingBits.length, voorbeelden: trailingBits.slice(0, 5), bit_decodering_poging: decoded.slice(0, 200) });
  }

  // 6b. zero-width bit-stego
  const zwSequences = [];
  let cur = ""; let curStart = -1;
  for (let i = 0; i < text.length; i++) {
    const cc = text.charCodeAt(i);
    if (zwSet.has(cc)) {
      if (curStart < 0) curStart = i;
      cur += (cc === 0x200B) ? "0" : (cc === 0x200C) ? "1" : "X";
    } else {
      if (cur.length >= 6) zwSequences.push({ offset: curStart, lengte: cur.length, bits_ZWSP_0_ZWNJ_1: cur });
      cur = ""; curStart = -1;
    }
  }
  if (cur.length >= 6) zwSequences.push({ offset: curStart, lengte: cur.length, bits_ZWSP_0_ZWNJ_1: cur });
  if (zwSequences.length) {
    let allBits = zwSequences.map(s => s.bits_ZWSP_0_ZWNJ_1).join("").replace(/X/g, "");
    let decoded = "";
    for (let i = 0; i + 7 < allBits.length && decoded.length < 100; i += 8) {
      const b = parseInt(allBits.substr(i, 8), 2);
      decoded += (b >= 0x20 && b < 0x7F) ? String.fromCharCode(b) : ".";
    }
    findings.push({ soort: "zero-width-steganografie", aantal_reeksen: zwSequences.length, totaal_bits: allBits.length, voorbeelden: zwSequences.slice(0, 3), bit_decodering_poging: decoded });
  }

  // 6c. verborgen tekst via CSS
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
  if (cssHidden.length) findings.push({ soort: "verborgen-tekst-via-CSS", aantal: cssHidden.length, voorbeelden: cssHidden.slice(0, 20) });

  // 6d. HTML/XML comments
  const comments = [];
  const commentRx = /<!--([\s\S]{5,500}?)-->/g;
  let cm;
  while ((cm = commentRx.exec(text)) !== null && comments.length < 40) {
    const t = cm[1].trim(); if (t.length > 5) comments.push(t.slice(0, 300));
  }
  if (comments.length) findings.push({ soort: "HTML/XML-comments (verborgen voor lezer, wel in bestand)", aantal: comments.length, voorbeelden: comments.slice(0, 10) });

  // 6e. onzichtbare Unicode los
  const zwBare = [];
  for (let i = 0; i < text.length && zwBare.length < 30; i++) {
    if (zwSet.has(text.charCodeAt(i))) {
      const cc = text.charCodeAt(i);
      zwBare.push({ offset: i, codepoint: "U+" + cc.toString(16).toUpperCase().padStart(4, "0"), naam: zwNames[cc] || "?", context: text.slice(Math.max(0, i - 30), i + 30).replace(/[\r\n]/g, " ") });
    }
  }
  if (zwBare.length) findings.push({ soort: "onzichtbare-Unicode-tekens (los)", aantal: zwBare.length, voorbeelden: zwBare.slice(0, 10) });

  // 6f. homoglyphs
  const hg = [];
  for (let i = 0; i < text.length && hg.length < 30; i++) {
    const cc = text.charCodeAt(i);
    if (homoglyphMap[cc]) {
      hg.push({ offset: i, gevonden: text[i], codepoint: "U+" + cc.toString(16).toUpperCase().padStart(4, "0"), lijkt_op_ASCII: homoglyphMap[cc], context: text.slice(Math.max(0, i - 20), i + 20).replace(/[\r\n]/g, " ") });
    }
  }
  if (hg.length) findings.push({ soort: "homoglyph-substitutie (Cyrillisch/Grieks in ASCII-context)", aantal: hg.length, voorbeelden: hg.slice(0, 10) });

  return findings;
}

// ============================================================
// ZICHTBAARHEID-CLASSIFICATIE (v10)
// ============================================================
function splitByVisibility(text) {
  const narratives = [];
  let m;
  const rxText = /<text[^>]*>([\s\S]*?)<\/text>/gi;
  while ((m = rxText.exec(text)) !== null) narratives.push(m[1]);
  const narrativeCombined = narratives.join("\n---sectie---\n");
  const rest = text.replace(rxText, "");
  return { narrative: narrativeCombined, buiten_narrative: rest, aantal_narratives: narratives.length };
}
function extractInvisibleValues(text) {
  const results = [];
  const rxVal = /<value[^>]*(?:code|codeSystem|displayName)="([^"]{2,200})"/g;
  const seen = new Set();
  let m;
  while ((m = rxVal.exec(text)) !== null && results.length < 40) {
    if (!seen.has(m[1])) { seen.add(m[1]); results.push({ soort: "CDA <value> attribuut", waarde: m[1] }); }
  }
  const nfMap = {};
  const rxNf = /nullFlavor="([A-Z]+)"/g;
  while ((m = rxNf.exec(text)) !== null) nfMap[m[1]] = (nfMap[m[1]] || 0) + 1;
  const nfTotal = Object.values(nfMap).reduce((s, n) => s + n, 0);
  if (nfTotal) results.push({ soort: "nullFlavor-tellingen (data die leeg naar buiten gaat)", waarde: JSON.stringify(nfMap), totaal: nfTotal });
  const rxScr = /<script[^>]*>([\s\S]{5,400}?)<\/script>/gi;
  while ((m = rxScr.exec(text)) !== null && results.length < 80) {
    results.push({ soort: "inline <script>-inhoud", waarde: m[1].trim().slice(0, 300) });
  }
  return results;
}

// ============================================================
// CDA-SPECIFIEKE FORENSISCHE HEURISTIEKEN (v9.1 rijke versie)
// ============================================================
function cdaForensicHeuristics(s) {
  const out = {};
  const selfClose = [];
  const rx = /<td[^>]+ID="([a-zA-Z]+\d*)(reaction|severity|end|dose|value)"[^>]*\/>/g;
  let m;
  while ((m = rx.exec(s)) !== null && selfClose.length < 60) {
    selfClose.push({ veld: m[1] + m[2], offset: m.index });
  }
  if (selfClose.length) out.zelfsluitende_datavelden_bij_comments = selfClose;

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

  const placeholders = [];
  const hn = s.match(/<houseNumber>(999|000|9999)<\/houseNumber>/gi);
  if (hn) placeholders.push({ soort: "placeholder-huisnummer", waarden: hn });
  const straat = s.match(/<streetName>\s*(POSTBUS|Postbus)[^<]*<\/streetName>/gi);
  if (straat) placeholders.push({ soort: "postbus-als-straat", waarden: straat });
  if (placeholders.length) out.placeholder_adressen = placeholders;

  const streetnames = [...(s.matchAll(/<streetName>\s*([^<]+?)\s*<\/streetName>/g))].map(mm => mm[1]);
  const suspTrunc = [];
  const seen = new Set();
  for (const sn of streetnames) {
    if (!sn) continue;
    if ([10, 20, 30].includes(sn.length) && !/[aeiouy]$/i.test(sn)) {
      if (!seen.has(sn)) { seen.add(sn); suspTrunc.push({ waarde: sn, lengte: sn.length, reden: "eindigt op ronde legacy VARCHAR-grens zonder klinker" }); }
    }
    if (sn === sn.toUpperCase() && sn.length > 5 && !seen.has(sn)) {
      seen.add(sn); suspTrunc.push({ waarde: sn, lengte: sn.length, reden: "all-caps in mixed-case document (legacy AS400/mainframe artefact)" });
    }
  }
  if (suspTrunc.length) out.legacy_truncatie_verdacht = suspTrunc;

  const pc = s.match(/<postalCode>\d{4}\s+[A-Z]{2}<\/postalCode>/g);
  if (pc) out.postcode_zib_schending = {
    aantal: pc.length, voorbeelden: Array.from(new Set(pc)).slice(0, 10),
    norm: "ZIB Adresgegevens v3.2 eist 4 cijfers + 2 letters ZONDER spatie"
  };

  const versies = [...(s.matchAll(/<versionNumber\s+value="(\d+)"/g))].map(mm => parseInt(mm[1], 10));
  if (versies.length) {
    const hoogste = Math.max(...versies);
    if (hoogste >= 20) out.versienummer_explosie = {
      hoogste: hoogste, alle: Array.from(new Set(versies)).sort((a,b) => a - b),
      interpretatie: "versienummer >= 20 op één ClinicalDocument = intensieve nabewerking"
    };
  }

  const times = [...(s.matchAll(/<effectiveTime\s+value="(\d{14})/g))].map(mm => mm[1]);
  if (times.length >= 3) {
    const parsed = times.map(t => {
      const dt = new Date(Date.UTC(+t.substr(0,4), +t.substr(4,2)-1, +t.substr(6,2), +t.substr(8,2), +t.substr(10,2), +t.substr(12,2)));
      return { raw: t, ms: dt.getTime() };
    }).sort((a,b) => a.ms - b.ms);
    const clusters = [];
    let cur = [parsed[0]];
    for (let i = 1; i < parsed.length; i++) {
      if (parsed[i].ms - cur[cur.length-1].ms <= 15 * 60 * 1000) cur.push(parsed[i]);
      else { if (cur.length >= 3) clusters.push(cur); cur = [parsed[i]]; }
    }
    if (cur.length >= 3) clusters.push(cur);
    if (clusters.length) out.batch_mutatie_clusters = clusters.map(c => ({
      aantal: c.length, van: c[0].raw, tot: c[c.length-1].raw,
      span_seconden: Math.round((c[c.length-1].ms - c[0].ms) / 1000),
      interpretatie: "meerdere records gemuteerd binnen 15 min door één actor"
    }));
  }

  const commentedNoReaction = [];
  const crx = /<td\s+ID="allergy(\d+)reaction"[^>]*\/>[\s\S]{0,500}<td\s+ID="allergy\1comments"[^>]*>[\s\S]{0,50}<paragraph>([^<]{3,300})/g;
  let cm;
  while ((cm = crx.exec(s)) !== null && commentedNoReaction.length < 20) {
    commentedNoReaction.push({
      allergy_id: "allergy" + cm[1], comment_bevat: cm[2].trim().slice(0, 150),
      interpretatie: "reactie-veld self-closing terwijl comment reactie beschrijft — voor triage-systemen ONZICHTBAAR"
    });
  }
  if (commentedNoReaction.length) out.reactie_leeg_maar_comment_beschrijft = commentedNoReaction;

  const custody = [];
  if (/http:\/\/localhost/i.test(s)) custody.push("localhost-URL in productie-CDA");
  if (/sodipodi|inkscape/i.test(s)) custody.push("Inkscape/Sodipodi SVG-editor metadata");
  if (/textastic/i.test(s)) custody.push("Textastic (iOS-editor) preview-URL");
  if (/claude\.ai|anthropic/i.test(s)) custody.push("Claude/Anthropic-referentie");
  if (custody.length) out.chain_of_custody_signalen = {
    signalen: custody,
    interpretatie: "dit CDA is een bewerkt derivaat, niet het bron-Epic-XML → bewijswaarde M, niet H"
  };

  const patNames = [...(s.matchAll(/<name>(GROTHE[^<]{0,40})<\/name>/g))].map(mm => mm[1]);
  const uniqPat = Array.from(new Set(patNames));
  if (uniqPat.length > 1) out.patient_naam_varianten = {
    aantal: uniqPat.length, varianten: uniqPat,
    risico: "cross-systeem identity-matching (LSP/Mitz/MedMij) kan falen bij mismatch"
  };

  return out;
}

// ============================================================
// NL ZORG IDENTIFIERS (v9.1 rijke versie)
// ============================================================
function nlZorgIds(s) {
  const out = {};
  const bsn = (s.match(/\b\d{9}\b/g) || []).filter(n => {
    if (n === "000000000") return false;
    let x = 0; for (let i=0;i<8;i++) x += parseInt(n[i],10)*(9-i); x -= parseInt(n[8],10);
    return x % 11 === 0;
  });
  if (bsn.length) out.bsn_11proef = Array.from(new Set(bsn)).slice(0,50);
  const agb = s.match(/\bAGB[- ]?\d{8}\b/gi); if (agb) out.agb = Array.from(new Set(agb));
  const big = s.match(/\b\d{11}\s*BIG\b/gi); if (big) out.big = Array.from(new Set(big));
  const uzi = s.match(/\bUZI[- ]?\d{9,}\b/gi); if (uzi) out.uzi = Array.from(new Set(uzi));
  const oids = s.match(/\b2\.16\.\d+(?:\.\d+){2,}\b/g); if (oids) out.oids = Array.from(new Set(oids)).slice(0,100);
  const urls = s.match(/https?:\/\/[^\s"'<>)]+/gi); if (urls) out.urls = Array.from(new Set(urls)).slice(0,200);
  const emails = s.match(/[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}/g); if (emails) out.emails = Array.from(new Set(emails)).slice(0,50);
  const cda = s.match(/<ClinicalDocument[^>]*/gi); if (cda) out.hl7_cda = cda.slice(0,5);
  const fhir = s.match(/"resourceType"\s*:\s*"[A-Z][A-Za-z]+"/g); if (fhir) out.fhir_resources = Array.from(new Set(fhir)).slice(0,50);
  const xdm = s.match(/METADATA\.XML|IHE_XDM|SUBSET\d+/gi); if (xdm) out.ihe_xdm = Array.from(new Set(xdm));
  const ipv4Cand = s.match(/(?<![.\d])\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?![.\d])/g) || [];
  const ipv4 = ipv4Cand.filter(ip => {
    const parts = ip.split(".").map(Number);
    if (parts.some(p => p > 255)) return false;
    if (parts[0] === 2 && parts[1] === 16 && parts[2] === 840) return false;
    return true;
  });
  if (ipv4.length) out.ipv4 = Array.from(new Set(ipv4)).slice(0,30);
  const uuids = s.match(/\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b/g); if (uuids) out.uuids = Array.from(new Set(uuids)).slice(0,50);
  return out;
}

// ============================================================
// HOOFDVERWERKING
// ============================================================
function processBytes(bytes, fileInfo) {
  fileInfo.grootte_bytes = bytes.length;
  const container = detectContainer(bytes);
  fileInfo.container = container ? container.type : "plain_text";
  const layers = [];
  if (tinyinflateStatus !== "available") {
    layers.push({ status: "ERROR", laag: "tinyinflate", reden: tinyinflateFout || "unknown; DEFLATE-afhankelijke lagen worden overgeslagen" });
  }

  if (container && container.type === "appledouble") {
    fileInfo.instructie = "AppleDouble resource fork (._-bestand). Bevat meestal alleen macOS metadata; scan gaat door op strings-basis.";
    fileInfo.hex_dump_128 = hexDump(bytes, 128);
    fileInfo.strings_uit_binary = extractStringsFromBytes(bytes, 6).slice(0, 200);
    fileInfo.layers_toegepast = layers;
    return;
  }

  let workBytes = bytes;

  if (container && container.type === "gzip") {
    try { workBytes = gunzip(bytes); layers.push("gzip → geïnflateerd (" + workBytes.length + " bytes)"); }
    catch (e) { fileInfo.decompress_fout = e.message; return finalizeBytesOnly(bytes, fileInfo, layers); }
  } else if (container && container.type === "zlib") {
    try { workBytes = zlibInflate(bytes); layers.push("zlib → geïnflateerd"); }
    catch (e) { fileInfo.decompress_fout = e.message; return finalizeBytesOnly(bytes, fileInfo, layers); }
  } else if (container && container.type === "zip") {
    let entries = [];
    try { entries = unzip(bytes); }
    catch (e) { fileInfo.zip_fout = e.message; return finalizeBytesOnly(bytes, fileInfo, layers); }
    fileInfo.zip_entries = entries.map(e => ({ naam: e.naam, methode: e.methode, lengte: e.bytes ? e.bytes.length : null, fout: e.fout }));

    const isOffice = entries.some(e => /^word\/document\.xml|^xl\/sharedStrings\.xml|^xl\/worksheets\/|^ppt\/slides\//i.test(e.naam || ""));
    if (isOffice) {
      const officeTexts = [];
      for (const entry of entries) {
        if (!entry.bytes) continue;
        if (/\.xml$/i.test(entry.naam) && /^(word|xl|ppt|docProps)\//i.test(entry.naam)) {
          const xml = bytesToUtf8(entry.bytes);
          const t = extractOfficeXmlText(xml);
          if (t.length) officeTexts.push({ deel: entry.naam, tekst: t });
        }
      }
      fileInfo.office_text = officeTexts;
      layers.push("Office (DOCX/XLSX/PPTX) tekst geëxtraheerd");
    }

    // IHE XDM manifest-detectie
    const xdmManifest = entries.find(e => /METADATA\.XML$/i.test(e.naam || ""));
    if (xdmManifest && xdmManifest.bytes) {
      fileInfo.ihe_xdm_manifest = bytesToUtf8(xdmManifest.bytes).slice(0, 8000);
      layers.push("IHE XDM METADATA.XML gevonden");
    }

    fileInfo.zip_content = [];
    for (const entry of entries.slice(0, 50)) {
      if (!entry.bytes) continue;
      const sub = { naam: entry.naam, grootte_bytes: entry.bytes.length };
      processBytes(entry.bytes, sub);
      fileInfo.zip_content.push(sub);
    }
    layers.push("ZIP → " + entries.length + " entries verwerkt");
    fileInfo.layers_toegepast = layers;
    return;
  } else if (container && container.type === "pdf") {
    fileInfo.pdf_info = extractPdfInfo(bytes);
    fileInfo.pdf_streams = extractPdfStreams(bytes);
    layers.push("PDF /Info + " + fileInfo.pdf_streams.length + " streams");
  } else if (container && container.type === "png") {
    fileInfo.png_chunks = extractPngMetadata(bytes);
    fileInfo.strings_uit_binary = extractStringsFromBytes(bytes, 6).slice(0, 200);
    fileInfo.hex_dump_128 = hexDump(bytes, 128);
    layers.push("PNG chunks gelezen"); fileInfo.layers_toegepast = layers; return;
  } else if (container && container.type === "jpeg") {
    fileInfo.jpeg_segments = extractJpegMetadata(bytes);
    fileInfo.strings_uit_binary = extractStringsFromBytes(bytes, 6).slice(0, 200);
    fileInfo.hex_dump_128 = hexDump(bytes, 128);
    layers.push("JPEG segments gelezen"); fileInfo.layers_toegepast = layers; return;
  } else if (container && (container.type === "7z" || container.type === "rar" || container.type === "zstd")) {
    fileInfo.instructie = container.type + " kan Scriptable niet native uitpakken. Op je Mac: `7z x` / `unrar x` / `zstd -d`.";
    fileInfo.hex_dump_128 = hexDump(bytes, 128);
    fileInfo.strings_uit_binary = extractStringsFromBytes(bytes, MIN_STRING_LEN).slice(0, 500);
    fileInfo.layers_toegepast = layers; return;
  } else if (container && container.type.startsWith("executable")) {
    fileInfo.instructie = "Executable (" + container.type + "). Scan beperkt tot strings.";
    fileInfo.hex_dump_128 = hexDump(bytes, 128);
    fileInfo.strings_uit_binary = extractStringsFromBytes(bytes, 6).slice(0, 300);
    fileInfo.layers_toegepast = layers; return;
  } else if (container && container.type === "bplist") {
    fileInfo.instructie = "Binary property list (bplist00). Scan beperkt tot strings.";
    fileInfo.strings_uit_binary = extractStringsFromBytes(bytes, 4).slice(0, 400);
    fileInfo.layers_toegepast = layers; return;
  } else if (container && container.type === "sqlite") {
    fileInfo.instructie = "SQLite-database. Strings-scan uitgevoerd; voor structuur `sqlite3 <bestand> .dump` op Mac.";
    fileInfo.strings_uit_binary = extractStringsFromBytes(bytes, 6).slice(0, 500);
    fileInfo.layers_toegepast = layers; return;
  } else if (container && container.type === "rtf") {
    const rawText = bytesToUtf8(bytes);
    fileInfo.rtf_stripped = rawText.replace(/\\[a-zA-Z]+\d*\s?|\{|\}|\\'[0-9a-fA-F]{2}/g, " ").replace(/\s+/g, " ").trim().slice(0, 20000);
    layers.push("RTF stripping toegepast");
  }

  // ENCODING DETECT + TEKST
  const decoded = bytesToStringAuto(workBytes);
  fileInfo.encoding = decoded.encoding;
  const text = decoded.text.slice(0, SCAN_HEAD);

  // Zero-width / homoglyph forensische lijst
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

  // Zichtbaarheids-splitsing (v10)
  const vis = splitByVisibility(text);
  const invisibleValues = extractInvisibleValues(text);
  revealed.zichtbaarheid = {
    aantal_narrative_secties: vis.aantal_narratives,
    zichtbaar_in_narrative_preview: vis.narrative.slice(0, 4000),
    alleen_in_structuur_of_binair: {
      aantal_verborgen_datapunten: invisibleValues.length,
      voorbeelden: invisibleValues.slice(0, 30)
    }
  };

  // Steganografie sweep (v10)
  const stego = detectSteganography(text);
  if (stego.length) { revealed.steganografie = stego; layers.push("steganografie-scan"); }

  // Matroesjka (v10)
  const matroesjkaLog = [];
  const fullyDecoded = matroesjkaDecode(text, 0, matroesjkaLog);
  revealed.matroesjka = {
    diepste_laag_bereikt: matroesjkaLog.length ? Math.max(...matroesjkaLog.map(l => l.diepte)) : 0,
    lagen_toegepast: matroesjkaLog,
    volledig_gedecodeerde_tekst: fullyDecoded.slice(0, 20000)
  };
  if (matroesjkaLog.length) layers.push("matroesjka (" + matroesjkaLog.length + " lagen)");

  // HAR
  if (/^\s*\{\s*"log"\s*:/.test(normalized)) {
    const har = parseHar(normalized);
    if (har) { revealed.har_entries = har.slice(0, 100); layers.push("HAR: " + har.length + " requests"); }
  }

  // JSONP unwrap
  const jsonp = unwrapJsonp(normalized);
  if (jsonp) { revealed.jsonp_callback = jsonp; layers.push("JSONP unwrapped"); }

  // HTTP splitsen
  const http = splitHttp(normalized);
  let bodyText = normalized;
  if (http) {
    revealed.http_headers = http.headers;
    revealed.http_cookies = parseCookies(http.headers);
    const H = parseHeaders(http.headers);
    bodyText = http.body;
    if (H["transfer-encoding"] && /chunked/i.test(H["transfer-encoding"])) {
      bodyText = dechunk(bodyText); layers.push("HTTP chunked gedecodeerd");
    }
    const ct = H["content-type"] || "";
    const mp = /boundary=([^;\s]+)/i.exec(ct);
    if (mp) {
      const parts = parseMultipart(bodyText, mp[1].replace(/"/g,""));
      if (parts.length) { revealed.multipart_parts = parts.slice(0, 20); layers.push("multipart/form-data gesplitst"); }
    }
    layers.push("HTTP-response gesplitst");
  }

  // Meta tags / refresh / source-maps / signed
  const meta = extractMetaTags(bodyText); if (meta.length) revealed.meta_tags = meta;
  const refresh = extractMetaRefresh(bodyText); if (refresh.length) { revealed.meta_refresh_redirects = refresh; layers.push("meta-refresh"); }
  const sm = extractSourceMaps(bodyText); if (sm.length) { revealed.source_maps = sm; layers.push("source-map URLs"); }
  const signed = extractSignedUrlParams(bodyText); if (signed.length) { revealed.signed_url_params = signed; layers.push("signed URL params"); }

  // Verborgen HTML
  const hidden = extractHiddenHtml(bodyText);
  if (hidden.length) { revealed.verborgen_html_tekst = hidden.slice(0,60); layers.push("verborgen HTML/CSS tekst"); }

  // Data URIs
  const dataUris = extractDataUris(bodyText);
  if (dataUris.length) { revealed.data_uris = dataUris; layers.push("data: URIs (" + dataUris.length + ")"); }

  // Base64 blobs
  const b64Rx = /[A-Za-z0-9+/_-]{40,}={0,2}/g;
  const b64Hits = []; let bm; let bc = 0;
  while ((bm = b64Rx.exec(bodyText)) !== null && bc < 60) {
    const dec = decodeB64Str(bm[0]);
    if (dec && /[\x20-\x7E]{6,}/.test(dec)) { b64Hits.push({ offset:bm.index, tekst:dec.slice(0,600) }); bc++; }
  }
  if (b64Hits.length) { revealed.base64_gedecodeerd = b64Hits; layers.push("base64 (" + bc + ")"); }

  // Base32
  const b32Rx = /\b[A-Z2-7]{40,}={0,6}\b/g;
  const b32Hits = []; let b32m; let b32c = 0;
  while ((b32m = b32Rx.exec(bodyText)) !== null && b32c < 20) {
    const dec = decodeBase32(b32m[0]);
    if (dec && /[\x20-\x7E]{4,}/.test(dec)) { b32Hits.push({ offset:b32m.index, tekst:dec.slice(0,300) }); b32c++; }
  }
  if (b32Hits.length) { revealed.base32_gedecodeerd = b32Hits; layers.push("base32 (" + b32c + ")"); }

  // JWT
  const jwts = [];
  { const rx2 = /\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+(?:\.[A-Za-z0-9_\-]+)?/g; let jm;
    while ((jm = rx2.exec(bodyText)) !== null && jwts.length < 20) {
      const p = jm[0].split(".");
      jwts.push({ header: decodeB64Str(p[0]), payload: decodeB64Str(p[1]) });
    }
  }
  if (jwts.length) { revealed.jwt_tokens = jwts; layers.push("JWT (" + jwts.length + ")"); }

  // Overige decoders
  if (/&(?:#\d+|#x[0-9A-Fa-f]+|[a-zA-Z]+);/.test(bodyText)) { revealed.html_entities_decoded = decodeHtmlEntities(bodyText.slice(0, 20000)); layers.push("HTML entities"); }
  if (/\\u[0-9a-fA-F]{4}|\\x[0-9a-fA-F]{2}/.test(bodyText)) { revealed.js_escapes_decoded = decodeJsEscapes(bodyText.slice(0, 20000)); layers.push("JS-escapes"); }
  if (/%[0-9A-Fa-f]{2}/.test(bodyText)) { revealed.url_encoded_decoded = decodeUrlRecursive(bodyText.slice(0, 20000)); layers.push("URL-encoding (recursief)"); }
  if (/=[0-9A-Fa-f]{2}(?:=[0-9A-Fa-f]{2}){2,}/.test(bodyText)) { revealed.quoted_printable_decoded = decodeQP(bodyText.slice(0, 20000)); layers.push("quoted-printable"); }

  // Punycode
  const punyMatches = bodyText.match(/\bxn--[a-z0-9\-]+/gi);
  if (punyMatches) {
    const puny = [];
    for (const p of new Set(punyMatches)) { const d = decodePunycode(p.toLowerCase()); if (d) puny.push({ punycode: p, unicode: d }); }
    if (puny.length) { revealed.punycode_gedecodeerd = puny; layers.push("punycode"); }
  }

  // ROT13
  const rot = rot13Auto(bodyText.slice(0, 4000));
  if (rot) { revealed.rot13_gedecodeerd = rot.slice(0, 4000); layers.push("ROT13 automatisch onthuld"); }

  // Line-endings / timestamps
  revealed.line_endings = analyzeLineEndings(bodyText);
  revealed.timestamps = extractTimestamps(bodyText);

  // NL zorg identifiers
  const nlz = nlZorgIds(bodyText);
  if (Object.keys(nlz).length) revealed.nl_zorg_identifiers = nlz;

  // CDA-heuristieken
  if (/<ClinicalDocument|urn:hl7-org:v3/i.test(bodyText)) {
    const cda = cdaForensicHeuristics(bodyText);
    if (Object.keys(cda).length) { revealed.cda_forensische_heuristieken = cda; layers.push("CDA forensische heuristieken"); }
  }

  // Strings uit binary
  revealed.strings_uit_body = extractStringsFromBytes(workBytes, MIN_STRING_LEN).slice(0, 800);

  // Consolidatie
  const parts = [];
  parts.push("=== NORMALIZED (encoding=" + fileInfo.encoding + ") ===\n" + normalized.slice(0, 80000));
  if (http) parts.push("=== HTTP HEADERS ===\n" + http.headers);
  if (revealed.har_entries) parts.push("=== HAR ENTRIES ===\n" + revealed.har_entries.map(h => h.method + " " + h.url + " → " + h.status).join("\n"));
  if (fileInfo.pdf_info) parts.push("=== PDF INFO ===\n" + JSON.stringify(fileInfo.pdf_info, null, 2));
  if (fileInfo.pdf_streams) parts.push("=== PDF STREAMS ===\n" + fileInfo.pdf_streams.map(p => "[@" + p.offset + " " + (p.type||"?") + "]\n" + (p.tekst || ("fout: " + p.fout))).join("\n---\n"));
  if (fileInfo.office_text) parts.push("=== OFFICE TEXT ===\n" + fileInfo.office_text.map(o => "--- " + o.deel + " ---\n" + o.tekst.join(" ")).join("\n"));
  if (fileInfo.rtf_stripped) parts.push("=== RTF STRIPPED ===\n" + fileInfo.rtf_stripped);
  if (hidden.length) parts.push("=== VERBORGEN HTML/CSS TEKST ===\n" + hidden.join("\n---\n"));
  if (dataUris.length) parts.push("=== DATA URIs GEDECODEERD ===\n" + dataUris.map(d => "[" + d.mime + "]\n" + (d.decoded_preview || "")).join("\n---\n"));
  if (b64Hits.length) parts.push("=== BASE64 ===\n" + b64Hits.map(h=>"[@"+h.offset+"]\n"+h.tekst).join("\n---\n"));
  if (jwts.length) parts.push("=== JWT ===\n" + jwts.map(j=>"header="+j.header+"\npayload="+j.payload).join("\n---\n"));

  fileInfo.deobfuscated_text = parts.join("\n\n");
  fileInfo.layers_toegepast = layers;
  fileInfo.revealed = revealed;
}

function finalizeBytesOnly(bytes, fileInfo, layers) {
  fileInfo.hex_dump_128 = hexDump(bytes, 128);
  fileInfo.strings_uit_binary = extractStringsFromBytes(bytes, MIN_STRING_LEN).slice(0, 500);
  fileInfo.layers_toegepast = layers;
}

// ============================================================
// HOOFDLOOP
// ============================================================
const rapport = [];
for (let i = 0; i < inputs.length; i++) {
  const item = inputs[i];
  const path = resolvePath(item);
  const name = fileNameOf(item, path);
  const fileInfo = { bestandsnaam: name, pad: path || "-", status: "OK" };

  try {
    let bytes = null;
    if (item && item.__inlineText) {
      const arr = new Uint8Array(item.__inlineText.length);
      for (let j = 0; j < item.__inlineText.length; j++) arr[j] = item.__inlineText.charCodeAt(j) & 0xFF;
      bytes = arr;
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
  script_versie: "v11-consolidated",
  tinyinflate: { status: tinyinflateStatus, fout: tinyinflateFout },
  omgeving: inApp ? "app" : inShareSheet ? "share_sheet" : inSiri ? "siri" : "shortcut",
  aantal_bestanden: rapport.length,
  rapport: rapport
};
const json = JSON.stringify(output, null, 2);
Script.setShortcutOutput(json);
if (inApp) {
  console.log(json.slice(0, 5000));
  try { QuickLook.present(json).catch(() => {}); } catch (e) {}
}
}
Script.complete();
