// Mutation test: deliberately break the tool's code in specific ways and require that
// SOMETHING catches each break, either the in-page self-test (which disables the tool)
// or an end-to-end probe whose expected values come from @scure (independent code).
// A mutation that survives both means the safety net has a hole.
// Run: npm ci && node tests/mutation.test.mjs
import nc from 'node:crypto';
import fs from 'node:fs';
import { entropyToMnemonic, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { mnemonicToSeedSync } from '@scure/bip39';
import { HDKey } from '@scure/bip32';
import { bech32 } from '@scure/base';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 as nsha } from '@noble/hashes/sha256';
import { LifeHash } from 'lifehash';
import { loadPage, ready, readHtml, makeReporter } from './harness.mjs';

const R = makeReporter();
const html = readHtml();
const sha = (s) => new Uint8Array(nc.createHash('sha256').update(s).digest());
const fp = (mn, pw) => HDKey.fromMasterSeed(mnemonicToSeedSync(mn, pw)).fingerprint.toString(16).padStart(8, '0');

const addr = (mn, pw) => {
  const k = HDKey.fromMasterSeed(mnemonicToSeedSync(mn, pw)).derive("m/84'/0'/0'/0/0");
  return bech32.encode('bc', [0, ...bech32.toWords(ripemd160(nsha(k.publicKey)))]);
};

const ZV = { private: 0x04b2430c, public: 0x04b24746 };
const watch = (mn, pw) => { const seed = mnemonicToSeedSync(mn, pw);
  return { zpub: HDKey.fromMasterSeed(seed, ZV).derive("m/84'/0'/0'").publicExtendedKey, xpub: HDKey.fromMasterSeed(seed).derive("m/84'/0'/0'").publicExtendedKey, fp: fp(mn, pw) }; };

const hexb4 = (h) => Uint8Array.from(h.match(/../g).map((x) => parseInt(x, 16)));
const svgPixels = (svg) => { const px = new Array(32 * 32 * 3).fill(-1);
  for (const m of svg.matchAll(/<rect x="(\d+)" y="(\d+)" width="(\d+)" height="1" fill="rgb\((\d+),(\d+),(\d+)\)"/g)) { const [x, y, wd, r, g, b] = m.slice(1).map(Number);
    for (let i = 0; i < wd; i++) { const o = (y * 32 + x + i) * 3; px[o] = r; px[o + 1] = g; px[o + 2] = b; } } return px; };
// fingerprints chosen to hit all four gradient families (and both patterns); expected pixels come from the independent `lifehash` package
const LH_FPS = ['4fbf7566', '289e08eb', '0b369d3f', '8875c736', '2768c0b1', '8d9cced8', '73c5da0a', 'b4e3f5ed', 'f00e80ca', '00000000', 'ffffffff', '12345678', 'deadbeef', 'cafebabe', '0badf00d', '5eed5eed', 'a1b2c3d4', '13371337', 'c0ffee00', '7f7f7f7f', '1bae9145', '8530a8f6', '09221a00', 'fad09a48'];
const LH_EXPECT = Object.fromEntries(LH_FPS.map((f) => [f, Array.from(LifeHash.makeFrom(hexb4(f), 2, 1, false).colors)]));
// Fixed probe inputs (not SeedSigner's, so this is independent of the in-page vectors).
const D50 = '31415926535897932384626433832795028841971693993751'.replace(/[0789]/g, c => ({ 0: '6', 7: '2', 8: '4', 9: '5' }[c]));
const D99 = (D50 + D50).slice(0, 99);
const C128 = '10110011100011110000111110000011111100000011111110000000111111110101010011001100111000111100001111000001111100000011111100000010'.slice(0, 128);
const UNI = 'éﬁ pässwörd ｆｕｌｌ';
const expect = {
  d50: entropyToMnemonic(sha(D50).slice(0, 16), wordlist),
  d99: entropyToMnemonic(sha(D99).slice(0, 32), wordlist),
  c128: entropyToMnemonic(sha(C128).slice(0, 16), wordlist),
};

async function probe(w) {
  const fails = [], $ = (id) => w.document.getElementById(id);
  const mode = (m) => { const e = w.document.querySelector(`input[name=mode][value=${m}]`); e.checked = true; e.onchange(); };
  const words = (n) => { const e = w.document.querySelector(`input[name=words][value="${n}"]`); e.checked = true; e.onchange(); };
  const run = async (m, n, input, pw = '') => { mode(m); words(n); $('rolls').value = input; $('rolls').oninput(); $('passphrase').value = pw; $('passphrase2').value = pw; await w.generate(); return $('genResult').textContent.split('\n')[0]; };
  const adOf = () => (($('address').textContent.match(/: (bc1[0-9a-z]+)/) || [])[1]);
  const fpOf = () => (($('fingerprint').textContent.match(/: ([0-9a-f]{8})/) || [])[1]);

  let r = await run('dice', 12, D50); if (r !== expect.d50 || fpOf() !== fp(expect.d50, '')) fails.push('dice 12 words / fingerprint');
  if (adOf() !== addr(expect.d50, '')) fails.push('first receive address');
  { const wo = watch(expect.d50, ''), z = $('wZpub').textContent, dr = $('wDescR').textContent, dc = $('wDescC').textContent;
    if (z !== wo.zpub) fails.push('watch-only zpub');
    if (!dr.startsWith(`wpkh([${wo.fp}/84h/0h/0h]${wo.xpub}/0/*)#`) || !/#[02-9ac-hj-np-z]{8}$/.test(dr)) fails.push('watch-only receive descriptor');
    if (!dc.startsWith(`wpkh([${wo.fp}/84h/0h/0h]${wo.xpub}/1/*)#`)) fails.push('watch-only change descriptor');
    if (dr.split('#')[1] === dc.split('#')[1]) fails.push('descriptor checksums differ per branch');
    if ($('watchBox').style.display !== '') fails.push('watch-only box shown after FORGE'); }
  { const cells = [...w.document.querySelectorAll('#wordGrid .wcell')]; await run('dice', 12, D50);
    const cs = [...w.document.querySelectorAll('#wordGrid .wcell')];
    if (cs.length !== 12 || cs[0].textContent !== '1.' + expect.d50.split(' ')[0] || cs[11].textContent !== '12.' + expect.d50.split(' ')[11]) fails.push('numbered word grid');
    $('phrase').value = ''; await w.sendToVerify(); if ($('phrase').value !== expect.d50) fails.push('SEND TO VERIFY moves the words');
    $('rolls').value = D50; $('passphrase').value = 'a'; $('passphrase2').value = 'b'; await w.generate(); $('phrase').value = ''; await w.sendToVerify();
    if ($('phrase').value !== '') fails.push('an error message is never used as a seed');
    $('passphrase').value = ''; $('passphrase2').value = ''; }
  r = await run('dice', 12, D50 + '1', ''); if (r !== 'Remove 1 roll (51 of 50).') fails.push('too many rolls message');
  r = await run('dice', 12, D50.slice(0, 40), ''); if (r !== 'Enter 10 more rolls (40 of 50).') fails.push('too few rolls message');
  { const bs = [...w.document.querySelectorAll('#tapRow button')];
    if (bs.length !== 6 || !bs.every((b, i) => b.querySelectorAll('svg circle').length === i + 1)) fails.push('dice faces have the right pips'); }
  r = await run('dice', 24, D99);     if (r !== expect.d99) fails.push('dice 24 words');
  r = await run('coin', 12, C128);    if (r !== expect.c128) fails.push('coin 12 words');
  r = await run('dice', 12, D50.replace(/(.{5})/g, '$1 ') + ' x,y;z'); if (r !== expect.d50) fails.push('input cleaning (spaces/junk)');
  r = await run('dice', 12, D50 + '1');   if (!/^Remove 1 roll \(51 of 50\)\./.test(r)) fails.push('rejects wrong length');
  r = await run('dice', 12, D50, UNI);    if (fpOf() !== fp(expect.d50, UNI)) fails.push('unicode passphrase fingerprint');
  if (adOf() !== addr(expect.d50, UNI)) fails.push('first receive address with unicode passphrase');
  if ($('wZpub').textContent !== watch(expect.d50, UNI).zpub) fails.push('watch-only zpub with unicode passphrase');
  { let bl = 0;
    for (const f of LH_FPS) { const rows = await w.lifeHash(f), mine = rows.flat(2), ref = LH_EXPECT[f]; if (mine.length !== ref.length || mine.some((v, i) => v !== ref[i])) bl++; }
    if (bl) fails.push('fingerprint pictures match the independent lifehash package');
    await run('dice', 12, D50); await new Promise((r) => setTimeout(r, 40)); const px = svgPixels($('fpIcon').innerHTML), fpNow = fpOf(), refPx = fpNow ? Array.from(LifeHash.makeFrom(hexb4(fpNow), 2, 1, false).colors) : null;
    if (!refPx || px.some((v, i) => v !== refPx[i])) fails.push('fingerprint picture shown next to the fingerprint'); }
  { const li = [...w.document.querySelectorAll('#addrList li')].map(x => x.textContent);
    if (li.length !== 5 || (adOf() && li[0] !== adOf()) || new Set(li).size !== 5) fails.push('five receive addresses are listed');
    if ($('addrBox').style.display !== '' || $('checkGuide').style.display !== '') fails.push('address list and guide are shown after FORGE');
    const full = [...w.document.querySelectorAll('#wordGrid .wtxt')].map(x => x.textContent); w.toggleAbbr();
    const ab = [...w.document.querySelectorAll('#wordGrid .wtxt')].map(x => x.textContent);
    if (!full.length || ab.some((a, i) => a !== full[i].slice(0, 4))) fails.push('4-letter view shows the first four letters');
    w.toggleAbbr(); if ([...w.document.querySelectorAll('#wordGrid .wtxt')].map(x => x.textContent).join(' ') !== full.join(' ')) fails.push('4-letter view toggles back'); }
  { const fx = JSON.parse(fs.readFileSync(new URL('./fixtures/qr.json', import.meta.url), 'utf8')); let bq = 0;
    const hh = (rows) => nc.createHash('sha256').update(rows.map(r => r.map(x => x ? '1' : '0').join('')).join('')).digest('hex');
    fx.forEach((c, i) => { const m = i % 8, q = w.qrMatrix(c.text, m); if (q.version !== c.version || hh(q.rows) !== c.hashes[m]) bq++;
      const a = w.qrMatrix(c.text); if (hh(a.rows) !== c.hashes[a.mask]) bq++; });
    if (bq) fails.push('QR codes match the independent library');
    w.showQr('wZpub', 'zpub'); if (!$('qrImg').querySelector('svg path')) fails.push('SHOW QR draws a code'); }
  if ($('fpIcon').querySelector('svg')) { /* keep icon until an error */ }
  // passphrase confirmation must block a mismatch
  mode('dice'); words(12); $('rolls').value = D50; $('rolls').oninput(); $('passphrase').value = 'abc'; $('passphrase2').value = 'abd'; await w.generate();
  if (!/do not match/.test($('genResult').textContent) || adOf()) fails.push('passphrase confirmation blocks a mismatch');
  if ($('wZpub').textContent !== '' || $('watchBox').style.display !== 'none') fails.push('watch-only export hidden after an error');
  if ($('qrImg').innerHTML !== '' || $('qrBox').style.display !== 'none') fails.push('QR code hidden after an error');
  if ($('fpIcon').innerHTML !== '') fails.push('fingerprint picture hidden after an error');
  if ($('addrList').textContent !== '' || $('addrBox').style.display !== 'none' || $('checkGuide').style.display !== 'none') fails.push('address list and guide hidden after an error');
  $('passphrase').value = ''; $('passphrase2').value = '';
  // tap buttons append the right values
  $('rolls').value = ''; w.updateCount(); const taps = [...w.document.querySelectorAll('#tapRow button')];
  if (taps.length !== 6) fails.push('six dice tap buttons'); else { taps[3].onclick(); taps[0].onclick(); if ($('rolls').value !== '41') fails.push('tap buttons append the right roll'); }
  $('rolls').value = '';
  // VERIFY must show the published BIP84 vector address
  $('phrase').value = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'; await w.verify();
  if (!/bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu/.test($('verifyStatus').textContent)) fails.push('VERIFY shows first address');
  $('verifyPass').value = 'TREZOR'; await w.verify(); { const vs = $('verifyStatus').textContent;
    if (!/Without passphrase: fingerprint 73c5da0a \| first address bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu/.test(vs)) fails.push('VERIFY without-passphrase line');
    if (!/With passphrase \(6 characters, not shown\): fingerprint b4e3f5ed \| first address bc1qv5rmq0kt9yz3pm36wvzct7p3x6mtgehjul0feu/.test(vs)) fails.push('VERIFY with-passphrase line'); }
  { await new Promise((r) => setTimeout(r, 30)); const i0 = svgPixels($('vIcon0').innerHTML), i1 = svgPixels($('vIcon1').innerHTML);
    if (!LH_EXPECT['73c5da0a'] || i0.some((v, i) => v !== LH_EXPECT['73c5da0a'][i]) || $('vFig0').style.display === 'none') fails.push('VERIFY shows the picture without passphrase');
    if (i1.some((v, i) => v !== LH_EXPECT['b4e3f5ed'][i]) || $('vFig1').style.display === 'none') fails.push('VERIFY shows the picture with passphrase'); }
  { const ABOUT = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';
    const M = async (rec, pw) => { $('phrase').value = ABOUT; $('verifyPass').value = pw; $('verifyRecorded').value = rec; await w.verify(); return [$('verifyMatch').textContent, $('verifyMatch').className]; };
    let [tx, cl] = await M('b4e3f5ed', 'TREZOR'); if (!/^MATCH \(with passphrase\)/.test(tx) || !/ok/.test(cl)) fails.push('match: fingerprint with passphrase');
    [tx, cl] = await M('73c5da0a', 'TREZOR'); if (!/^MATCH \(without passphrase\)/.test(tx) || !/ok/.test(cl)) fails.push('match: fingerprint without passphrase');
    [tx, cl] = await M('bc1qv5rmq0kt9yz3pm36wvzct7p3x6mtgehjul0feu', 'TREZOR'); if (!/^MATCH \(with passphrase\)/.test(tx)) fails.push('match: address with passphrase');
    [tx, cl] = await M('bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu', 'TREZOR'); if (!/^MATCH \(without passphrase\)/.test(tx)) fails.push('match: address without passphrase');
    [tx, cl] = await M('deadbeef', 'TREZOR'); if (!/^NO MATCH:/.test(tx) || !/bad/.test(cl)) fails.push('match: neither');
    [tx, cl] = await M('b4e3f5ed', ''); if (!/^NO MATCH without a passphrase/.test(tx)) fails.push('match: needs passphrase');
    $('verifyRecorded').value = ''; $('verifyPass').value = ''; }
  r = await run('dice', 12, D50, ''); if (!/Passphrase: none/.test($('genResult').textContent) || !/Passphrase used: NO/.test(w.passLine('printed'))) fails.push('passphrase none line');
  r = await run('dice', 12, D50, 'abc'); if (!/Passphrase: used \(3 characters/.test($('genResult').textContent) || !/Passphrase used: YES/.test(w.passLine('saved'))) fails.push('passphrase used line');
  $('passphrase').value = ''; $('passphrase2').value = '';
  $('verifyPass').value = '';
  if ((await w.checkPhrase(expect.d50)).ok !== true) fails.push('checker accepts valid');
  // Corrupt one word; the checker must agree with @scure about whether the result is valid.
  const parts = expect.d50.split(' '); parts[11] = parts[11] === 'zoo' ? 'abandon' : 'zoo';
  const corrupted = parts.join(' ');
  if ((await w.checkPhrase(corrupted)).ok !== validateMnemonic(corrupted, wordlist)) fails.push('checker rejects bad checksum');
  const meta = w.document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  if (!meta || !/default-src 'none'/.test(meta.content)) fails.push('CSP present');
  return fails;
}

async function detect(mutated) {
  const w = loadPage(mutated);
  if (!w.selfTestDone) return { by: 'page failed to run' };
  await ready(w);
  const badge = w.document.getElementById('selfTestBadge').textContent;
  if (!/PASSED/.test(badge)) return { by: 'self-test gate' };
  const f = await probe(w);
  return f.length ? { by: 'end-to-end probe (' + f[0] + ')' } : { by: null };
}

// [name, find (must occur exactly once), replace, equivalent?]
const M = [
  ['wordlist: one word altered',            '"abandon","ability"', '"abandon","abilitx"'],
  ['entropy truncation 16 -> 15 bytes',     'const entLen = {12:16,24:32}[wc];', 'const entLen = {12:15,24:32}[wc];'],
  ['entropy truncation 32 -> 31 bytes',     'const entLen = {12:16,24:32}[wc];', 'const entLen = {12:16,24:31}[wc];'],
  ['checksum length wrong',                 'const cbits = bits/32;', 'const cbits = bits/16;'],
  ['rolls hashed with extra byte',          'const digest = await sha256(rolls);', 'const digest = await sha256(rolls+"0");'],
  ['PBKDF2 iterations 2048 -> 2047',        'iterations:2048', 'iterations:2047'],
  ['PBKDF2 salt prefix case',               '"mnemonic"+(passphrase||"")', '"Mnemonic"+(passphrase||"")'],
  ['passphrase NFKD normalisation removed', '(passphrase||"").normalize("NFKD")', '(passphrase||"")'],
  ['HMAC key altered',                      'encode("Bitcoin seed")', 'encode("Bitcoin seeD")'],
  ['fingerprint takes wrong 4 bytes',       'ripemd160(await sha256bytes(pubkeyBytes(k))).slice(0,4)', 'ripemd160(await sha256bytes(pubkeyBytes(k))).slice(1,5)'],
  ['pubkey parity prefix flipped',          'pub[0]=(P[1]&1n)?3:2;', 'pub[0]=(P[1]&1n)?2:3;'],
  ['secp256k1 generator y altered',         '0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8n', '0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B9n'],
  ['RIPEMD-160 round constant altered',     '0xA953FD4E', '0xA953FD4F'],
  ['dice cleaning drops sixes',             's.replace(/[^1-6]/g,"")', 's.replace(/[^1-5]/g,"")'],
  ['coin cleaning drops ones',              's.replace(/[^01]/g,"")', 's.replace(/[^0]/g,"")'],
  ['phrase checksum check disabled',        'if(bits.slice(eBits)!==bytesToBits(h).slice(0,cLen)) return', 'if(false) return'],
  ['exact-length check loosened',           'if(rolls.length!==need){', 'if(rolls.length<need){'],
  ['CSP weakened',                          "default-src 'none'", "default-src *"],
  ['address: a hardened level made non-hardened', '[[84,true],[0,true],[0,true],[0,false],[0,false]]', '[[84,true],[0,true],[0,false],[0,false],[0,false]]'],
  ['address: purpose 84 -> 44',             'of [[84,true],[0,true],[0,true],[0,false],[0,false]]', 'of [[44,true],[0,true],[0,true],[0,false],[0,false]]'],
  ['five addresses: purpose 84 -> 44',       'of [[84,true],[0,true],[0,true],[0,false]])', 'of [[44,true],[0,true],[0,true],[0,false]])'],
  ['address: hardened offset off by one',   '(index+0x80000000)>>>0', '(index+0x80000001)>>>0'],
  ['address: non-hardened parent pubkey misplaced', 'data.set(pubkeyBytes(k),0);', 'data.set(pubkeyBytes(k),1);'],
  ['address: bech32 checksum constant',     'const mod=poly(values)^1;', 'const mod=poly(values)^0;'],
  ['address: bech32 charset swapped',       '"qpzry9x8gf2tvdw0s3jn54khce6mua7l"', '"qpzry9x8gf2tvdw0s3jn54khce6mua7k"'],
  ['address: witness version 0 -> 1',       'bech32Encode("bc",0,h160)', 'bech32Encode("bc",1,h160)'],
  ['address: hash160 skips RIPEMD-160',     'const h160=ripemd160(await sha256bytes(pubkeyBytes(k)));', 'const h160=(await sha256bytes(pubkeyBytes(k))).slice(0,20);'],
  ['address: mainnet prefix -> testnet',    'bech32Encode("bc",0,h160)', 'bech32Encode("tb",0,h160)'],
  ['passphrase confirmation bypassed',      'if(document.getElementById("passphrase").value !== document.getElementById("passphrase2").value){', 'if(false){'],
  ['tap button appends wrong value',        'el.value += v; updateCount();', 'el.value += "1"; updateCount();'],
  ['address: child key not reduced mod n (needed about half the time)', 'child=(il+k)%SN;', 'child=(il+k);'],
  ['VERIFY ignores the typed passphrase (fingerprint)', 'fp1 = await mnemonicFingerprint(r.mnemonic, vp)', 'fp1 = await mnemonicFingerprint(r.mnemonic, "")'],
  ['watch: depth byte wrong', 'b[4]=3;', 'b[4]=4;'],
  ['watch: parent fingerprint dropped', 'b.set(parentFp,5);', 'b.set([0,0,0,0],5);'],
  ['watch: child index not hardened', 'b.set([0x80,0,0,0],9);', 'b.set([0,0,0,0],9);'],
  ['watch: zpub version bytes -> xpub', 'ser([0x04,0xb2,0x47,0x46])', 'ser([0x04,0x88,0xb2,0x1e])'],
  ['watch: base58 alphabet swapped', 'B58="123456789ABCDEFGHJKLMNPQRSTUVWXYZ', 'B58="123456789ABCDEFGHJKLMNPQRSTUVWXZY'],
  ['watch: base58 checksum skips second SHA-256', 'await sha256bytes(await sha256bytes(payload))', 'await sha256bytes(payload)'],
  ['watch: leading-zero bytes not encoded (payload always starts with a non-zero version byte)', 'if(b===0) out="1"+out;', 'if(b===0) out=out;', true],
  ['watch: account path wrong (m/84h/0h/1h)', 'for(const i of [84,0,0]){', 'for(const i of [84,0,1]){'],
  ['watch: descriptor checksum final xor removed', 'chk^=1n; let out="";', 'let out="";'],
  ['watch: descriptor origin path wrong', '"/84h/0h/0h]"', '"/84h/0h/1h]"'],
  ['watch: change descriptor uses branch 0', 'd(1)', 'd(0)'],
  ['watch: export not hidden on errors', '    clearWatch();\n    clearFpIcons();', '    clearFpIcons();'],
  ['qr: format info XOR mask wrong', '^0x5412', '^0x5413'],
  ['qr: format BCH polynomial wrong', '*0x537', '*0x536'],
  ['qr: dark module missing', 'set(8,size-8,true);', 'set(8,size-8,false);'],
  ['qr: version info polynomial wrong', '*0x1f25', '*0x1f24'],
  ['qr: Galois field polynomial wrong', '*0x11d', '*0x11c'],
  ['qr: Reed-Solomon root step wrong', 'root=qrGfMul(root,2)', 'root=qrGfMul(root,3)'],
  ['qr: pad bytes wrong', 'pad^=0xec^0x11', 'pad^=0xec^0x12'],
  ['qr: zigzag direction wrong', 'up=((right+1)&2)===0', 'up=((right+1)&2)!==0'],
  ['qr: column 6 not skipped', 'if(right===6) right=5;', ''],
  ['qr: error codewords not interleaved', 'for(let i=0;i<ecLen;i++) for(const b of blocks) words.push(b[1][i]);', 'for(const b of blocks) for(let i=0;i<ecLen;i++) words.push(b[1][i]);'],
  ['qr: data codewords not interleaved', 'for(let i=0;i<maxLen;i++) for(const b of blocks) if(i<b[0].length) words.push(b[0][i]);', 'for(const b of blocks) for(let i=0;i<b[0].length;i++) words.push(b[0][i]);'],
  ['qr: character count width for versions 10+', 'put(bytes.length,ver<10?8:16)', 'put(bytes.length,ver<10?8:8)'],
  ['qr: alignment pattern ring wrong', 'Math.max(Math.abs(dx),Math.abs(dy))!==1)', 'Math.max(Math.abs(dx),Math.abs(dy))!==2)'],
  ['qr: timing pattern phase wrong', 'set(6,i,i%2===0); set(i,6,i%2===0);', 'set(6,i,i%2===1); set(i,6,i%2===0);'],
  ['qr: finder pattern ring wrong', 'dist!==2&&dist!==4', 'dist!==2&&dist!==3'],
  ['qr: mask 5 wrong', '(x,y)=>x*y%2+x*y%3===0', '(x,y)=>x*y%2+x*y%3!==0'],
  ['qr: mask 3 wrong', '(x,y)=>(x+y)%3===0', '(x,y)=>(x+y)%3===1'],
  ['qr: version 7 table entry wrong', '7:[18,[[4,31]]]', '7:[18,[[4,30]]]'],
  ['qr: version 9 table entry wrong', '9:[22,[[3,36],[2,37]]]', '9:[22,[[3,36],[2,36]]]'],
  ['qr: alignment positions wrong (v8)', '8:[6,24,42]', '8:[6,24,40]'],
  ['qr: penalty rule weight changed (picks another valid mask)', 'if(!col) r+=pat(h)*40;', 'if(!col) r+=pat(h)*0;', true],
  ['qr: balance penalty removed (picks another valid mask)', 'r+=(Math.ceil(Math.abs(dark*20-tot*10)/tot)-1)*10;', '', true],
  ['qr: QR box not hidden when export cleared', 'function clearWatch(){\n  clearAddrs();\n  hideQr();', 'function clearWatch(){\n  clearAddrs();'],
  ['lifehash: grid size wrong', 'const N=16, digest', 'const N=15, digest'],
  ['lifehash: generation limit wrong', 'while(history.length<150){', 'while(history.length<149){'],
  ['lifehash: version 1 start (no second hash)', 'start=await sha256bytes(digest)', 'start=digest'],
  ['lifehash: version 2 bit skip wrong', 'const e=new LhBits(digest); e.next(); e.next();', 'const e=new LhBits(digest); e.next();'],
  ['lifehash: Life rule survive wrong', 'alive?(n===2||n===3):(n===3)', 'alive?(n===2):(n===3)'],
  ['lifehash: Life rule birth wrong', 'alive?(n===2||n===3):(n===3)', 'alive?(n===2||n===3):(n===2)'],
  ['lifehash: loop detection removed', 'if(seen.has(key)) break;', ''],
  ['lifehash: change tracking wrong', 'if(alive!==na){', 'if(false){'],
  ['lifehash: overlay fraction wrong', 'lhClamp((0-(i+1))/(0-history.length))', 'lhClamp((0-i)/(0-history.length))'],
  ['lifehash: normalization wrong', 'frac[p]=(mn-frac[p])/(mn-mx)', 'frac[p]=(frac[p]-mn)/(mn-mx)'],
  ['lifehash: snowflake mirror wrong', '[[0,0,0],[0,1,0],[0,0,1],[0,1,1]]', '[[0,0,0],[0,1,0],[0,0,1],[0,0,1]]'],
  ['lifehash: pinwheel transform order swapped (same four cells, written in another order)', '[[0,0,0],[1,1,0],[1,0,1],[0,1,1]]', '[[0,0,0],[1,0,1],[1,1,0],[0,1,1]]', true],
  ['lifehash: pattern bit inverted', 'snowflake=e.next();', 'snowflake=!e.next();'],
  ['lifehash: monochrome tint darkening wrong', 'lhLerp(key,LH_BLACK,0.5)', 'lhLerp(key,LH_BLACK,0.4)'],
  ['lifehash: monochrome key advance wrong', 'ka=e.frac()*0.3+0.05', 'ka=e.frac()*0.3+0.04'],
  ['lifehash: monochrome neutral advance wrong', 'na=e.frac()*0.3+0.05', 'na=e.frac()*0.3+0.06'],
  ['lifehash: complementary hue offset wrong', 'lhMod(s1+0.5,1)', 'lhMod(s1+0.4,1)'],
  ['lifehash: complementary lighten wrong', 'lhLerp(lt,LH_WHITE,la)', 'lhLerp(lt,LH_WHITE,la*0.9)'],
  ['lifehash: triadic hue offset wrong', 's2=lhMod(s1+1.0/3,1)', 's2=lhMod(s1+1.0/4,1)'],
  ['lifehash: triadic order wrong', 'lhBlendMany([lhLerp(cs[2],LH_WHITE,la),cs[1],lhLerp(cs[0],LH_BLACK,da)])', 'lhBlendMany([lhLerp(cs[0],LH_BLACK,da),cs[1],lhLerp(cs[2],LH_WHITE,la)])'],
  ['lifehash: analogous advance wrong', 'adv=e.frac()*0.5+0.2', 'adv=e.frac()*0.5+0.1'],
  ['lifehash: analogous middle tone wrong', 'lhLerp(d1,LH_BLACK,adv/2)', 'lhLerp(d1,LH_BLACK,adv/3)'],
  ['lifehash: analogous ordering wrong', 'if(lhLum(c1)<lhLum(c4))', 'if(lhLum(c1)>lhLum(c4))'],
  ['lifehash: reverse flag ignored (monochrome)', 'return rev?lhRev(g):g; }\n  if(val===1)', 'return g; }\n  if(val===1)'],
  ['lifehash: luminance weight wrong', 'Math.pow(0.299*c[0],2)', 'Math.pow(0.3*c[0],2)'],
  ['lifehash: spectrum colour wrong', '[217,63,53]', '[217,63,54]'],
  ['lifehash: byte rounding wrong', 'Math.floor(lhClamp(c[1])*255)', 'Math.round(lhClamp(c[1])*255)'],
  ['lifehash: icon not cleared on errors', '    clearWatch();\n    clearFpIcons();\n  }\n}', '    clearWatch();\n  }\n}'],
  ['VERIFY ignores the typed passphrase (address)', 'a1 = await mnemonicFirstAddress(r.mnemonic, vp)', 'a1 = await mnemonicFirstAddress(r.mnemonic, "")'],
  ['VERIFY without-passphrase line uses the typed passphrase', 'fp0 = await mnemonicFingerprint(r.mnemonic, "");', 'fp0 = await mnemonicFingerprint(r.mnemonic, vp);'],
  ['match: with-passphrase check compares the wrong values', '(kind === "fp" ? fp1 : a1)', '(kind === "fp" ? fp0 : a0)'],
  ['match: address backups compared against the fingerprint', 'q === (kind === "fp" ? fp0 : a0)', 'q === fp0'],
  ['match: NO MATCH shown as success', 'return {ok:false, text:"NO MATCH:', 'return {ok:true, text:"NO MATCH:'],
  ['match: hasPass guard dropped (a1/fp1 are undefined without a passphrase)', 'if(hasPass && q ===', 'if(q ===', true],
  ['passphrase line: YES/NO swapped (print and download)', '(used ? "YES (keep it separate; it is not " + kind + " here)" : "NO")', '(used ? "NO" : "YES (keep it separate; it is not " + kind + " here)")'],
  ['result line: no-passphrase wording wrong', ': "none"), mnemonic.split(" "));', ': "used"), mnemonic.split(" "));'],
  ['grid: word numbers off by one',           '(i + 1) + "."', 'i + "."'],
  ['seed flag never set (SEND TO VERIFY would refuse)', 'g.dataset.seed = "1";', 'g.dataset.seed = "";'],
  ['seed flag not cleared after an error (error text treated as a seed)', 'delete g.dataset.seed;', ''],
  ['plain message: too few rolls wording', '"Enter " + diff + " more "', '"Enter " + rolls.length + " more "'],
  ['dice face drawn with a missing pip (5)', '5:[[28,28],[72,28],[50,50],[28,72],[72,72]]', '5:[[28,28],[72,28],[28,72],[72,72]]'],
  ['five addresses: child index off by one', 'const [ck]=await ckdPriv(k,c,i,false);', 'const [ck]=await ckdPriv(k,c,i+1,false);'],
  ['five addresses: hardened child', 'const [ck]=await ckdPriv(k,c,i,false);', 'const [ck]=await ckdPriv(k,c,i,true);'],
  ['five addresses: one too few', 'for(let i=0;i<n;i++){\n    const [ck]', 'for(let i=0;i<n-1;i++){\n    const [ck]'],
  ['five addresses: receive chain replaced by change chain', 'for(const [i,h] of [[84,true],[0,true],[0,true],[0,false]]) [k,c]=await ckdPriv(k,c,i,h);\n  const out=[];', 'for(const [i,h] of [[84,true],[0,true],[0,true],[1,false]]) [k,c]=await ckdPriv(k,c,i,h);\n  const out=[];'],
  ['address list not cleared after an error', 'function clearAddrs(){\n  document.getElementById("addrList").textContent = "";', 'function clearAddrs(){\n  '],
  ['address guide hidden after FORGE', 'document.getElementById("checkGuide").style.display = "";\n}', 'document.getElementById("checkGuide").style.display = "none";\n}'],
  ['4-letter view: three letters', 'e.textContent = abbrOn ? e.dataset.w.slice(0, 4) : e.dataset.w;', 'e.textContent = abbrOn ? e.dataset.w.slice(0, 3) : e.dataset.w;'],
  ['mnemonic NFKD removed (English ASCII words)', 'enc.encode(mnemonic.normalize("NFKD"))', 'enc.encode(mnemonic)', true],
  ['master key range check removed (unreachable in practice)', 'if(k===0n || k>=SN) throw new Error("Invalid master key");', '', true],
];

const base = await detect(html);
R.ok(base.by === null, "control: the unmodified file passes the self-test and every probe" + (base.by ? " [" + base.by + "]" : ""));

const survivors = [];
for (const [name, find, rep, equivalent] of M) {
  const count = html.split(find).length - 1;
  if (count !== 1) { R.ok(false, `mutation target must occur exactly once (${count}x): ${name}`); continue; }
  const res = await detect(html.replace(find, () => rep));
  if (equivalent) { R.ok(true, `${name}: behaviourally equivalent, ${res.by ? 'caught by ' + res.by : 'survives as expected'}`); continue; }
  R.ok(res.by !== null, res.by ? `${name}: caught by ${res.by}` : `${name}: SURVIVED (a hole in the safety net)`);
  if (!res.by) survivors.push(name);
}
if (survivors.length) console.log('\nSurvivors:', survivors);
R.done('mutation');
