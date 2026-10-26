// Mutation test: deliberately break the tool's code in specific ways and require that
// SOMETHING catches each break, either the in-page self-test (which disables the tool)
// or an end-to-end probe whose expected values come from @scure (independent code).
// A mutation that survives both means the safety net has a hole.
// Run: npm ci && node tests/mutation.test.mjs
import nc from 'node:crypto';
import { entropyToMnemonic, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { mnemonicToSeedSync } from '@scure/bip39';
import { HDKey } from '@scure/bip32';
import { bech32 } from '@scure/base';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 as nsha } from '@noble/hashes/sha256';
import { loadPage, ready, readHtml, makeReporter } from './harness.mjs';

const R = makeReporter();
const html = readHtml();
const sha = (s) => new Uint8Array(nc.createHash('sha256').update(s).digest());
const fp = (mn, pw) => HDKey.fromMasterSeed(mnemonicToSeedSync(mn, pw)).fingerprint.toString(16).padStart(8, '0');

const addr = (mn, pw) => {
  const k = HDKey.fromMasterSeed(mnemonicToSeedSync(mn, pw)).derive("m/84'/0'/0'/0/0");
  return bech32.encode('bc', [0, ...bech32.toWords(ripemd160(nsha(k.publicKey)))]);
};

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
  r = await run('dice', 24, D99);     if (r !== expect.d99) fails.push('dice 24 words');
  r = await run('coin', 12, C128);    if (r !== expect.c128) fails.push('coin 12 words');
  r = await run('dice', 12, D50.replace(/(.{5})/g, '$1 ') + ' x,y;z'); if (r !== expect.d50) fails.push('input cleaning (spaces/junk)');
  r = await run('dice', 12, D50 + '1');   if (!/^Need exactly 50/.test(r)) fails.push('rejects wrong length');
  r = await run('dice', 12, D50, UNI);    if (fpOf() !== fp(expect.d50, UNI)) fails.push('unicode passphrase fingerprint');
  if (adOf() !== addr(expect.d50, UNI)) fails.push('first receive address with unicode passphrase');
  // passphrase confirmation must block a mismatch
  mode('dice'); words(12); $('rolls').value = D50; $('rolls').oninput(); $('passphrase').value = 'abc'; $('passphrase2').value = 'abd'; await w.generate();
  if (!/do not match/.test($('genResult').textContent) || adOf()) fails.push('passphrase confirmation blocks a mismatch');
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
  ['address: purpose 84 -> 44',             '[[84,true],', '[[44,true],'],
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
  ['VERIFY ignores the typed passphrase (fingerprint)', 'fingerprint " + await mnemonicFingerprint(r.mnemonic, vp)', 'fingerprint " + await mnemonicFingerprint(r.mnemonic, "")'],
  ['VERIFY ignores the typed passphrase (address)', 'first address " + await mnemonicFirstAddress(r.mnemonic, vp)', 'first address " + await mnemonicFirstAddress(r.mnemonic, "")'],
  ['VERIFY without-passphrase line uses the typed passphrase', 'fingerprint " + await mnemonicFingerprint(r.mnemonic, "") + " | first address " + await mnemonicFirstAddress(r.mnemonic, "")', 'fingerprint " + await mnemonicFingerprint(r.mnemonic, vp) + " | first address " + await mnemonicFirstAddress(r.mnemonic, vp)'],
  ['mnemonic NFKD removed (English ASCII words)', 'enc.encode(mnemonic.normalize("NFKD"))', 'enc.encode(mnemonic)', true],
  ['master key range check removed (unreachable in practice)', 'if(k===0n || k>=SN) throw new Error("Invalid master key");', '', true],
];

const base = await detect(html);
R.ok(base.by === null, 'control: the unmodified file passes the self-test and every probe');

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
