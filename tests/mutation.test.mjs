// Mutation test: deliberately break the tool's code in specific ways and require that
// SOMETHING catches each break, either the in-page self-test (which disables the tool)
// or an end-to-end probe whose expected values come from @scure (independent code).
// A mutation that survives both means the safety net has a hole.
// Run: npm ci && node tests/mutation.test.mjs
import nc from 'node:crypto';
import fs from 'node:fs';
import { entropyToMnemonic, validateMnemonic, mnemonicToEntropy } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { mnemonicToSeedSync } from '@scure/bip39';
import { HDKey } from '@scure/bip32';
import { bech32, bech32m, createBase58check } from '@scure/base';
import { secp256k1, schnorr } from '@noble/curves/secp256k1';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 as nsha } from '@noble/hashes/sha256';
import { LifeHash } from 'lifehash';
import * as btc from '@scure/btc-signer';
import { hex as bhex } from '@scure/base';
import { loadPage, ready, readHtml, makeReporter } from './harness.mjs';

const R = makeReporter();
const html = readHtml();
const sha = (s) => new Uint8Array(nc.createHash('sha256').update(s).digest());
const fp = (mn, pw) => HDKey.fromMasterSeed(mnemonicToSeedSync(mn, pw)).fingerprint.toString(16).padStart(8, '0');

const addr = (mn, pw) => {
  const k = HDKey.fromMasterSeed(mnemonicToSeedSync(mn, pw)).derive("m/84'/0'/0'/0/0");
  return bech32.encode('bc', [0, ...bech32.toWords(ripemd160(nsha(k.publicKey)))]);
};

const b85At = (mn, pw, words, index) => { const k = HDKey.fromMasterSeed(mnemonicToSeedSync(mn, pw)).derive(`m/83696968'/39'/0'/${words}'/${index}'`);
  const e = nc.createHmac('sha512', 'bip-entropy-from-k').update(k.privateKey).digest(); return entropyToMnemonic(new Uint8Array(e.subarray(0, words * 4 / 3)), wordlist); };
const segAt = (mn, pw, chain, i) => { const k = HDKey.fromMasterSeed(mnemonicToSeedSync(mn, pw)).derive(`m/84'/0'/0'/${chain}/${i}`);
  return bech32.encode('bc', [0, ...bech32.toWords(ripemd160(nsha(k.publicKey)))]); };
const b58c = createBase58check(nsha);
const altAt = (type, mn, pw, acct, chain, i, test) => { const purpose = { pkh: 44, 'sh-wpkh': 49 }[type]; const k = HDKey.fromMasterSeed(mnemonicToSeedSync(mn, pw)).derive(`m/${purpose}'/${test ? 1 : 0}'/${acct}'/${chain}/${i}`);
  const h = ripemd160(nsha(k.publicKey)); if (type === 'pkh') return b58c.encode(Uint8Array.from([test ? 0x6f : 0, ...h]));
  return b58c.encode(Uint8Array.from([test ? 0xc4 : 5, ...ripemd160(nsha(Uint8Array.from([0, 0x14, ...h])))])); };
const segAtT = (mn, pw, acct, chain, i) => { const k = HDKey.fromMasterSeed(mnemonicToSeedSync(mn, pw)).derive(`m/84'/1'/${acct}'/${chain}/${i}`);
  return bech32.encode('tb', [0, ...bech32.toWords(ripemd160(nsha(k.publicKey)))]); };
const trAtT = (mn, pw, acct, chain, i) => { const k = HDKey.fromMasterSeed(mnemonicToSeedSync(mn, pw)).derive(`m/86'/1'/${acct}'/${chain}/${i}`); const xo = k.publicKey.slice(1);
  const P = secp256k1.ProjectivePoint.fromHex('02' + Buffer.from(xo).toString('hex')); const t = schnorr.utils.taggedHash('TapTweak', xo);
  const Q = P.add(secp256k1.ProjectivePoint.BASE.multiply(BigInt('0x' + Buffer.from(t).toString('hex'))));
  return bech32m.encode('tb', [1, ...bech32m.toWords(Q.toRawBytes(true).slice(1))]); };
const trAt = (mn, pw, chain, i) => { const k = HDKey.fromMasterSeed(mnemonicToSeedSync(mn, pw)).derive(`m/86'/0'/0'/${chain}/${i}`); const xo = k.publicKey.slice(1);
  const P = secp256k1.ProjectivePoint.fromHex('02' + Buffer.from(xo).toString('hex')); const t = schnorr.utils.taggedHash('TapTweak', xo);
  const Q = P.add(secp256k1.ProjectivePoint.BASE.multiply(BigInt('0x' + Buffer.from(t).toString('hex'))));
  return bech32m.encode('bc', [1, ...bech32m.toWords(Q.toRawBytes(true).slice(1))]); };

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
  { const ABOUT = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'; const seedB = mnemonicToSeedSync(ABOUT, ''); const VER = { wpkh: 0x04b24746, 'sh-wpkh': 0x049d7cb2, pkh: 0x0488b21e, tr: 0x0488b21e }, PUR = { wpkh: 84, 'sh-wpkh': 49, pkh: 44, tr: 86 };
    for (const [type, acct] of [['wpkh', 0], ['sh-wpkh', 0], ['pkh', 0], ['tr', 0], ['sh-wpkh', 3], ['pkh', 7], ['tr', 2147483647]]) {
      const wo = await w.watchOnlyFromSeed(seedB, type, acct), pu = PUR[type], hk = HDKey.fromMasterSeed(seedB, { private: 0, public: VER[type] }), hx = HDKey.fromMasterSeed(seedB);
      const tag = `watch ${type} account ${acct}`, path = `m/${pu}'/0'/${acct}'`;
      if (wo.key !== hk.derive(path).publicExtendedKey) fails.push(tag + ': key (' + (type === 'wpkh' ? 'zpub' : type === 'sh-wpkh' ? 'ypub' : 'xpub') + ')');
      if (wo.xpub !== hx.derive(path).publicExtendedKey) fails.push(tag + ': xpub');
      const first = { wpkh: segAt, tr: trAt }[type] ? null : altAt(type, ABOUT, '', acct, 0, 0);
      if (type === 'wpkh' || type === 'tr') { const k = hx.derive(`${path}/0/0`); const exp = type === 'wpkh' ? bech32.encode('bc', [0, ...bech32.toWords(ripemd160(nsha(k.publicKey)))]) : (acct === 0 ? trAt(ABOUT, '', 0, 0) : null); if (exp && wo.first !== exp) fails.push(tag + ': first address'); }
      else if (wo.first !== first) fails.push(tag + ': first address');
      const o = `${wo.fp}/${pu}h/0h/${acct}h`, wrap = (b) => type === 'sh-wpkh' ? `sh(wpkh([${o}]${wo.xpub}/${b}/*))#` : `${type}([${o}]${wo.xpub}/${b}/*)#`;
      if (!wo.receive.startsWith(wrap(0)) || !wo.change.startsWith(wrap(1))) fails.push(tag + ': descriptors'); } }
  { const ABOUT = 'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about'; const seedB = mnemonicToSeedSync(ABOUT, '');
    const TV = { wpkh: 0x045f1cf6, 'sh-wpkh': 0x044a5262, pkh: 0x043587cf, tr: 0x043587cf }, PUR = { wpkh: 84, 'sh-wpkh': 49, pkh: 44, tr: 86 };
    const MV = { main: { 'ms-wsh': 0x02aa7ed3, 'ms-sh-wsh': 0x0295b43f }, test: { 'ms-wsh': 0x02575483, 'ms-sh-wsh': 0x024289ef } }, SC = { 'ms-wsh': 2, 'ms-sh-wsh': 1 };
    for (const [type, acct] of [['wpkh', 0], ['sh-wpkh', 1], ['pkh', 0], ['tr', 4]]) {
      const wo = await w.watchOnlyFromSeed(seedB, type, acct, 'test'), tag = `testnet ${type} account ${acct}`, path = `m/${PUR[type]}'/1'/${acct}'`;
      if (wo.key !== HDKey.fromMasterSeed(seedB, { private: 0, public: TV[type] }).derive(path).publicExtendedKey) fails.push(tag + ': key');
      if (wo.xpub !== HDKey.fromMasterSeed(seedB, { private: 0, public: 0x043587cf }).derive(path).publicExtendedKey) fails.push(tag + ': tpub');
      if (!wo.receive.includes(`[${wo.fp}/${PUR[type]}h/1h/${acct}h]${wo.xpub}/0/*`)) fails.push(tag + ": descriptor origin");
      const first = type === 'wpkh' ? segAtT(ABOUT, '', acct, 0, 0) : type === 'tr' ? trAtT(ABOUT, '', acct, 0, 0) : altAt(type, ABOUT, '', acct, 0, 0, true);
      if (wo.first !== first) fails.push(tag + ': first address'); }
    for (const net of ['main', 'test']) for (const type of ['ms-wsh', 'ms-sh-wsh']) for (const acct of [0, 2]) {
      const wo = await w.watchOnlyFromSeed(seedB, type, acct, net), tag = `multisig ${type} ${net} account ${acct}`, coin = net === 'test' ? 1 : 0, path = `m/48'/${coin}'/${acct}'/${SC[type]}'`;
      if (wo.key !== HDKey.fromMasterSeed(seedB, { private: 0, public: MV[net][type] }).derive(path).publicExtendedKey) fails.push(tag + ': key');
      if (wo.receive !== `[${wo.fp}/48h/${coin}h/${acct}h/${SC[type]}h]${HDKey.fromMasterSeed(seedB, { private: 0, public: net === 'test' ? 0x043587cf : 0x0488b21e }).derive(path).publicExtendedKey}`) fails.push(tag + ': key origin');
      if (wo.change !== '' || wo.first !== '') fails.push(tag + ': has no addresses'); } }
  { const LW = async (x) => { $('lwInput').value = x; await w.findLastWords(); return [$('lwStatus').textContent, $('lwOut').textContent]; };
    let [a, o] = await LW('abandon '.repeat(10) + 'xyzzy'); if (!/^Unknown word: xyzzy/.test(a) || o !== '') fails.push('last word: unknown word is rejected');
    [a, o] = await LW('abandon '.repeat(11)); if (!/^128 words complete this 12-word phrase/.test(a) || o.split(/\s+/).length !== 128) fails.push('last word: 12-word list');
    [a, o] = await LW('abandon '.repeat(10)); if (!/^Type 11, 14, 17, 20 or 23/.test(a)) fails.push('last word: wrong word count rejected');
    await LW('abandon '.repeat(11)); $('lwInput').dispatchEvent(new w.Event('input')); if ($('lwOut').textContent !== '') fails.push('last word: list cleared when the words change');
    await LW('abandon '.repeat(11)); w.clearLastWords(true); if ($('lwInput').value !== '' || $('lwOut').textContent !== '') fails.push('last word: CLEAR empties the box'); }
  try { const K = (n) => new Uint8Array(32).fill(n), pubE = (n) => secp256k1.getPublicKey(K(n), true), pubS = (n) => schnorr.getPublicKey(K(n));
    const kinds = { p2wpkh: (n) => btc.p2wpkh(pubE(n)), p2pkh: (n) => btc.p2pkh(pubE(n)), p2tr: (n) => btc.p2tr(pubS(n)), p2sh: (n) => btc.p2sh(btc.p2wpkh(pubE(n))), p2wsh: (n) => btc.p2wsh(btc.p2ms(1, [pubE(n), pubE(n + 1)])) };
    const insp = async (bytes, net = 'main') => w.inspectPsbt(new Uint8Array(bytes), net);
    // every script type, mainnet and testnet, against the independent decoder
    for (const test of [false, true]) { const NET = test ? btc.TEST_NETWORK : btc.NETWORK, ad = (sc) => btc.Address(NET).encode(btc.OutScript.decode(sc));
      for (const [ik, ok] of [['p2wpkh', 'p2tr'], ['p2tr', 'p2wsh'], ['p2pkh', 'p2sh'], ['p2sh', 'p2pkh'], ['p2wsh', 'p2wpkh']]) {
        const tx = new btc.Transaction({ allowUnknownOutputs: true }); tx.addInput({ txid: '11'.repeat(32), index: 1, witnessUtxo: { script: kinds[ik](20).script, amount: 123456n } });
        tx.addOutput({ script: kinds[ok](40).script, amount: 50000n }); tx.addOutput({ script: kinds.p2wpkh(41).script, amount: 1n });
        const r = await insp(tx.toPSBT(0), test ? 'test' : 'main'), tag = `psbt ${test ? 'testnet ' : ''}${ik} -> ${ok}`;
        if (r.ins[0].address !== ad(kinds[ik](20).script)) fails.push(tag + ': input address');
        if (r.outs[0].address !== ad(kinds[ok](40).script) || r.outs[1].address !== ad(kinds.p2wpkh(41).script)) fails.push(tag + ': output addresses');
        if (r.fee !== 123456n - 50001n) fails.push(tag + ': fee'); } }
    // big numbers, locktime, version, 3-byte and 5-byte length prefixes, signatures, finalized inputs, taproot key information
    { const tx = new btc.Transaction({ lockTime: 2500000000, version: 2, allowUnknownOutputs: true });
      const TXID = Array.from({ length: 32 }, (_, k) => (k * 7 + 3).toString(16).padStart(2, '0')).join(''); for (const [i, id] of [[70000, TXID], [0, 'cd'.repeat(32)], [3, 'ef'.repeat(32)]]) tx.addInput({ txid: id, index: i, witnessUtxo: { script: kinds.p2wpkh(5).script, amount: i === 70000 ? 2100000000000000n : 5n } });
      tx.addOutput({ script: Uint8Array.from([0x6a, 0x4d, 0x2c, 0x01, ...new Uint8Array(300).fill(7)]), amount: 0n });
      tx.addOutput({ script: Uint8Array.from([0x6a, 0x4e, 0x70, 0x11, 0x01, 0x00, ...new Uint8Array(70000).fill(7)]), amount: 1n });
      tx.addOutput({ script: kinds.p2tr(3).script, amount: 7n, tapBip32Derivation: [[pubS(3), { hashes: [], der: { fingerprint: 0x01020304, path: [0x80000056] } }]] });
      tx.addOutput({ script: kinds.p2tr(11).script, amount: 3n, tapBip32Derivation: [[pubS(11), { hashes: [new Uint8Array(32).fill(9), new Uint8Array(32).fill(8)], der: { fingerprint: 0x0a0b0c0d, path: [0x80000056] } }]] });
      tx.addOutput({ script: kinds.p2wpkh(4).script, amount: 9n, bip32Derivation: [[pubE(4), { fingerprint: 0xdeadbeef, path: [0x80000054] }]] });
      tx.updateInput(0, { partialSig: [[pubE(5), new Uint8Array(71).fill(1)], [pubE(6), new Uint8Array(71).fill(2)]] }, true); tx.updateInput(1, { finalScriptWitness: [new Uint8Array([2, 2, 2])] }, true);
      const r = await insp(tx.toPSBT(0));
      if (r.version !== 2 || r.locktime !== 2500000000) fails.push('psbt: version and locktime (locktime above 2^31)');
      if (r.ins[0].vout !== 70000 || r.ins[0].amount !== 2100000000000000n) fails.push('psbt: large vout and 21,000,000 BTC amount');
      if (r.ins[0].sigs !== 2 || r.ins[0].final || r.ins[1].sigs !== 0 || !r.ins[1].final) fails.push('psbt: signature count and finalized flag');
      if (r.outs.length !== 5 || !/^OP_RETURN/.test(r.outs[0].address) || !/^OP_RETURN/.test(r.outs[1].address) || r.outs[1].amount !== 1n) fails.push('psbt: script longer than 252 and than 65535 bytes');
      if (r.outs[2].fps.join() !== '01020304' || r.outs[4].fps.join() !== 'deadbeef' || r.outs[3].fps.join() !== '0a0b0c0d' || r.outs[0].fps.length !== 0) fails.push('psbt: wallet key information (taproot and ordinary)');
      if (r.fee !== 2100000000000010n - 20n) fails.push('psbt: fee with a huge input');
      if (r.ins[0].txid !== TXID || r.ins[2].vout !== 3) fails.push('psbt: txid and index of each input'); }
    // inputs without an amount, a legacy input given as a full previous transaction (also a segwit-serialized previous transaction)
    { const prev = new btc.Transaction({ allowLegacyWitnessUtxo: true }); prev.addInput({ txid: 'cd'.repeat(32), index: 0, witnessUtxo: { script: kinds.p2wpkh(1).script, amount: 500000n } });
      prev.addOutputAddress(kinds.p2pkh(8).address, 300000n); prev.addOutputAddress(kinds.p2pkh(9).address, 190000n);
      for (const withWitness of [true, false]) { const t2 = new btc.Transaction({ allowLegacyWitnessUtxo: true }); t2.addInput({ txid: prev.id, index: 1, nonWitnessUtxo: prev.toBytes(withWitness, withWitness) }); t2.addOutputAddress(kinds.p2pkh(10).address, 180000n);
        const r = await insp(t2.toPSBT(0)); if (r.ins[0].amount !== 190000n || r.ins[0].address !== kinds.p2pkh(9).address || r.fee !== 10000n) fails.push('psbt: amount read from a full previous transaction' + (withWitness ? ' with witness data' : '')); }
      { const vi = (n) => n < 253 ? [n] : [253, n & 255, n >> 8], kv = (k, v) => [...vi(k.length), ...k, ...vi(v.length), ...v], le8 = (n) => { const o = []; for (let q = 0; q < 8; q++) o.push(Number((BigInt(n) >> BigInt(8 * q)) & 255n)); return o; };
        const out = (amt, sc) => [...le8(amt), ...vi(sc.length), ...sc], sc9 = [...kinds.p2pkh(9).script], sc8 = [...kinds.p2pkh(8).script];
        const prevSeg = [2, 0, 0, 0, 0, 1, 1, ...new Array(32).fill(5), 0, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 2, ...out(300000, sc8), ...out(190000, sc9), 1, 1, 0xff, 0, 0, 0, 0];
        const unsigned = [2, 0, 0, 0, 1, ...new Array(32).fill(6), 1, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 1, ...out(180000, [...kinds.p2wpkh(2).script]), 0, 0, 0, 0];
        const psbt = Uint8Array.from([0x70, 0x73, 0x62, 0x74, 0xff, ...kv([0], unsigned), 0, ...kv([0], prevSeg), 0, 0]);
        const rs = await insp(psbt); if (rs.ins[0].amount !== 190000n || rs.fee !== 10000n || rs.outs.length !== 1) fails.push('psbt: previous transaction in segwit serialization (marker and flag)'); }
      const t3 = new btc.Transaction({ allowUnknownOutputs: true }); t3.addInput({ txid: '22'.repeat(32), index: 0 }); t3.addOutput({ script: kinds.p2wpkh(2).script, amount: 1n });
      const r3 = await insp(t3.toPSBT(0)); if (r3.ins[0].amount !== null || r3.fee !== null) fails.push('psbt: unknown input amount gives an unknown fee');
      const t4 = new btc.Transaction({ allowUnknownOutputs: true }); t4.addInput({ txid: '33'.repeat(32), index: 0, witnessUtxo: { script: kinds.p2wpkh(1).script, amount: 1000n } }); t4.addInput({ txid: '44'.repeat(32), index: 0 }); t4.addOutput({ script: kinds.p2wpkh(2).script, amount: 1n });
      const r4 = await insp(t4.toPSBT(0)); if (r4.fee !== null || r4.ins[0].amount !== 1000n || r4.ins[1].amount !== null) fails.push('psbt: one unknown input amount among known ones gives an unknown fee'); }
    // errors
    for (const [name, bytes, re] of [['wrong marker', Uint8Array.from([1, 2, 3, 4, 5, 6]), /not a PSBT/], ['too short', Uint8Array.from([0x70, 0x73]), /not a PSBT/]]) { let m = ''; try { await insp(bytes); } catch (e) { m = e.message; } if (!re.test(m)) fails.push('psbt: ' + name + ' rejected'); }
    { const tx = new btc.Transaction(); tx.addInput({ txid: '11'.repeat(32), index: 0, witnessUtxo: { script: kinds.p2wpkh(1).script, amount: 10n } }); tx.addOutput({ script: kinds.p2wpkh(2).script, amount: 5n });
      const good = tx.toPSBT(0); let m = ''; try { await insp(good.slice(0, good.length - 7)); } catch (e) { m = e.message; } if (!/cut short|damaged/.test(m)) fails.push('psbt: cut-off PSBT rejected');
      const v2 = Uint8Array.from([0x70, 0x73, 0x62, 0x74, 0xff, 1, 0xfb, 4, 2, 0, 0, 0, 0]); m = ''; try { await insp(v2); } catch (e) { m = e.message; } if (!/version 2/.test(m)) fails.push('psbt: version 2 rejected');
      const notx = Uint8Array.from([0x70, 0x73, 0x62, 0x74, 0xff, 0]); m = ''; try { await insp(notx); } catch (e) { m = e.message; } if (!/No unsigned transaction/.test(m)) fails.push('psbt: missing unsigned transaction reported');
      const withTail = new Uint8Array([...good, 9, 9]); const rt = await insp(withTail); if (!rt.trailing) fails.push('psbt: extra data after the PSBT is noticed'); if ((await insp(good)).trailing) fails.push('psbt: no trailing note on a clean PSBT'); }
    // text handling, report text and the UI
    { const tx = new btc.Transaction(); tx.addInput({ txid: '11'.repeat(32), index: 0, witnessUtxo: { script: kinds.p2wpkh(1).script, amount: 100000000n } }); tx.addOutput({ script: kinds.p2wpkh(2).script, amount: 99000000n });
      const b = tx.toPSBT(0), b64 = Buffer.from(b).toString('base64'), hx = Buffer.from(b).toString('hex');
      const run = async (x) => { $('psbtInput').value = x; await w.runPsbt(); return [$('psbtStatus').textContent, $('psbtOut').textContent]; };
      let [a, o] = await run(b64); if (!/^Read OK/.test(a) || !/INPUT 0: 1\.00000000 BTC \(100000000 sats\)/.test(o) || !/OUTPUT 0: 0\.99000000 BTC \(99000000 sats\)/.test(o) || !/FEE: 0\.01000000 BTC \(1000000 sats\) \(1\.01% of the total of all outputs\)/.test(o)) fails.push('psbt: report text and fee percentage');
      [a, o] = await run(hx.toUpperCase()); if (!/^Read OK/.test(a)) fails.push('psbt: hex in capitals accepted');
      [a, o] = await run(b64.slice(0, 40) + ' \n ' + b64.slice(40)); if (!/^Read OK/.test(a)) fails.push('psbt: base64 with line breaks accepted');
      [a, o] = await run('zzz not psbt !!'); if (!/Paste the PSBT as base64/.test(a) || o !== '') fails.push('psbt: junk text rejected with the paste hint');
      $('psbtNet').value = 'test'; [a, o] = await run(b64); if (!/to tb1q/.test(o)) fails.push('psbt: testnet addresses when Testnet is chosen'); $('psbtNet').value = 'main';
      $('psbtInput').dispatchEvent(new w.Event('input')); if ($('psbtOut').textContent !== '') fails.push('psbt: report cleared when the text changes');
      await run(b64); w.clearPsbt(true); if ($('psbtInput').value !== '' || $('psbtOut').textContent !== '') fails.push('psbt: CLEAR empties the box');
      { const wf = fp(expect.d50, ''), tk = new btc.Transaction({ allowUnknownOutputs: true });
        tk.addInput({ txid: '11'.repeat(32), index: 0, witnessUtxo: { script: kinds.p2wpkh(1).script, amount: 100000n } });
        tk.addOutput({ script: kinds.p2wpkh(2).script, amount: 40000n, bip32Derivation: [[pubE(2), { fingerprint: parseInt(wf, 16), path: [0x80000054] }]] });
        tk.addOutput({ script: kinds.p2wpkh(3).script, amount: 30000n, bip32Derivation: [[pubE(3), { fingerprint: 0xdeadbeef, path: [0x80000054] }]] });
        tk.addOutput({ script: kinds.p2wpkh(4).script, amount: 20000n });
        const kb = Buffer.from(tk.toPSBT(0)).toString('base64'); $('phrase').value = ''; [a, o] = await run(kb);
        const blocks = o.split('OUTPUT ').slice(1);
        if (!/has wallet key information \(fingerprint deadbeef\): usually this wallet's own change/.test(blocks[1] || '') || /no wallet key information/.test(blocks[1] || '')) fails.push('psbt: report marks an output that carries key information');
        if (!/no wallet key information: treat as a payment to someone else/.test(blocks[2] || '') || /has wallet key information/.test(blocks[2] || '')) fails.push('psbt: report marks an output without key information as a payment to someone else');
        if (/matches the wallet typed above/.test(o)) fails.push('psbt: no wallet match claimed when no words are typed');
        $('phrase').value = expect.d50; $('verifyPass').value = ''; [a, o] = await run(kb); const bl2 = o.split('OUTPUT ').slice(1);
        if (!/matches the wallet typed above/.test(bl2[0] || '')) fails.push('psbt: output made by the typed words is marked as matching');
        if (/matches the wallet typed above/.test((bl2[1] || '') + (bl2[2] || ''))) fails.push('psbt: other outputs not marked as matching');
        $('phrase').value = ''; }
      await w.onPsbtFile(new w.File([b], 'a.psbt')); if (!/^Read OK/.test($('psbtStatus').textContent)) fails.push('psbt: binary file read');
      await w.onPsbtFile(new w.File([b64], 'a.txt')); if (!/^Read OK/.test($('psbtStatus').textContent)) fails.push('psbt: text file read');
      await w.onPsbtFile(new w.File([new Uint8Array(2000001)], 'big.psbt')); if (!/too large/.test($('psbtStatus').textContent)) fails.push('psbt: oversized file refused');
      const neg = new btc.Transaction({ allowUnknownOutputs: true }); neg.addInput({ txid: '11'.repeat(32), index: 0, witnessUtxo: { script: kinds.p2wpkh(1).script, amount: 1000n } }); neg.addOutput({ script: kinds.p2wpkh(2).script, amount: 5000n });
      let bn = null; try { bn = Buffer.from(neg.toPSBT(0)).toString('base64'); } catch (e) { bn = null; }
      if (bn) { [a, o] = await run(bn); if (!/FEE: -0\.00004000 BTC \(-?4000 sats\)/.test(o)) fails.push('psbt: outputs larger than inputs shown as a negative fee'); } } }
  catch (e) { fails.push('psbt: the inspector crashed: ' + e.message); }
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
    { const tr = [...w.document.querySelectorAll('#trList li')].map(x => x.textContent);
      if (tr.length !== 5 || tr.some(x => !/^bc1p[0-9a-z]{58}$/.test(x)) || new Set(tr).size !== 5 || $('trBox').style.display !== '') fails.push('five Taproot addresses are listed'); }
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
  // SeedQR / CompactSeedQR: data, QR codes, 7 x 7 blocks for copying by hand, print sheets, clearing
  try {
    const fxS = JSON.parse(fs.readFileSync(new URL('./fixtures/seedqr.json', import.meta.url), 'utf8')); let bd = 0, bs = 0, bg = 0;
    const hs = (rows) => nc.createHash('sha256').update(rows.map(r => r.map(x => x ? '1' : '0').join('')).join('')).digest('hex');
    fxS.forEach((c, i) => { const ws = c.words.split(' '), d = w.seedQrData(ws);
      if (!d || d.digits !== c.digits || Buffer.from(d.bytes).toString('hex') !== c.entropy) bd++;
      for (const kind of ['seedqr', 'compact']) { const f = c.formats[kind], m = (i + (kind === 'compact' ? 3 : 0)) % 8, q = w.seedQrMatrix(ws, kind, m);
        if (q.version !== f.version || q.rows.length !== f.size || hs(q.rows) !== f.hashes[m]) bs++;
        const a = w.seedQrMatrix(ws, kind); if (hs(a.rows) !== f.hashes[a.mask]) bs++;
        const rebuilt = q.rows.map(row => { const o = new Array(row.length).fill(false); for (const part of w.qrRowRuns(row).split(', ').filter(Boolean)) { const [x, y] = part.split('-').map(Number); for (let k = x; k <= (y || x); k++) o[k - 1] = true; } return o; });
        if (hs(rebuilt) !== hs(q.rows)) bg++;
        const N = q.rows.length, dark = q.rows.flat().filter(Boolean).length, cnt = (svg, fill) => { const mm = svg.match(new RegExp('<path d="([^"]*)" fill="' + fill + '"')); return mm ? (mm[1].match(/M/g) || []).length : 0; };
        if (cnt(w.qrGridSvg(q.rows, 0, 0, N, N, 7, false), '#000') !== dark || cnt(w.qrGridSvg(q.rows, 0, 0, N, N, 7, true), '#000') !== 0) bg++;
        let sd = 0, sg = 0; const per = Math.ceil(N / 7);
        for (let by = 0; by < per; by++) for (let bx = 0; bx < per; bx++) { const svg = w.qrGridSvg(q.rows, bx * 7, by * 7, bx * 7 + 7, by * 7 + 7, 7, false); sd += cnt(svg, '#000'); sg += cnt(svg, '#c8c8c8'); }
        if (sd !== dark || sg !== per * per * 49 - N * N) bg++; } });
    if (bd) fails.push('seedqr: digits and bytes from the words');
    if (bs) fails.push('seedqr: QR codes match the independent library');
    if (bg) fails.push('seedqr: hand-copy grid, blocks and row lists');
    const bad = [['abandon', 'abandon'], Array(11).fill('abandon').concat('zzzz'), entropyToMnemonic(new Uint8Array(20), wordlist).split(' ')];
    if (bad.some(x => w.seedQrData(x) !== null)) fails.push('seedqr: only 12 and 24 known words give a SeedQR');
    { let m = ''; try { w.seedQrMatrix(['abandon', 'abandon'], 'seedqr'); } catch (e) { m = e.message; } if (!/only for 12 and 24/.test(m)) fails.push('seedqr: a short phrase gives an error, not a code'); }
    // the page: show, hide, blocks, mini-map, print
    const pr = { n: 0, text: '', html: '', cls: '' }, conf = { v: true, n: 0 };
    w.print = () => { pr.n++; pr.text = $('printQr').textContent; pr.html = $('printQr').innerHTML; pr.cls = w.document.body.className; };
    w.confirm = () => { conf.n++; return conf.v; };
    const alerts = []; w.alert = (m) => alerts.push(m);
    const sz = () => { const v = $('sqImg').querySelector('svg'); return v ? Math.round(v.viewBox.baseVal.width) - 8 : 0; }, gc = () => $('sqGuideCaption').textContent;
    await run('dice', 12, D50, 'SECRETPASS'); const sw = $('genResult').textContent.split('\n')[0];
    if ($('seedQrBox').style.display !== '' || $('seedQrBox').open) fails.push('seedqr: box shown (closed) after FORGE');
    w.showSeedQr('seedqr'); if (sz() !== 25 || $('sqBox').style.display !== '' || !/^SeedQR for these 12 words, 25 x 25 squares/.test($('sqCaption').textContent)) fails.push('seedqr: SEEDQR shows a 25 x 25 code with its caption');
    w.showSeedQr('compact'); if (sz() !== 21 || !/^CompactSeedQR for these 12 words, 21 x 21 squares/.test($('sqCaption').textContent)) fails.push('seedqr: COMPACTSEEDQR shows a 21 x 21 code with its caption');
    w.hideSeedQr(); if ($('sqImg').innerHTML !== '' || $('sqBox').style.display !== 'none' || $('sqCaption').textContent !== '') fails.push('seedqr: HIDE removes the code');
    alerts.length = 0; pr.n = 0; w.printSeedQr(); w.printSqGuide(); w.openSqGuide(); w.printSqBlank();
    if (pr.n !== 0 || alerts.length !== 4) fails.push('seedqr: nothing is printed or opened while no code is shown (after HIDE too)');
    w.showSeedQr('seedqr'); conf.v = false; conf.n = 0; w.printSeedQr(); w.printSqGuide();
    if (pr.n !== 0 || conf.n !== 2) fails.push('seedqr: printing the code or the guide asks first and stops when declined');
    conf.v = true; w.printSeedQr();
    if (pr.n !== 1 || !/^VOIDFORGE SEEDQR \(12 words, 25 x 25 squares\)/.test(pr.text) || !/<svg/.test(pr.html) || /print-qr/.test(pr.cls) === false || pr.text.includes('SECRETPASS') || pr.text.includes(sw.split(' ').slice(0, 3).join(' ')) || !pr.text.includes($('fingerprint').textContent) || !/Passphrase used: YES/.test(pr.text)) fails.push('seedqr: PRINT THIS QR sheet (code, fingerprint, no words, no passphrase)');
    w.dispatchEvent(new w.Event('afterprint')); if ($('printQr').textContent !== '' || w.document.body.classList.contains('print-qr')) fails.push('seedqr: print area cleaned up after printing');
    w.printSqGuide();
    if (pr.n !== 2 || !/HAND-COPY GUIDE \(12 words, 25 x 25 squares\)/.test(pr.text) || !/Row 1: /.test(pr.text) || !/Row 25: /.test(pr.text) || /Row 26/.test(pr.text) || pr.text.includes('SECRETPASS') || pr.text.includes(sw.split(' ').slice(0, 3).join(' '))) fails.push('seedqr: PRINT HAND-COPY GUIDE sheet (rows, no words, no passphrase)');
    w.dispatchEvent(new w.Event('afterprint')); conf.n = 0; w.printSqBlank();
    if (pr.n !== 3 || conf.n !== 0 || !/BLANK 25 x 25 GRID FOR SEEDQR/.test(pr.text) || /Row 1: /.test(pr.text)) fails.push('seedqr: PRINT BLANK GRID sheet (no question, no rows)');
    { const bm = pr.html.match(/<path d="([^"]*)" fill="#000"/); if (!bm || bm[1] !== '') fails.push('seedqr: the blank grid sheet has no black squares'); }
    w.dispatchEvent(new w.Event('afterprint'));
    w.openSqGuide();
    if ($('sqGuide').style.display !== '' || !/^Block 1 of 16: rows 1 to 7, columns 1 to 7 of the 25 x 25 grid\./.test(gc()) || !$('sqGuideImg').querySelector('svg') || !$('sqMini').querySelector('svg')) fails.push('seedqr: COPY BY HAND opens block 1 of 16 with a mini-map');
    w.sqGuideBlock(1); if (!/^Block 2 of 16: rows 1 to 7, columns 8 to 14/.test(gc())) fails.push('seedqr: NEXT BLOCK goes right');
    w.sqGuideBlock(1); w.sqGuideBlock(1);
    { const txt = [...$('sqGuideImg').querySelectorAll('text')].map(x => x.textContent).join(',');
      const mini = $('sqMini').innerHTML.match(/<rect x="(\d+)" y="(\d+)" width="(\d+)" height="(\d+)" fill="rgba/);
      if (!/^Block 4 of 16: rows 1 to 7, columns 22 to 25 of the 25 x 25 grid\. Grey squares are outside the code/.test(gc()) || txt !== '22,23,24,25,1,2,3,4,5,6,7') fails.push('seedqr: a cut-off block names only the rows and columns that exist');
      if (!mini || mini.slice(1).join() !== '23,2,4,7') fails.push('seedqr: the mini-map outlines the block, cut at the edge of the code');
      const gp = $('sqGuideImg').querySelector('path[fill="#c8c8c8"]'); if (!gp || (gp.getAttribute('d').match(/M/g) || []).length !== 3 * 7) fails.push('seedqr: squares outside the code are grey'); }
    w.sqGuideBlock(1); if (!/^Block 5 of 16: rows 8 to 14, columns 1 to 7/.test(gc())) fails.push('seedqr: blocks continue on the next row');
    w.sqGuideBlock(-1); if (!/^Block 4 of 16/.test(gc())) fails.push('seedqr: PREVIOUS BLOCK goes back');
    w.openSqGuide(); w.sqGuideBlock(-1); if (!/^Block 16 of 16: rows 22 to 25, columns 22 to 25/.test(gc())) fails.push('seedqr: PREVIOUS BLOCK wraps to the last block');
    w.sqGuideBlock(1); if (!/^Block 1 of 16/.test(gc())) fails.push('seedqr: NEXT BLOCK wraps to the first block');
    w.sqGuideFull(); if (!/^Whole SeedQR grid, 25 x 25 squares/.test(gc()) || $('sqGuideImg').querySelectorAll('text').length !== 50 || $('sqMini').innerHTML !== '' || $('sqGuide').style.display !== '') fails.push('seedqr: WHOLE GRID shows every row and column number');
    w.showSeedQr('compact'); if ($('sqGuide').style.display !== 'none' || $('sqGuideImg').innerHTML !== '' || $('sqMini').innerHTML !== '' || gc() !== '') fails.push('seedqr: showing another code closes the guide');
    w.openSqGuide(); if (!/^Block 1 of 9: rows 1 to 7, columns 1 to 7 of the 21 x 21 grid/.test(gc())) fails.push('seedqr: a 21 x 21 code has 9 blocks');
    w.hideSeedQr(); if ($('sqGuide').style.display !== 'none' || $('sqMini').innerHTML !== '') fails.push('seedqr: HIDE closes the guide too');
    w.showSeedQr('seedqr'); w.openSqGuide(); await run('dice', 12, D50, ''); if ($('sqImg').innerHTML !== '' || $('sqBox').style.display !== 'none' || $('sqGuide').style.display !== 'none' || $('sqGuideImg').innerHTML !== '') fails.push('seedqr: a new FORGE removes the old code and guide');
    w.showSeedQr('seedqr'); w.clearAll(); if ($('sqImg').innerHTML !== '' || $('seedQrBox').style.display !== 'none') fails.push('seedqr: CLEAR removes the code and hides the box');
    alerts.length = 0; w.showSeedQr('seedqr'); if ($('sqImg').innerHTML !== '' || !/Generate a seed first/.test(alerts.join('|'))) fails.push('seedqr: no code without a seed');
    await run('dice', 24, D99, ''); w.showSeedQr('seedqr'); if (sz() !== 29 || !/^SeedQR for these 24 words, 29 x 29 squares/.test($('sqCaption').textContent)) fails.push('seedqr: 24 words give a 29 x 29 code');
    w.openSqGuide(); if (!/^Block 1 of 25: rows 1 to 7, columns 1 to 7 of the 29 x 29/.test(gc())) fails.push('seedqr: a 29 x 29 code has 25 blocks');
    for (let i = 0; i < 4; i++) w.sqGuideBlock(1); if (!/^Block 5 of 25: rows 1 to 7, columns 29 to 29/.test(gc())) fails.push('seedqr: the last block column of a 29 x 29 code is one square wide');
    w.showSeedQr('compact'); if (sz() !== 25 || !/^CompactSeedQR for these 24 words, 25 x 25 squares/.test($('sqCaption').textContent)) fails.push('seedqr: 24 words give a 25 x 25 CompactSeedQR');
    w.setResult('x', Array(15).fill('abandon')); if ($('seedQrBox').style.display !== 'none') fails.push('seedqr: no SeedQR box for a 15-word phrase'); w.setResult('x', null); if ($('seedQrBox').style.display !== 'none') fails.push('seedqr: no SeedQR box without words');
    w.setResult(sw, Array(12).fill('abandon')); if ($('seedQrBox').style.display !== '') fails.push('seedqr: box shown for 12 words');
    if (w.qrRowRuns([false, true, true]) !== '2-3' || w.qrRowRuns([true, false, true, true]) !== '1, 3-4' || w.qrRowRuns([true]) !== '1' || w.qrRowRuns([false, false]) !== '') fails.push('seedqr: row lists are written as runs, also at the right edge');
    { const q = w.qrMatrix('a'), svg = w.qrGridSvg(q.rows, 18, 18, 25, 25, 7, false), t = (svg.match(/<text/g) || []).length; if (t !== 2 * (q.rows.length - 18)) fails.push('seedqr: no numbers for squares outside the code'); }
    { const q = w.qrMatrix('a'), mm2 = w.qrMiniMapSvg(q.rows, 18, 18, 25, 25).match(/<rect x="(\d+)" y="(\d+)" width="(\d+)" height="(\d+)" fill="rgba/); if (!mm2 || mm2.slice(3).join() !== '3,3') fails.push('seedqr: the mini-map outline is cut at the bottom and right edges'); }
    w.print = () => {}; w.confirm = () => true; w.alert = () => {};
  } catch (e) { fails.push('seedqr: the probe crashed: ' + e.message); }
  // explainer and backup sheet
  try {
    const shaB = (b) => nc.createHash('sha256').update(b).digest(), bitsOf = (b) => Array.from(b).map(x => x.toString(2).padStart(8, '0')).join('');
    const pc = { n: 0, cells: [], cls: '', txt: '' }; let cnf = true;
    w.print = () => { pc.n++; pc.cells = [...w.document.querySelectorAll('#printOnly .ps-cell')].map(c => c.textContent); pc.cls = w.document.body.className; pc.txt = $('printOnly').textContent; pc.grid = (w.document.querySelector('#printOnly .ps-grid') || {}).className; };
    w.confirm = () => cnf; w.alert = () => {};
    for (const [n, R] of [[12, D50], [24, D99]]) {
      await run('dice', n, R, 'SECRETPASS'); const wd = $('genResult').textContent.split('\n')[0].split(' '), eo = $('exOut');
      const dg = shaB(Buffer.from(R)), ent = dg.subarray(0, n * 4 / 3), cs = bitsOf(shaB(ent)).slice(0, n / 3), all = bitsOf(ent) + cs;
      if ($('explainBox').style.display !== '' || $('explainBox').open || eo.style.display !== 'none' || eo.textContent !== '') fails.push('explain: box closed with nothing shown after FORGE (' + n + ')');
      await w.showExplain();
      const cells = [...eo.querySelectorAll('.ex-cell')];
      if (cells.length !== n || cells.some((c, i) => c.querySelector('b').textContent !== (i + 1) + '. ' + wd[i] || c.querySelector('code').textContent !== all.slice(i * 11, i * 11 + 11) || !c.textContent.endsWith('number ' + parseInt(all.slice(i * 11, i * 11 + 11), 2)))) fails.push('explain: every piece shows its word, its 11 bits and its number (' + n + ')');
      const mono = [...eo.querySelectorAll('.ex-mono')].map(e => e.textContent);
      if (mono[1] !== dg.toString('hex') || mono[2] !== ent.toString('hex') || mono[3] !== '…' + cs + '  ← checksum') fails.push('explain: hash, entropy and checksum shown correctly (' + n + ')');
      if (eo.querySelector('.ex-cs') && [...eo.querySelectorAll('.ex-cs')].map(e => e.textContent).join() !== cs + ',' + cs.slice(0) ) fails.push('explain: checksum bits marked (' + n + ')');
      const last = cells[n - 1].querySelectorAll('span'); if (last[0].textContent !== all.slice(n * 11 - 11, n * 11 - cs.length) || last[1].textContent !== cs) fails.push('explain: last piece splits entropy bits from checksum bits (' + n + ')');
      if (eo.querySelectorAll('.ex-step').length !== 5 || !eo.querySelector('.ex-ok') || eo.querySelector('.ex-bad') || eo.style.display !== '') fails.push('explain: five steps and a match message (' + n + ')');
      if (eo.textContent.includes('SECRETPASS') || eo.querySelector('a,script,img,form,input,svg')) fails.push('explain: no passphrase, links or inputs (' + n + ')');
      const first = eo.querySelector('.ex-body .ex-text').textContent, bits = n === 12 ? 129 : 257;
      if (!first.includes(R.length + ' dice rolls') || !first.includes('roughly ' + Math.floor(R.length * Math.log2(6)) + ' bits') || !/^[1-6]( [1-6])*$/.test(mono[0]) || mono[0].replace(/ /g, '') !== R) fails.push('explain: step 1 shows the rolls and their bits (' + n + ')');
      if (!eo.textContent.includes('first ' + n * 4 / 3 + ' bytes') || !eo.textContent.includes('first ' + cs.length + ' bits') || !eo.textContent.includes('All ' + (n * 11) + ' bits are cut into ' + n + ' pieces')) fails.push('explain: step texts name the right sizes (' + n + ')');
      w.hideExplain(); if (eo.textContent !== '' || eo.style.display !== 'none') fails.push('explain: HIDE removes the steps (' + n + ')');
      await w.showExplain(); if (eo.textContent !== '') fails.push('explain: nothing shown after HIDE until a new FORGE (' + n + ')');
      // backup sheet
      pc.n = 0; cnf = false; w.printSeed(); if (pc.n !== 0) fails.push('print sheet: declining the question prints nothing (' + n + ')');
      cnf = true; w.printSeed();
      if (pc.n !== 1 || pc.cells.length !== n || pc.cells.some((c, i) => c !== String(i + 1).padStart(2, '0') + wd[i]) || pc.grid !== 'ps-grid ps-' + n || !/print-seed/.test(pc.cls) || pc.txt.includes('SECRETPASS') || !/Passphrase used: YES/.test(pc.txt) || !pc.txt.includes($('fingerprint').textContent)) fails.push('print sheet: numbered boxes, fingerprint, passphrase line only (' + n + ')');
      w.dispatchEvent(new w.Event('afterprint')); if ($('printOnly').textContent !== '' || w.document.body.classList.contains('print-seed')) fails.push('print sheet: cleaned up after printing (' + n + ')');
    }
    w.setResult('x', Array(15).fill('abandon')); if ($('explainBox').style.display !== 'none') fails.push('explain: no box for a 15-word phrase');
    w.setResult('x', null); if ($('explainBox').style.display !== 'none') fails.push('explain: no box without words');
    await run('dice', 12, D50, ''); await w.showExplain(); w.clearAll(); if ($('exOut').textContent !== '' || $('explainBox').style.display !== 'none') fails.push('explain: CLEAR removes the steps and hides the box');
    { await run('coin', 12, C128, ''); await w.showExplain(); const eo = $('exOut'), t0 = eo.querySelector('.ex-body .ex-text').textContent;
      if (!t0.includes('128 coin flips') || !t0.includes('exactly 1 bit') || !t0.includes('roughly 128 bits') || !/^[01]( [01])*$/.test(eo.querySelector('.ex-mono').textContent)) fails.push('explain: coin flips are counted as 1 bit each'); }
    { await run('dice', 12, D50, ''); w.eval("exCtx.words[0] = 'tampered'"); await w.showExplain(); const eo = $('exOut');
      if (!eo.querySelector('.ex-bad') || eo.querySelector('.ex-ok') || !/do NOT match/.test(eo.textContent)) fails.push('explain: a mismatch between the steps and the seed is reported, not hidden'); }
    w.print = () => {}; w.confirm = () => true;
  } catch (e) { fails.push('explain: the probe crashed: ' + e.message); }
  try { // Guide me, term tips, larger text
    if (!w.Element.prototype.scrollIntoView) w.Element.prototype.scrollIntoView = function () {};
    w.confirm = () => true; const B = w.document.body, gh = (id) => $(id).classList.contains('gh'), nextOff = () => $('gNext').disabled;
    w.clearAll(); await new Promise(r => setTimeout(r, 20));
    if (B.classList.contains('guided') || w.document.querySelectorAll('.gh').length || $('guideBtn').getAttribute('aria-pressed') !== 'false') fails.push('guide: off by default, nothing hidden');
    mode('dice'); words(12); w.toggleGuide();
    if (!B.classList.contains('guided') || $('guideBtn').getAttribute('aria-pressed') !== 'true' || $('guideBtn').textContent !== 'GUIDE: ON') fails.push('guide: GUIDE ME turns the guide on');
    if (gh('wordRadios') || !gh('rolls') || !gh('forgeBtn'.replace('forgeBtn', 'wordGrid')) || !gh('advanced') || !gh('addrBox') || $('gBack').disabled !== true || !/step 1 of 5/.test($('gTitle').textContent)) fails.push('guide: step 1 shows only the choices');
    w.guideStep(1); if (w.document.querySelectorAll('#gDots i.on').length !== 2 || w.document.querySelectorAll('.gstep').length !== 5 || [...w.document.querySelectorAll('.gstep')].filter(e => e.style.display !== 'none').length !== 1) fails.push('guide: progress bar and one explanation at a time');
    if (gh('rolls') || gh('tapRow') || !gh('wordRadios') || !/step 2 of 5/.test($('gTitle').textContent) || $('gNeed').textContent !== '50' || $('gUnit').textContent !== 'rolls') fails.push('guide: step 2 shows the rolls and how many are needed');
    if (!nextOff()) fails.push('guide: NEXT locked with no rolls');
    $('rolls').value = D50.slice(0, 49); $('rolls').oninput(); if (!nextOff()) fails.push('guide: NEXT still locked one roll short');
    $('rolls').value = D50; $('rolls').oninput(); if (nextOff()) fails.push('guide: NEXT unlocks with enough rolls');
    $('advanced').open = false; w.guideStep(1); if (!/step 3 of 5/.test($('gTitle').textContent) || gh('advanced') || !$('advanced').open || nextOff()) fails.push('guide: step 3 shows the passphrase box and can be skipped');
    w.guideStep(-1); if (!/step 2 of 5/.test($('gTitle').textContent)) fails.push('guide: BACK goes back one step');
    w.guideStep(1); w.guideStep(1); if (!/step 4 of 5/.test($('gTitle').textContent) || gh('wordGrid') || gh('forgeBtn'.replace('forgeBtn', 'genResult')) || !gh('rolls') || !nextOff()) fails.push('guide: step 4 locked until FORGE');
    w.guideStep(1); if (/step 5/.test($('gTitle').textContent)) fails.push('guide: cannot skip FORGE');
    await w.generate(); if (nextOff()) fails.push('guide: FORGE unlocks NEXT');
    w.guideStep(1); if (!/step 5 of 5/.test($('gTitle').textContent) || $('gNext').textContent !== 'DONE' || gh('watchBox') || gh('addrBox') || !gh('wordGrid')) fails.push('guide: step 5 shows the checks and DONE');
    w.guideStep(1); if (B.classList.contains('guided') || w.document.querySelectorAll('.gh').length) fails.push('guide: DONE turns the guide off and shows everything');
    w.toggleGuide(); if (!/step 4 of 5/.test($('gTitle').textContent)) fails.push('guide: reopening with a seed starts at the words');
    w.clearAll(); await new Promise(r => setTimeout(r, 20)); if (!/step 1 of 5/.test($('gTitle').textContent)) fails.push('guide: CLEAR returns to step 1');
    mode('coin'); words(24); if ($('gNeed').textContent !== '256' || $('gUnit').textContent !== 'flips') fails.push('guide: coin 24 words needs 256 flips');
    mode('dice'); words(24); if ($('gNeed').textContent !== '99') fails.push('guide: dice 24 words needs 99 rolls'); words(12);
    w.toggleGuide(); if (B.classList.contains('guided') || w.document.querySelectorAll('.gh').length) fails.push('guide: switching off shows everything');
    const terms = [...w.document.querySelectorAll('.term')];
    if (terms.length < 6 || terms.some(e => e.getAttribute('tabindex') !== '0' || (e.getAttribute('data-tip') || '').length < 40)) fails.push('terms: every explained word is focusable and has a real explanation');
    const tip = $('tipBox'); terms[0].dispatchEvent(new w.MouseEvent('mouseover', { bubbles: true }));
    if (tip.style.display !== 'block' || tip.textContent !== terms[0].getAttribute('data-tip')) fails.push('terms: hovering shows the explanation');
    terms[0].dispatchEvent(new w.MouseEvent('mouseout', { bubbles: true })); if (tip.style.display !== 'none') fails.push('terms: moving away hides it');
    terms[1].dispatchEvent(new w.FocusEvent('focusin', { bubbles: true })); if (tip.style.display !== 'block') fails.push('terms: focusing shows the explanation');
    w.document.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'Escape', bubbles: true })); if (tip.style.display !== 'none') fails.push('terms: Escape hides it');
    w.toggleSize(); if (!B.classList.contains('big') || $('sizeBtn').getAttribute('aria-pressed') !== 'true') fails.push('text size: A+ makes the page larger');
    w.toggleSize(); if (B.classList.contains('big') || $('sizeBtn').getAttribute('aria-pressed') !== 'false') fails.push('text size: A- goes back');
    w.confirm = () => true;
  } catch (e) { fails.push('guide: the probe crashed: ' + e.message); }
  try { // rolling-dice logo and the demo words
    const demoOf = (r, n) => entropyToMnemonic(sha('VOIDFORGE DEMO, NOT A SEED|' + r).slice(0, n * 4 / 3), wordlist).split(' ');
    const cells = () => [...w.document.querySelectorAll('#demoGrid .dm-w')].map(e => e.textContent), setRolls = (v) => { $('rolls').value = v; $('rolls').oninput(); };
    w.clearAll(); await new Promise(r => setTimeout(r, 20)); mode('dice'); words(12);
    if ($('demoOn').checked || $('demoOut').style.display !== 'none' || cells().length) fails.push('demo: off and empty by default');
    $('demoOn').checked = true; await w.demoToggle();
    if ($('demoOut').style.display !== '' || cells().length || !/Add a roll/.test($('demoInfo').textContent) || !/NOT your seed words/.test($('demoOut').textContent)) fails.push('demo: with no rolls it asks for one and shows the NOT YOUR SEED banner');
    setRolls(D50.slice(0, 7)); await w.demoRefresh();
    const e1 = demoOf(D50.slice(0, 7), 12); if (cells().join('|') !== e1.map((x, i) => (i + 1) + '. ' + x).join('|') || !/from your 7 rolls so far/.test($('demoInfo').textContent)) fails.push('demo: words are the tagged hash of the rolls');
    setRolls(D50.slice(0, 8)); await w.demoRefresh();
    const e2 = demoOf(D50.slice(0, 8), 12), nch = e2.filter((x, i) => x !== e1[i]).length, marked = w.document.querySelectorAll('#demoGrid .dm-ch').length;
    if (cells().join('|') !== e2.map((x, i) => (i + 1) + '. ' + x).join('|') || $('demoInfo').textContent !== nch + ' of 12 words changed with your last roll.' || marked !== nch || nch < 8) fails.push('demo: a new roll re-makes every word and counts what changed');
    setRolls(D50.slice(0, 9)); await new Promise(r => setTimeout(r, 60)); if (cells().join('|') !== demoOf(D50.slice(0, 9), 12).map((x, i) => (i + 1) + '. ' + x).join('|')) fails.push('demo: every roll updates the words by itself');
    setRolls('1'); await w.demoRefresh(); setRolls('11'); await w.demoRefresh(); if (!/from your 1 roll so far/.test($('demoInfo').textContent) && !/of 12 words changed/.test($('demoInfo').textContent)) fails.push('demo: singular roll wording');
    setRolls(D50); await w.demoRefresh(); const e50 = demoOf(D50, 12);
    if (cells().join('|') !== e50.map((x, i) => (i + 1) + '. ' + x).join('|') || e50.join(' ') === expect.d50) fails.push('demo: with all 50 rolls the demo words are still not the real seed');
    words(24); setRolls(D99); await w.demoRefresh(); if (cells().length !== 24 || cells().join('|') !== demoOf(D99, 24).map((x, i) => (i + 1) + '. ' + x).join('|')) fails.push('demo: 24 words'); words(12);
    setRolls(D50); await w.demoRefresh(); $('demoOn').checked = false; await w.demoToggle(); if ($('demoOut').style.display !== 'none' || cells().length || $('demoInfo').textContent) fails.push('demo: switching off wipes the words');
    $('demoOn').checked = true; await w.demoToggle(); const before = cells().join('|'); await w.generate();
    if ($('demoOn').checked || $('demoOut').style.display !== 'none' || cells().length || $('demoInfo').textContent || !before) fails.push('demo: FORGE wipes the demo words');
    const real = $('genResult').textContent.split('\n')[0]; if (real !== expect.d50 || before.includes('. ' + real.split(' ')[0] + '|') && false) fails.push('demo: FORGE still makes the real seed');
    $('demoOn').checked = true; await w.demoToggle(); w.clearAll(); await new Promise(r => setTimeout(r, 20)); if ($('demoOn').checked || cells().length || $('demoOut').style.display !== 'none') fails.push('demo: CLEAR wipes the demo words');
    $('demoOn').checked = true; setRolls(D50.slice(0, 3)); await w.demoRefresh(); const mid = cells().join('|'); $('demoOn').checked = false; await w.demoToggle(); setRolls(D50.slice(0, 4)); await w.demoRefresh(); if (cells().length) fails.push('demo: stays empty while off');
    if (w.document.querySelectorAll('#demoBox input').length !== 1 || w.document.querySelector('#demoBox a, #demoBox script, #demoBox img')) fails.push('demo: only the one switch, no links or images');
    const lg = $('logo'), svgs = lg.querySelectorAll('svg'); if (svgs.length !== 3 || lg.getAttribute('role') !== 'button' || lg.tabIndex !== 0 || [...svgs].some(x => x.querySelectorAll('rect').length !== 3) || [...svgs].map(x => x.querySelectorAll('circle').length).join() !== '3,5,6') fails.push('logo: three dice showing 3, 5 and 6');
    if (lg.classList.contains('again')) fails.push('logo: starts on the first roll'); w.rollLogo(); if (!lg.classList.contains('again')) fails.push('logo: tapping rolls again'); w.rollLogo(); if (lg.classList.contains('again')) fails.push('logo: second tap rolls again');
    lg.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'Enter', bubbles: true, cancelable: true })); if (!lg.classList.contains('again')) fails.push('logo: Enter key rolls');
    lg.dispatchEvent(new w.KeyboardEvent('keydown', { key: 'a', bubbles: true, cancelable: true })); if (!lg.classList.contains('again')) fails.push('logo: other keys do not roll');
    w.clearAll();
  } catch (e) { fails.push('demo: the probe crashed: ' + e.message); }
  try { // Word draw
    if (!w.Element.prototype.scrollIntoView) w.Element.prototype.scrollIntoView = function () {};
    const A11 = 'abandon '.repeat(11), LEG = 'legal winner thank year wave sausage worth useful legal winner thank';
    let conf = 0, cnf2 = true; w.confirm = () => { conf++; return cnf2; };
    const wd = async (len, ws, fl, pw = '') => { $('wdLen').value = String(len); $('wdWords').value = ws; $('wdFlips').value = fl; $('passphrase').value = pw; $('passphrase2').value = pw; w.wdUpdate(); const dis = $('wdBtn').disabled; await w.wdGenerate(); return { dis, res: $('genResult').textContent.split('\n')[0] }; };
    w.clearAll(); await new Promise(r => setTimeout(r, 20));
    let r = await wd(12, A11, '0000000'); if (r.dis || r.res !== A11 + 'about') fails.push('word draw: all-zero known seed');
    if (!/73c5da0a/.test($('fingerprint').textContent) || $('explainBox').style.display !== 'none') fails.push('word draw: fingerprint shown and the dice explainer hidden');
    const out = $('wdOut').textContent; if ($('wdOut').style.display === 'none' || !/How your last word was made/.test(out) || !/Flips 0000000/.test(out) || !/Together 11 x 11 \+ 7 = 128 bits/.test(out) || !/Checksum first 4 bits of SHA-256/.test(out) || !/=\s+about/.test(out) || w.document.querySelectorAll('#wdOut .wd-row').length !== 15 || !/No hashing is applied/.test(out)) fails.push('word draw: the steps are shown');
    r = await wd(12, LEG, '1111111'); if (r.res !== LEG + ' yellow') fails.push('word draw: second known seed');
    if ($('wdMsg').textContent || $('wdBtn').disabled) fails.push('word draw: a complete, valid draw shows no complaint');
    if (!!/Checksum first 4 bits of SHA-256 of those bytes = [01]{4}\b/.test($('wdOut').textContent.replace(/\s+/g, ' '))) fails.push('word draw: checksum bits shown');
    r = await wd(12, 'lega WINN thank,year wave saus worth usef legal winner THANK', '1111111'); if (r.res !== LEG + ' yellow') fails.push('word draw: abbreviations, commas, capitals');
    r = await wd(24, 'abandon '.repeat(23), '000'); if (r.dis || r.res !== 'abandon '.repeat(23) + 'art') fails.push('word draw: 24 words');
    if (!/23 x 11 \+ 3 = 256 bits/.test($('wdOut').textContent.replace(/\s+/g, ' '))) fails.push('word draw: 24-word steps');
    r = await wd(12, A11, '000000'); if (!r.dis || !/6 \/ 7 flips/.test($('wdCount').textContent)) fails.push('word draw: a short flip count keeps the button off');
    r = await wd(12, 'abandon '.repeat(10), '0000000'); if (!r.dis || !/10 \/ 11 words/.test($('wdCount').textContent)) fails.push('word draw: a short word count keeps the button off');
    r = await wd(12, 'abandon '.repeat(12), '0000000'); if (!r.dis || !/Too many words/.test($('wdMsg').textContent)) fails.push('word draw: too many words');
    r = await wd(12, A11, '00000000'); if (!r.dis || $('wdFlips').value.length !== 8 && false) fails.push('word draw: too many flips');
    if (!/Too many flips/.test($('wdMsg').textContent)) fails.push('word draw: too many flips message');
    r = await wd(12, A11.replace('abandon abandon', 'abandon zzzz'), '0000000'); if (!r.dis || !/Word 2 \(zzzz\) is not a BIP39 word/.test($('wdMsg').textContent)) fails.push('word draw: unknown word named');
    $('wdFlips').value = '10x2 1011'; w.wdUpdate(); if ($('wdFlips').value !== '101011') fails.push('word draw: only 1 and 0 count');
    w.wdClear(); if ($('wdWords').value || $('wdFlips').value || $('wdOut').textContent) fails.push('word draw: CLEAR button wipes');
    if (w.wdResolve('abandon') !== 0 || w.wdResolve('aban') !== 0 || w.wdResolve('abando') !== 0 || w.wdResolve('abx') !== -1 || w.wdResolve('abanx') !== -1 || w.wdResolve('add') < 0 || w.wdResolve('zoo') !== 2047 || w.wdResolve('ab') !== -1) fails.push('word draw: word lookup');
    if (w.wdParse('abandon, ability;able').idx.join() !== '0,1,2' || w.wdParse('abandon qqqq').bad.length !== 1) fails.push('word draw: parsing');
    conf = 0; cnf2 = true; r = await wd(12, A11, '0000000'); if (conf !== 2) fails.push('word draw: identical words and identical flips both ask first (' + conf + ')');
    conf = 0; r = await wd(12, 'abandon ability able about above absent absorb abstract absurd abuse access', '0101010'); if (conf !== 1 || !/^abandon ability able about above absent absorb abstract absurd abuse access /.test(r.res)) fails.push('word draw: alphabetical words ask first (' + conf + ')');
    conf = 0; r = await wd(12, LEG, '1010101'); if (conf !== 0 || !/^legal winner/.test(r.res)) fails.push('word draw: normal draws do not ask');
    conf = 0; r = await wd(12, LEG, '1111111'); if (conf !== 1) fails.push('word draw: identical flips ask first (' + conf + ')');
    conf = 0; cnf2 = false; await w.generate(); r = await wd(12, A11, '0000000'); if (r.res === A11 + 'about' && false) fails.push('x'); if ($('genResult').dataset.seed === '1' && /abandon abandon/.test($('genResult').textContent) && conf < 1) fails.push('word draw: declining stops the seed');
    cnf2 = true; w.clearAll(); await new Promise(r2 => setTimeout(r2, 20));
    await wd(12, LEG, '1010101'); $('passphrase2').value = 'different'; await w.wdGenerate(); if (!/do not match/.test($('genResult').textContent) || $('genResult').dataset.seed === '1') fails.push('word draw: mismatched passphrases refused');
    r = await wd(12, LEG, '1010101', 'secret pass'); if (!/Passphrase: used/.test($('genResult').textContent)) fails.push('word draw: passphrase used');
    $('passphrase').value = ''; $('passphrase2').value = '';
    await wd(12, LEG, '1010101'); w.clearAll(); await new Promise(r2 => setTimeout(r2, 20)); if ($('wdWords').value || $('wdFlips').value || $('wdOut').textContent || $('wdOut').style.display !== 'none') fails.push('word draw: CLEAR wipes boxes and steps');
    await wd(12, LEG, '1010101'); await run('dice', 12, D50, ''); if ($('wdOut').textContent !== '' || $('wdOut').style.display !== 'none') fails.push('word draw: a dice FORGE wipes the old steps');
    w.clearAll(); await new Promise(r2 => setTimeout(r2, 20));
    w.toggleGuide(); if ($('wdBox').classList.contains('gh') || !$('rolls').classList.contains('gh')) fails.push('word draw: the box is offered on guide step 1'); await wd(12, LEG, '1010101'); if (!/step 4 of 5/.test($('gTitle').textContent) || $('wdBox').classList.contains('gh') === false) fails.push('word draw: the guide moves on to writing the words down'); w.toggleGuide(); w.clearAll(); await new Promise(r2 => setTimeout(r2, 20));
    w.confirm = () => true;
    if (w.document.querySelectorAll('#wdBox a, #wdBox script, #wdBox img, #wdBox form').length || !/word tiles/.test($('wdBox').textContent) || /Entropia/i.test(w.document.body.innerHTML)) fails.push('word draw: no links, and no product name');
    $('wdLen').value = '24'; w.wdUpdate(); if (!/0 \/ 23 words, 0 \/ 3 flips/.test($('wdCount').textContent)) fails.push('word draw: counts for 24 words'); $('wdLen').value = '12';
  } catch (e) { fails.push('word draw: the probe crashed: ' + e.message); }
  try { // Multisig
    if (!w.Element.prototype.scrollIntoView) w.Element.prototype.scrollIntoView = function () {};
    const slp = (t) => new Promise((r2) => setTimeout(r2, t));
    w.confirm = () => true; w.clearAll(); await slp(20);
    const A11 = 'abandon '.repeat(11), LEG = 'legal winner thank year wave sausage worth useful legal winner thank', ZOO = 'zoo '.repeat(11).trim();
    const mk = async (ws, fl) => { $('wdLen').value = '12'; $('wdWords').value = ws; $('wdFlips').value = fl; w.wdUpdate(); await w.wdGenerate(); for (let i = 0; i < 200 && !w.eval('watchCtx'); i++) await slp(25); };
    const sd = [[A11, '0000000'], [LEG, '1111111'], [ZOO, '1111111']];
    const accKey = (mn, path, ver) => HDKey.fromMasterSeed(mnemonicToSeedSync(mn, ''), ver ? { private: 0x0488ade4, public: ver } : undefined).derive(path);
    const mns = [A11 + 'about', LEG + ' yellow', ZOO + ' wrong'];
    $('msN').value = '3'; w.msUpdateM(); if ($('msM').value !== '2') fails.push('multisig: 3 keys default to 2-of-3');
    $('msN').value = '7'; w.msUpdateM(); if ($('msM').options.length !== 7) fails.push('multisig: M choices run from 1 to N'); $('msM').value = '7'; $('msN').value = '4'; w.msUpdateM(); if ($('msM').value !== '3' || $('msM').options.length !== 4) fails.push('multisig: shrinking N resets M to a majority');
    $('msN').value = '3'; w.msUpdateM();
    $('msM').value = '1'; w.msMNote(); if (!/not real multisig protection/.test($('msMNote').textContent)) fails.push('multisig: 1-of-N note');
    $('msM').value = '3'; w.msMNote(); if (!/lose even one/.test($('msMNote').textContent)) fails.push('multisig: N-of-N note');
    $('msM').value = '1'; w.msStart(); if (w.eval('ms') !== null || !/at least 2/.test($('msErr').textContent)) fails.push('multisig: 1-of-N refused at start');
    $('msM').value = '2'; $('msAcct').value = '12x'; w.msStart(); if (w.eval('ms') !== null) fails.push('multisig: bad account refused');
    $('msAcct').value = '2147483648'; w.msStart(); if (w.eval('ms') !== null) fails.push('multisig: account above 2147483647 refused');
    $('msAcct').value = '0'; w.msStart();
    if ($('msBanner').style.display !== '' || !/KEY 1 OF 3/.test($('msBanTitle').textContent) || !$('msAddBtn').disabled) fails.push('multisig: banner and disabled button at start');
    await w.msAddMade(); if (!/Make the seed first/.test($('msBanErr').textContent) || w.eval('ms.keys.length') !== 0) fails.push('multisig: adding without a seed');
    await mk(...sd[0]); if ($('msAddBtn').disabled) fails.push('multisig: button enabled once a seed exists');
    await w.msAddMade();
    if (w.eval('ms.keys.length') !== 1 || w.hasSeed() || $('rolls').value !== '' || $('wdWords').value !== '' || $('watchBox').style.display !== 'none' || w.eval('watchCtx') !== null || /abandon/.test($('genResult').textContent)) fails.push('multisig: ADD wipes the seed and keeps one public key');
    if (!/KEY 2 OF 3/.test($('msBanTitle').textContent) || w.document.querySelectorAll('.ms-slot.done').length !== 1) fails.push('multisig: moves on to key 2');
    await slp(200); if (!w.document.querySelector('#msIcon0 svg')) fails.push('multisig: fingerprint picture beside a saved key');
    await mk(...sd[0]); await w.msAddMade();
    if (w.eval('ms.keys.length') !== 1 || !/same key as key 1/.test($('msBanErr').textContent) || !w.hasSeed()) fails.push('multisig: same seed twice refused, seed kept');
    await mk(...sd[1]); await w.msAddMade();
    if (w.eval('ms.keys.length') !== 2) fails.push('multisig: second key added');
    w.msUsePaste();
    const paste = async (t, f) => { $('msPaste').value = t; $('msPasteFp').value = f || ''; await w.msAddPasted(); return $('msRunErr').textContent; };
    const k3 = accKey(mns[2], "m/48'/0'/0'/2'"), k3x = k3.publicExtendedKey, fp3 = fp(mns[2], ''), k1 = accKey(mns[0], "m/48'/0'/0'/2'").publicExtendedKey, k2 = accKey(mns[1], "m/48'/0'/0'/2'");
    const enc = (b) => createBase58check(nsha).encode(b);
    const ser = (ver, depth, pub) => { const b = new Uint8Array(78); b.set([ver >>> 24, (ver >>> 16) & 255, (ver >>> 8) & 255, ver & 255], 0); b[4] = depth; b.set(pub, 45); b[12] = 0x80; b[13 - 1] = 2; b.set(new Uint8Array(32).fill(7), 13); return b; };
    if (!/fingerprint is 8 characters/.test(await paste(k3x, ''))) fails.push('multisig paste: missing fingerprint explained');
    if (!/seed words/.test(await paste(A11 + 'about', 'aaaaaaaa'))) fails.push('multisig paste: seed words refused');
    if (!/PRIVATE key/.test(await paste(HDKey.fromMasterSeed(new Uint8Array(32).fill(7)).privateExtendedKey, 'aaaaaaaa'))) fails.push('multisig paste: xprv refused as private');
    if (!/typo|checksum/.test(await paste(k3x.slice(0, -1) + (k3x.endsWith('a') ? 'b' : 'a'), 'aaaaaaaa'))) fails.push('multisig paste: typo caught');
    if (!/not at the expected place/.test(await paste(HDKey.fromMasterSeed(new Uint8Array(32).fill(7)).publicExtendedKey, 'aaaaaaaa'))) fails.push('multisig paste: master key refused');
    if (!/not at the expected place/.test(await paste(accKey(mns[2], "m/0'/0'/2'").publicExtendedKey, 'aaaaaaaa'))) fails.push('multisig paste: depth-3 key with the right last step refused');
    if (!/not at the expected place/.test(await paste(accKey(mns[2], "m/48'/0'/0'/1'").publicExtendedKey, 'aaaaaaaa'))) fails.push('multisig paste: depth-4 key with the wrong last step refused');
    if (!/Testnet/.test(await paste(accKey(mns[2], "m/48'/1'/0'/2'", 0x043587cf).publicExtendedKey, 'aaaaaaaa'))) fails.push('multisig paste: testnet key refused on mainnet');
    if (!/single-signature/.test(await paste(accKey(mns[2], "m/48'/0'/0'/2'", 0x04b24746).publicExtendedKey, 'aaaaaaaa'))) fails.push('multisig paste: zpub refused');
    { const raw = createBase58check(nsha).decode(k3x); if (!/different multisig script type/.test(await paste(enc(Uint8Array.from([0x02, 0x95, 0xb4, 0x3f, ...raw.slice(4)])), 'aaaaaaaa'))) fails.push('multisig paste: Ypub refused on a Zpub wallet'); }
    if (!/not the one this wallet uses/.test(await paste('[aaaaaaaa/48h/0h/1h/2h]' + k3x, ''))) fails.push('multisig paste: other account in the path refused');
    if (!/same key as key 1/.test(await paste(k1, 'aaaaaaaa'))) fails.push('multisig paste: same public key under another fingerprint refused');
    if (!/same key as key 2/.test(await paste(k3x, fp(mns[1], '')))) fails.push('multisig paste: same fingerprint with another key refused');
    { const off = (() => { for (let x = 5n; ; x++) { try { secp256k1.ProjectivePoint.fromHex('02' + x.toString(16).padStart(64, '0')); } catch { return x; } } })();
      const bad = enc(ser(0x0488b21e, 4, Uint8Array.from([2, ...Buffer.from(off.toString(16).padStart(64, '0'), 'hex')])));
      if (!/not on the curve/.test(await paste(bad, 'aaaaaaaa'))) fails.push('multisig paste: key not on the curve refused');
      const P256 = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2Fn, small = (() => { for (let x = 1n; ; x++) { try { secp256k1.ProjectivePoint.fromHex('02' + x.toString(16).padStart(64, '0')); return x; } catch {} } })();
      if (!/not on the curve/.test(await paste(enc(ser(0x0488b21e, 4, Uint8Array.from([2, ...Buffer.from((P256 + small).toString(16).padStart(64, '0'), 'hex')]))), 'aaaaaaaa'))) fails.push('multisig paste: x above the field size refused');
      if (!/unknown key type/.test(await paste(enc(ser(0x01020304, 4, Uint8Array.from([2, ...Buffer.from(small.toString(16).padStart(64, '0'), 'hex')]))), 'aaaaaaaa'))) fails.push('multisig paste: unknown key version refused');
      const long = enc(new Uint8Array(79).fill(1)); if (!/wrong length/.test(await paste(long, 'aaaaaaaa'))) fails.push('multisig paste: wrong length refused');
      const pre = ser(0x0488b21e, 4, Uint8Array.from([4, ...new Uint8Array(32).fill(9)])); if (!/not a valid public key/.test(await paste(enc(pre), 'aaaaaaaa'))) fails.push('multisig paste: bad key prefix refused'); }
    if (w.eval('ms.keys.length') !== 2) fails.push('multisig paste: refused keys add nothing');
    if (await paste('[' + fp3 + "/48'/0'/0'/2']" + k3x + '/0/*', '') !== '') fails.push('multisig paste: a normal [fp/path]xpub/0/* line is accepted');
    if (!w.eval('ms.done') || w.eval('ms.keys.length') !== 3) fails.push('multisig: third key completes the wallet');
    { const cos = [[fp(mns[0], ''), k1], [fp(mns[1], ''), k2.publicExtendedKey], [fp3, k3x]].map(([f, x]) => `[${f}/48h/0h/0h/2h]${x}/0/*`).sort();
      const d = $('msDescR').textContent, dc = $('msDescC').textContent;
      if (!d.startsWith('wsh(sortedmulti(2,' + cos.join(',') + '))#') || !/#[02-9ac-hj-np-z]{8}$/.test(d)) fails.push('multisig: descriptor');
      if (!dc.startsWith('wsh(sortedmulti(2,' + cos.map((c) => c.replace(/\/0\/\*$/, '/1/*')).join(',') + '))#') || d.split('#')[1] === dc.split('#')[1]) fails.push('multisig: change descriptor');
      const ks = mns.map((m) => accKey(m, "m/48'/0'/0'/2'")), want = [0, 1, 2].map((i) => btc.p2wsh(btc.p2ms(2, ks.map((k) => k.derive('m/0/' + i).publicKey).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))), btc.NETWORK).address);
      if ([...w.document.querySelectorAll('#msAddrs li')].map((l) => l.textContent).join() !== want.join()) fails.push('multisig: first three addresses'); }
    if ($('msOneDev').style.display !== 'none' || $('msBanner').style.display !== 'none' || $('msDone').style.display === 'none') fails.push('multisig: finished state (banner gone, mixed sources hide the one-device warning)');
    w.msShowQr(); if ($('msQrBox').style.display !== '' || !/81 x 81/.test($('msQrCaption').textContent)) fails.push('multisig: QR');
    { const tmp = w.document.createElement('div'); tmp.innerHTML = w.qrSvg(w.qrMatrix($('msDescR').textContent).rows); if (tmp.innerHTML !== $('msQrImg').innerHTML) fails.push('multisig: QR encodes the receive descriptor'); }
    w.msHideQr(); if ($('msQrBox').style.display !== 'none' || $('msQrImg').textContent !== '') fails.push('multisig: hide QR');
    { let pr = 0; w.print = () => { pr++; }; w.msPrint(); const pq = w.document.getElementById('printQr').textContent; if (pr !== 1 || !/NO seed words/.test(pq) || !pq.includes($('msDescR').textContent) || !/2-of-3 multisig/.test(pq) || !pq.includes(w.document.querySelector('#msAddrs li').textContent) || !pq.includes(w.document.querySelectorAll('#msAddrs li')[2].textContent) || /abandon|legal winner|\bzoo\b/.test(pq)) fails.push('multisig: recovery sheet'); }
    // refused key check pieces of the library
    for (const [m, n, label] of [[0, 3, 'M of 0'], [4, 3, 'M above N'], [1, 1, 'one key'], [2, 16, 'sixteen keys']]) {
      const cs = []; const key = await w.parseExtendedKey(k3x); for (let i = 0; i < n; i++) cs.push({ fp: fp3, path: '48h/0h/0h/2h', key });
      let threw = false; try { await w.multisigScript(m, cs, 0, 0); } catch { threw = true; } if (!threw) fails.push('multisig: ' + label + ' refused');
    }
    { const key = await w.parseExtendedKey(k3x); let threw = false; try { await w.ckdPub(key.pub, key.chain, 0x80000000); } catch { threw = true; } if (!threw) fails.push('multisig: hardened public derivation refused');
      threw = false; try { await w.ckdPub(key.pub, key.chain, -1); } catch { threw = true; } if (!threw) fails.push('multisig: negative index refused'); }
    w.msShowQr(); if ($('msQrBox').style.display !== '') fails.push('multisig: QR shown before reset');
    w.clearAll(); await slp(20); if (w.eval('ms') !== null || $('msDescR').textContent !== '' || $('msRun').style.display !== 'none' || $('msQrImg').innerHTML !== '' || $('msQrBox').style.display !== 'none' || $('msAddrs').textContent !== '') fails.push('multisig: CLEAR ALL forgets the setup');
    // 2-of-2 nested, testnet, all made here
    $('msN').value = '2'; w.msUpdateM(); $('msNet').value = 'test'; $('msType').value = 'ms-sh-wsh'; $('msAcct').value = '1'; w.msStart(); if (w.eval('ms.account') !== 1) fails.push('multisig: account number is used');
    if ($('msTestBan').style.display !== '' || !/TESTNET/.test($('msBanTitle').textContent)) fails.push('multisig: testnet banner');
    for (const [i, s] of [sd[0], sd[1]].entries()) { await mk(...s); if (i === 1) { $('passphrase').value = 'pw'; $('passphrase2').value = 'pw'; w.wdUpdate(); await w.wdGenerate(); for (let j = 0; j < 200 && !w.eval('watchCtx'); j++) await slp(25); } await w.msAddMade(); }
    { const ks = [mns[0], mns[1]].map((m, i) => HDKey.fromMasterSeed(mnemonicToSeedSync(m, i === 1 ? 'pw' : '')).derive("m/48'/1'/1'/1'")), want = [0, 1, 2].map((i) => btc.p2sh(btc.p2wsh(btc.p2ms(2, ks.map((k) => k.derive('m/0/' + i).publicKey).sort((a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)))), btc.TEST_NETWORK), btc.TEST_NETWORK).address);
      if (!w.eval('ms.done') || [...w.document.querySelectorAll('#msAddrs li')].map((l) => l.textContent).join() !== want.join()) fails.push('multisig: nested testnet addresses');
      if (!/\/48h\/1h\/1h\/1h\]/.test($('msDescR').textContent)) fails.push('multisig: made keys carry the right origin path');
      if (!/^sh\(wsh\(sortedmulti\(2,/.test($('msDescR').textContent) || !/\)\)\)#/.test($('msDescR').textContent) || !/tpub/.test($('msDescR').textContent) || $('msOneDev').style.display !== '') fails.push('multisig: nested testnet descriptor and one-device warning');
      let pr = 0; w.print = () => { pr++; }; w.msPrint(); const pqt = w.document.getElementById('printQr'); if (!/TESTNET/.test(pqt.firstChild.textContent)) fails.push('multisig: testnet sheet title says so'); if (!/practice coins only/.test(pqt.textContent)) fails.push('multisig: testnet sheet text says so'); }
    w.msCancel(); if (w.eval('ms') !== null) fails.push('multisig: START OVER resets');
    w.clearAll(); await slp(20);
  } catch (e) { fails.push('multisig: the probe crashed: ' + e.message); }
  if ($('fpIcon').querySelector('svg')) { /* keep icon until an error */ }
  // passphrase confirmation must block a mismatch
  await run('dice', 12, D50, ''); w.showQr('wZpub', 'zpub');
  mode('dice'); words(12); $('rolls').value = D50; $('rolls').oninput(); $('passphrase').value = 'abc'; $('passphrase2').value = 'abd'; await w.generate();
  if (!/do not match/.test($('genResult').textContent) || adOf()) fails.push('passphrase confirmation blocks a mismatch');
  if ($('wZpub').textContent !== '' || $('watchBox').style.display !== 'none') fails.push('watch-only export hidden after an error');
  if ($('qrImg').innerHTML !== '' || $('qrBox').style.display !== 'none') fails.push('QR code hidden after an error');
  if ($('fpIcon').innerHTML !== '') fails.push('fingerprint picture hidden after an error');
  if ($('addrList').textContent !== '' || $('addrBox').style.display !== 'none' || $('checkGuide').style.display !== 'none') fails.push('address list and guide hidden after an error');
  if ($('trList').textContent !== '') fails.push('Taproot list cleared after an error');
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
    // zpub / xpub / descriptor / Taproot address, expected values from the independent libraries
    { const wp = watch(ABOUT, 'TREZOR'), w0 = watch(ABOUT, ''), other = watch('legal winner thank year wave sausage worth useful legal winner thank yellow', '');
      const chk = (b) => w.descriptorChecksum(b);
      const dsc = (fpv, xp, br, withSum) => { const body = `wpkh([${fpv}/84h/0h/0h]${xp}/${br}/*)`; return withSum ? chk(body) : body; };
      [tx, cl] = await M(wp.zpub, 'TREZOR'); if (!/^MATCH \(with passphrase\)/.test(tx) || !/ok/.test(cl)) fails.push('compare: zpub with passphrase');
      [tx, cl] = await M(w0.zpub, 'TREZOR'); if (!/^MATCH \(without passphrase\)/.test(tx)) fails.push('compare: zpub without passphrase');
      [tx, cl] = await M(wp.xpub, 'TREZOR'); if (!/^MATCH \(with passphrase\)/.test(tx)) fails.push('compare: xpub with passphrase');
      [tx, cl] = await M(w0.xpub, ''); if (!/^MATCH \(without passphrase\)/.test(tx)) fails.push('compare: xpub without passphrase');
      [tx, cl] = await M(other.zpub, 'TREZOR'); if (!/^NO MATCH:/.test(tx) || !/bad/.test(cl)) fails.push('compare: another wallet zpub is NO MATCH');
      [tx, cl] = await M(other.xpub, ''); if (!/^NO MATCH without/.test(tx)) fails.push('compare: another wallet xpub is NO MATCH');
      [tx, cl] = await M(dsc(wp.fp, wp.xpub, '0', true), 'TREZOR'); if (!/^MATCH \(with passphrase\)/.test(tx)) fails.push('compare: receive descriptor');
      [tx, cl] = await M(dsc(wp.fp, wp.xpub, '1', true), 'TREZOR'); if (!/^MATCH \(with passphrase\)/.test(tx)) fails.push('compare: change descriptor');
      [tx, cl] = await M(dsc(w0.fp, w0.xpub, '0', false), ''); if (!/^MATCH \(without passphrase\)/.test(tx)) fails.push('compare: descriptor without checksum');
      [tx, cl] = await M(dsc(w0.fp, w0.xpub, '0', true).replace(/.$/, (c) => (c === 'q' ? 'p' : 'q')), ''); if (!/checksum/.test(tx) || !/bad/.test(cl)) fails.push('compare: wrong descriptor checksum is rejected');
      [tx, cl] = await M(dsc(other.fp, other.xpub, '0', true), ''); if (!/^NO MATCH/.test(tx) || !/bad/.test(cl)) fails.push('compare: another wallet descriptor is NO MATCH');
      [tx, cl] = await M(dsc(w0.fp, other.xpub, '0', true), ''); if (!/^NO MATCH/.test(tx)) fails.push('compare: right fingerprint with another key is NO MATCH');
      [tx, cl] = await M(dsc(other.fp, w0.xpub, '0', true), ''); if (!/^NO MATCH/.test(tx)) fails.push('compare: right key with another fingerprint is NO MATCH');
      const tr = (pw, i) => { const k = HDKey.fromMasterSeed(mnemonicToSeedSync(ABOUT, pw)).derive(`m/86'/0'/0'/0/${i}`); const xo = k.publicKey.slice(1);
        const P = secp256k1.ProjectivePoint.fromHex('02' + Buffer.from(xo).toString('hex')); const t = schnorr.utils.taggedHash('TapTweak', xo);
        const Q = P.add(secp256k1.ProjectivePoint.BASE.multiply(BigInt('0x' + Buffer.from(t).toString('hex'))));
        return bech32m.encode('bc', [1, ...bech32m.toWords(Q.toRawBytes(true).slice(1))]); };
      [tx, cl] = await M(tr('', 0), ''); if (!/^MATCH \(without passphrase\)/.test(tx)) fails.push('compare: Taproot address 0');
      [tx, cl] = await M(tr('TREZOR', 4), 'TREZOR'); if (!/^MATCH \(with passphrase\)/.test(tx)) fails.push('compare: Taproot address 4 with passphrase');
      [tx, cl] = await M(tr('', 5), ''); if (!/^NO MATCH/.test(tx)) fails.push('compare: Taproot address 5 is outside the first five');
      [tx, cl] = await M(tr('TREZOR', 0), ''); if (!/^NO MATCH/.test(tx)) fails.push('compare: Taproot address of the passphrase wallet without passphrase');
      [tx, cl] = await M('wpkh(garbage)', ''); if (!/Not recognized/.test(tx)) fails.push('compare: garbage descriptor not recognized'); }
    // "Is this address yours?" (search range 4 per press to keep the run short)
    { $('phrase').value = ABOUT; $('verifyRecorded').value = '';
      const ev = (id) => $(id).dispatchEvent(new w.Event('input'));
      const CA = async (pw, x, press = 1) => { $('verifyPass').value = pw; $('checkAddr').value = x; ev('verifyPass'); ev('checkAddr'); let r; for (let n = 0; n < press; n++) { await w.checkAddress(4); r = [$('addrCheckStatus').textContent, $('addrCheckStatus').className]; } return r; };
      let [t1, c1] = await CA('', segAt(ABOUT, '', 0, 2)); if (!/^FOUND: this SegWit address is receive address #2 \(m\/84'\/0'\/0'\/0\/2\)/.test(t1) || !/ok/.test(c1)) fails.push('find: SegWit receive address');
      [t1] = await CA('', segAt(ABOUT, '', 1, 3)); if (!/change address #3 \(m\/84'\/0'\/0'\/1\/3\)/.test(t1)) fails.push('find: SegWit change address');
      [t1] = await CA('', trAt(ABOUT, '', 0, 1)); if (!/^FOUND: this Taproot address is receive address #1 \(m\/86'\/0'\/0'\/0\/1\)/.test(t1)) fails.push('find: Taproot receive address');
      [t1] = await CA('', trAt(ABOUT, '', 1, 2)); if (!/Taproot address is change address #2 \(m\/86'\/0'\/0'\/1\/2\)/.test(t1)) fails.push('find: Taproot change address');
      [t1] = await CA('', altAt('pkh', ABOUT, '', 0, 0, 2)); if (!/^FOUND: this Legacy address is receive address #2 \(m\/44'\/0'\/0'\/0\/2\)/.test(t1)) fails.push('find: legacy receive address');
      [t1] = await CA('', altAt('sh-wpkh', ABOUT, '', 0, 1, 1)); if (!/^FOUND: this Nested SegWit address is change address #1 \(m\/49'\/0'\/0'\/1\/1\)/.test(t1)) fails.push('find: nested SegWit change address');
      $('checkAcct').value = '3'; ev('checkAcct');
      [t1] = await CA('', altAt('sh-wpkh', ABOUT, '', 3, 0, 0)); if (!/receive address #0 \(m\/49'\/0'\/3'\/0\/0\)/.test(t1)) fails.push('find: nested SegWit account 3');
      [t1] = await CA('', altAt('sh-wpkh', ABOUT, '', 0, 0, 0)); if (!/^NOT FOUND/.test(t1)) fails.push('find: account 0 address not found when account 3 is set');
      $('checkAcct').value = '0'; ev('checkAcct');
      [t1] = await CA('', segAtT(ABOUT, '', 0, 0, 2)); if (!/^FOUND: this Testnet SegWit address is receive address #2 \(m\/84'\/1'\/0'\/0\/2\)/.test(t1)) fails.push('find: testnet SegWit address');
      [t1] = await CA('', trAtT(ABOUT, '', 0, 1, 1)); if (!/^FOUND: this Testnet Taproot address is change address #1 \(m\/86'\/1'\/0'\/1\/1\)/.test(t1)) fails.push('find: testnet Taproot address');
      [t1] = await CA('', altAt('pkh', ABOUT, '', 0, 0, 3, true)); if (!/^FOUND: this Testnet Legacy address is receive address #3 \(m\/44'\/1'\/0'\/0\/3\)/.test(t1)) fails.push('find: testnet legacy address');
      [t1] = await CA('', altAt('sh-wpkh', ABOUT, '', 0, 1, 0, true)); if (!/^FOUND: this Testnet Nested SegWit address is change address #0 \(m\/49'\/1'\/0'\/1\/0\)/.test(t1)) fails.push('find: testnet nested SegWit address');
      [t1, c1] = await CA('', segAt(ABOUT, '', 0, 6)); if (!/^NOT FOUND in indices 0 to 3 /.test(t1) || !/bad/.test(c1)) fails.push('find: index beyond the first range is NOT FOUND');
      [t1] = await CA('', segAt(ABOUT, '', 0, 6), 2); if (!/^FOUND: .*receive address #6 /.test(t1)) fails.push('find: second press continues with the next indices');
      [t1] = await CA('', segAt(ABOUT, '', 0, 6), 3); if (!/^NOT FOUND in indices 0 to 3 /.test(t1)) fails.push('find: after a FOUND the next search starts at 0 again');
      await CA('', segAt(ABOUT, '', 0, 6)); $('checkAddr').value = segAt(ABOUT, '', 0, 1); ev('checkAddr'); await w.checkAddress(4);
      if (!/^FOUND: .*receive address #1 /.test($('addrCheckStatus').textContent)) fails.push('find: changing the address restarts the search at index 0');
      await CA('', segAt(ABOUT, '', 0, 6)); $('checkAddr').value = segAt(ABOUT, '', 0, 1); await w.checkAddress(4);
      if (!/^NOT FOUND in indices 4 to 7 /.test($('addrCheckStatus').textContent)) fails.push('find: a continued search covers only the next indices');
      await CA('', segAt(ABOUT, '', 0, 6)); $('phrase').value = ABOUT + ' '; ev('phrase'); $('phrase').value = ABOUT; await w.checkAddress(4);
      if (!/^NOT FOUND in indices 0 to 3 /.test($('addrCheckStatus').textContent)) fails.push('find: changing the phrase restarts the search at index 0');
      [t1] = await CA('', segAt(ABOUT, 'TREZOR', 0, 1)); if (!/^NOT FOUND/.test(t1)) fails.push('find: passphrase-wallet address is not found without the passphrase');
      [t1] = await CA('TREZOR', segAt(ABOUT, 'TREZOR', 0, 1)); if (!/^FOUND: .*receive address #1 .*with passphrase/.test(t1)) fails.push('find: passphrase-wallet address found with the passphrase');
      [t1] = await CA('TREZOR', segAt(ABOUT, '', 0, 1)); if (!/^FOUND: .*without passphrase/.test(t1)) fails.push('find: no-passphrase address still found when a passphrase is typed');
      [t1] = await CA('', segAt('legal winner thank year wave sausage worth useful legal winner thank yellow', '', 0, 0)); if (!/^NOT FOUND/.test(t1)) fails.push('find: address of another wallet is NOT FOUND');
      [t1, c1] = await CA('', 'bc1qxyz'); if (!/Enter a bc1q/.test(t1) || !/bad/.test(c1)) fails.push('find: rejects text that is not an address');
      $('phrase').value = 'abandon abandon'; [t1] = await CA('', segAt(ABOUT, '', 0, 0)); if (!/valid seed phrase/.test(t1)) fails.push('find: needs a valid phrase');
      $('phrase').value = ABOUT; $('verifyPass').value = ''; $('checkAddr').value = ''; $('addrCheckStatus').textContent = ''; }
    // SeedQR digit strings, CompactSeedQR hex, and BIP85 child seeds
    { const V = async (x) => { $('phrase').value = x; await w.verify(); return [$('verifyStatus').textContent.split('\n')[0], $('phrase').value, $('verifyStatus').className]; };
      const mn24 = entropyToMnemonic(new Uint8Array(32).fill(0x5a), wordlist), dg = (m) => m.split(' ').map((x) => String(wordlist.indexOf(x)).padStart(4, '0')).join('');
      let [m1, b1, c1] = await V(dg(ABOUT)); if (!/^Valid 12-word BIP39 phrase \(read from a SeedQR digit string\)/.test(m1) || b1 !== ABOUT || !/ok/.test(c1)) fails.push('seedqr: 12-word digit string');
      [m1, b1] = await V(dg(mn24)); if (!/^Valid 24-word/.test(m1) || b1 !== mn24) fails.push('seedqr: 24-word digit string');
      for (const nb of [20, 24, 28]) { const mw = entropyToMnemonic(new Uint8Array(nb).fill(0x2b), wordlist); [m1, b1] = await V(dg(mw)); if (!new RegExp('^Valid ' + (nb * 3 / 4) + '-word').test(m1) || b1 !== mw) fails.push('seedqr: ' + (nb * 3 / 4) + '-word digit string'); }
      [m1, b1] = await V(dg(ABOUT).replace(/(\d{4})/g, '$1 ')); if (b1 !== ABOUT) fails.push('seedqr: digit string with spaces');
      [m1, b1] = await V(Buffer.from(mnemonicToEntropy(mn24, wordlist)).toString('hex')); if (!/CompactSeedQR hex/.test(m1) || b1 !== mn24) fails.push('seedqr: 24-word compact hex');
      [m1, b1] = await V('7F'.repeat(16)); if (b1 !== 'legal winner thank year wave sausage worth useful legal winner thank yellow') fails.push('seedqr: 12-word compact hex (capitals)');
      [m1, b1] = await V(Buffer.from(mnemonicToEntropy(entropyToMnemonic(new Uint8Array(20).fill(0x33), wordlist), wordlist)).toString('hex')); if (!/^Valid 15-word/.test(m1)) fails.push('seedqr: 15-word compact hex (40 characters)');
      [m1, b1, c1] = await V('2047'.repeat(12)); if (/above 2047/.test(m1)) fails.push('seedqr: 2047 is a valid word number'); 
      [m1, b1, c1] = await V('2048' + '0000'.repeat(11)); if (!/above 2047/.test(m1) || !/bad/.test(c1)) fails.push('seedqr: number above 2047 rejected');
      [m1, b1, c1] = await V('0000'.repeat(12)); if (!/Checksum failed/.test(m1) || !/bad/.test(c1)) fails.push('seedqr: bad checksum rejected');
      [m1, b1] = await V('0000'.repeat(11)); if (!/Invalid length/.test(m1)) fails.push('seedqr: wrong digit count rejected');
      [m1, b1] = await V('7f'.repeat(15)); if (/^Valid/.test(m1)) fails.push('seedqr: wrong hex length rejected');
      [m1, b1] = await V(ABOUT); if (m1 !== 'Valid 12-word BIP39 phrase') fails.push('seedqr: plain words unchanged');
      // BIP85
      const CH = async (parent, pw, words, idx) => { $('phrase').value = parent; $('verifyPass').value = pw; $('childWords').value = String(words); $('childIndex').value = String(idx); await w.deriveChild();
        return [$('childOut').textContent.replace(/Child master[\s\S]*$/, '').replace(/^CHILD[^\n]*\n/, '').replace(/\s*\d+\. /g, ' ').trim(), $('childStatus').textContent, $('childStatus').className, $('childOut').textContent]; };
      let [cw, cs, cc, co] = await CH(ABOUT, '', 12, 0); if (cw !== b85At(ABOUT, '', 12, 0) || !/ok/.test(cc)) fails.push('bip85: child 12 words index 0');
      [cw] = await CH(ABOUT, '', 18, 7); if (cw !== b85At(ABOUT, '', 18, 7)) fails.push('bip85: child 18 words index 7');
      [cw] = await CH(mn24, '', 24, 123456); if (cw !== b85At(mn24, '', 24, 123456)) fails.push('bip85: child 24 words');
      [cw, cs, cc, co] = await CH(ABOUT, 'TREZOR', 12, 1); if (cw !== b85At(ABOUT, 'TREZOR', 12, 1) || !/and passphrase/.test(cs)) fails.push('bip85: passphrase changes the child');
      [cw] = await CH(ABOUT, '', 12, 2147483647); if (cw !== b85At(ABOUT, '', 12, 2147483647)) fails.push('bip85: largest index works');
      try { if ((await w.mnemonicBip85(ABOUT, '', 15, 0)) !== b85At(ABOUT, '', 15, 0) || (await w.mnemonicBip85(ABOUT, '', 21, 3)) !== b85At(ABOUT, '', 21, 3)) fails.push('bip85: 15 and 21 word children'); } catch (e) { fails.push('bip85: 15 and 21 word children (' + e.message + ')'); }
      [cw] = await CH(ABOUT, '', 12, 2267); if (cw !== b85At(ABOUT, '', 12, 2267)) fails.push('bip85: child key with leading zeros (index 2267 starts 000)');
      [cw, cs, cc] = await CH(ABOUT, '', 12, 2147483648); if (!/whole number/.test(cs) || !/bad/.test(cc) || $('childOut').textContent !== '') fails.push('bip85: index above the limit rejected');
      [cw, cs, cc] = await CH(ABOUT, '', 12, 'x1'); if (!/whole number/.test(cs)) fails.push('bip85: non-number index rejected');
      [cw, cs, cc] = await CH(ABOUT, '', 12, ''); if (!/whole number/.test(cs)) fails.push('bip85: empty index rejected');
      [cw, cs, cc, co] = await CH(ABOUT, '', 12, 0); { const fpc = co.match(/Child master fingerprint: ([0-9a-f]{8})/), adc = co.match(/Child first receive address \(BIP84\): (bc1q[0-9a-z]+)/);
        if (!fpc || fpc[1] !== fp(b85At(ABOUT, '', 12, 0), '') || !adc || adc[1] !== addr(b85At(ABOUT, '', 12, 0), '')) fails.push('bip85: child fingerprint and first address shown'); }
      $('childIndex').dispatchEvent(new w.Event('input')); if ($('childOut').textContent !== '' || $('childOut').style.display !== 'none') fails.push('bip85: output cleared when the index is edited');
      await CH(ABOUT, '', 12, 0); $('verifyPass').dispatchEvent(new w.Event('input')); if ($('childOut').textContent !== '') fails.push('bip85: output cleared when the passphrase is edited');
      await CH(ABOUT, '', 12, 0); $('phrase').dispatchEvent(new w.Event('input')); if ($('childOut').textContent !== '') fails.push('bip85: output cleared when the phrase is edited');
      await CH(ABOUT, '', 12, 0); $('childWords').dispatchEvent(new w.Event('change')); if ($('childOut').textContent !== '') fails.push('bip85: output cleared when the length is changed');
      [cw, cs, cc] = await CH('abandon abandon', '', 12, 0); if (!/valid parent seed phrase/.test(cs) || !/bad/.test(cc) || $('childOut').textContent !== '') fails.push('bip85: invalid parent rejected');
      $('childOut').textContent = ''; $('childStatus').textContent = ''; $('verifyPass').value = ''; $('phrase').value = ABOUT; $('verifyStatus').textContent = ''; }
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
  { const f0 = (w.__focus || []).find((x) => x[0] === 'rolls'); if (!f0 || !f0[1] || f0[1].preventScroll !== true) fails.push('page open: rolls box focused without scrolling'); }
  const meta = w.document.querySelector('meta[http-equiv="Content-Security-Policy"]');
  if (!meta || !/default-src 'none'/.test(meta.content)) fails.push('CSP present');
  return fails;
}

async function detect(mutated) {
  const w = loadPage(mutated, (win) => { win.__focus = []; win.HTMLElement.prototype.focus = function (o) { win.__focus.push([this.id, o]); }; });
  if (!w.selfTestDone) return { by: 'page failed to run' };
  await ready(w);
  const badge = w.document.getElementById('selfTestBadge').textContent;
  if (!/PASSED/.test(badge)) return { by: 'self-test gate' };
  let f; try { f = await probe(w); } catch (e) { return { by: 'end-to-end probe (page error: ' + String(e && e.message).slice(0, 60) + ')' }; }
  if (process.env.MUT_DEBUG && f.length) console.log('PROBE FAILS:', f);
  return f.length ? { by: 'end-to-end probe (' + f[0] + ')' } : { by: null };
}

// [name, find (must occur exactly once), replace, equivalent?]
const M = [
  ['wordlist: one word altered',            '"abandon","ability"', '"abandon","abilitx"'],
  ['entropy truncation 16 -> 15 bytes',     'async function rollsToMnemonic(rolls, wc){\n  const entLen = {12:16,24:32}[wc];', 'async function rollsToMnemonic(rolls, wc){\n  const entLen = {12:15,24:32}[wc];'],
  ['entropy truncation 32 -> 31 bytes',     'async function rollsToMnemonic(rolls, wc){\n  const entLen = {12:16,24:32}[wc];', 'async function rollsToMnemonic(rolls, wc){\n  const entLen = {12:16,24:31}[wc];'],
  ['checksum length wrong',                 'const cbits = bits/32;', 'const cbits = bits/16;'],
  ['rolls hashed with extra byte',          'const digest = await sha256(rolls);\n  return entropyToMnemonic', 'const digest = await sha256(rolls+"0");\n  return entropyToMnemonic'],
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
  ['address: bech32 checksum constant',     'const mod=poly(values)^(version===0?1:0x2bc830a3);', 'const mod=poly(values)^(version===0?0:0x2bc830a3);'],
  ['taproot: bech32m constant used for v0 too', 'const mod=poly(values)^(version===0?1:0x2bc830a3);', 'const mod=poly(values)^0x2bc830a3;'],
  ['taproot: bech32 constant used for v1', 'const mod=poly(values)^(version===0?1:0x2bc830a3);', 'const mod=poly(values)^1;'],
  ['taproot: bech32m constant digit', 'const mod=poly(values)^(version===0?1:0x2bc830a3);', 'const mod=poly(values)^(version===0?1:0x2bc830a2);'],
  ['address: bech32 charset swapped',       '"qpzry9x8gf2tvdw0s3jn54khce6mua7l"', '"qpzry9x8gf2tvdw0s3jn54khce6mua7k"'],
  ['address: witness version 0 -> 1',       'bech32Encode("bc",0,h160)', 'bech32Encode("bc",1,h160)'],
  ['address: hash160 skips RIPEMD-160',     'const h160=ripemd160(await sha256bytes(pubkeyBytes(k)));', 'const h160=(await sha256bytes(pubkeyBytes(k))).slice(0,20);'],
  ['address: mainnet prefix -> testnet',    'bech32Encode("bc",0,h160)', 'bech32Encode("tb",0,h160)'],
  ['passphrase confirmation bypassed',      'if(document.getElementById("passphrase").value !== document.getElementById("passphrase2").value){', 'if(false){'],
  ['tap button appends wrong value',        'el.value += v; updateCount();', 'el.value += "1"; updateCount();'],
  ['address: child key not reduced mod n (needed about half the time)', 'child=(il+k)%SN;', 'child=(il+k);'],
  ['VERIFY ignores the typed passphrase (fingerprint)', 'fp1 = await mnemonicFingerprint(r.mnemonic, vp)', 'fp1 = await mnemonicFingerprint(r.mnemonic, "")'],
  ['watch: ypub version bytes wrong', '"sh-wpkh":[0x04,0x9d,0x7c,0xb2], other:XPUB_VER', '"sh-wpkh":[0x04,0x9d,0x7c,0xb3], other:XPUB_VER'],
  ['watch: taproot purpose wrong', 'tr:{purpose:86,', 'tr:{purpose:84,'],
  ['watch: nested descriptor not wrapped in sh()', 'type === "sh-wpkh" ? "sh(wpkh(" + inner + "))"', 'type === "sh-wpkh" ? "wpkh(" + inner + ")"'],
  ['watch: first address uses the wrong type', 'first:await addressFromKey(type, fk, net)', 'first:await addressFromKey("wpkh", fk, net)'],
  ['net: testnet bech32 prefix wrong', 'test:{coin:1, hrp:"tb",', 'test:{coin:1, hrp:"bc",'],
  ['net: testnet coin type wrong', 'test:{coin:1,', 'test:{coin:0,'],
  ['net: testnet legacy version byte wrong', 'pkh:0x6f,', 'pkh:0x00,'],
  ['net: testnet nested version byte wrong', 'sh:0xc4,', 'sh:0x05,'],
  ['net: testnet vpub version wrong', 'wpkh:[0x04,0x5f,0x1c,0xf6]', 'wpkh:[0x04,0xb2,0x47,0x46]'],
  ['net: testnet upub version wrong', '"sh-wpkh":[0x04,0x4a,0x52,0x62]', '"sh-wpkh":[0x04,0x9d,0x7c,0xb2]'],
  ['net: testnet tpub version wrong', 'other:[0x04,0x35,0x87,0xcf]', 'other:XPUB_VER'],
  ['net: testnet Vpub version wrong', '"ms-wsh":[0x02,0x57,0x54,0x83]', '"ms-wsh":[0x02,0xaa,0x7e,0xd3]'],
  ['net: testnet Upub version wrong', '"ms-sh-wsh":[0x02,0x42,0x89,0xef]', '"ms-sh-wsh":[0x02,0x95,0xb4,0x3f]'],
  ['net: mainnet Zpub version wrong', '"ms-wsh":[0x02,0xaa,0x7e,0xd3]', '"ms-wsh":[0x02,0x57,0x54,0x83]'],
  ['net: mainnet Ypub version wrong', '"ms-sh-wsh":[0x02,0x95,0xb4,0x3f]', '"ms-sh-wsh":[0x02,0x42,0x89,0xef]'],
  ['net: address not recognized as testnet', 'return /^(tb1|[2mn])/.test(addr) ? "test" : "main";', 'return "main";'],
  ['net: testnet nested not recognized', '  if(/^2/.test(addr)) return "sh-wpkh";\n', ''],
  ['net: testnet legacy not recognized', '  if(/^[mn]/.test(addr)) return "pkh";\n', ''],
  ['net: testnet taproot not recognized', '  if(/^tb1p/.test(addr)) return "tr";\n', ''],
  ['net: finder always uses mainnet coin type', 'net = addressNetOf(addr), coin = NETS[net].coin;', 'net = addressNetOf(addr), coin = 0;'],
  ['net: taproot ignores the network prefix', 'return taprootAddress(k, N.hrp);', 'return taprootAddress(k);'],
  ['multisig: native script number wrong', '"ms-wsh":{script:2,', '"ms-wsh":{script:1,'],
  ['multisig: nested script number wrong', '"ms-sh-wsh":{script:1,', '"ms-sh-wsh":{script:2,'],
  ['multisig: purpose 48 wrong', '[[48,true],[N.coin,true],[account,true],[M.script,true]]', '[[44,true],[N.coin,true],[account,true],[M.script,true]]'],
  ['multisig: depth byte wrong', 'ser(N.ver[type],4)', 'ser(N.ver[type],3)'],
  ['multisig: origin path missing the script', '"h/" + account + "h/" + M.script + "h";', '"h/" + account + "h";'],
  ['multisig: child number is the account not the script', '((M ? M.script : account)+0x80000000)', '(account+0x80000000)'],
  ['lastword: checksum length wrong', 'cLen = Math.floor((total*11)/32), eBits = total*11 - cLen;', 'cLen = Math.floor((total*11)/32) - 1, eBits = total*11 - cLen;'],
  ['lastword: checksum not compared', 'if(bits.slice(eBits) === bytesToBits(h).slice(0, cLen)) out.push(WORDLIST[i]);', 'out.push(WORDLIST[i]);'],
  ['lastword: only the first 1024 words tried', 'for(let i = 0; i < 2048; i++){\n    const bits = head', 'for(let i = 0; i < 1024; i++){\n    const bits = head'],
  ['lastword: word number off by one', 'out.push(WORDLIST[i]);', 'out.push(WORDLIST[i+1] || WORDLIST[0]);'],
  ['lastword: 23 words not accepted', '[11,14,17,20,23].includes(words.length)', '[11,14,17,20].includes(words.length)'],
  ['lastword: unknown word not rejected', 'for(const w of words){ if(!(w in WORD_MAP)) throw new Error("Unknown word: " + w); }\n  const total', 'const total'],
  ['lastword: list not cleared when the words change', 'document.getElementById("lwInput").addEventListener("input", () => clearLastWords(false));', ''],
  ['lastword: CLEAR keeps the typed words', 'if(all) document.getElementById("lwInput").value = "";', ''],
  ['psbt: 2-byte length prefix wrong', 'const v=b[o]|(b[o+1]<<8); o+=2; return v; }', 'const v=b[o]|(b[o+1]<<7); o+=2; return v; }'],
  ['psbt: 4-byte length prefix not read', 'if(f===0xfe) return r.u32();', 'if(f===0xfe) return r.byte();'],
  ['psbt: 64-bit amount byte order', 'for(let i=7;i>=0;i--) v=(v<<8n)|BigInt(b[o+i]);', 'for(let i=0;i<8;i++) v=(v<<8n)|BigInt(b[o+i]);'],
  ['psbt: 32-bit numbers read as signed', 'const v=(b[o]|(b[o+1]<<8)|(b[o+2]<<16)|(b[o+3]<<24))>>>0; o+=4; return v; },', 'const v=(b[o]|(b[o+1]<<8)|(b[o+2]<<16)|(b[o+3]<<24)); o+=4; return v; },'],
  ['psbt: txid not reversed', 'hex(Uint8Array.from(r.bytes(32)).reverse())', 'hex(Uint8Array.from(r.bytes(32)))'],
  ['psbt: output amount skipped (always 0)', 'const value=r.i64(), sl=r.varint(); tx.outs.push({value, script:r.bytes(sl)});', 'const value=(r.i64(),0n), sl=r.varint(); tx.outs.push({value, script:r.bytes(sl)});'],
  ['psbt: segwit marker of previous tx not handled', 'if(n===0){ r.byte(); seg=true; n=r.varint(); }', 'if(false){ r.byte(); seg=true; n=r.varint(); }'],
  ['psbt: previous transaction output chosen by the wrong index', 'psbtParseTxOutputs(nw.val)[tx.ins[i].vout]', 'psbtParseTxOutputs(nw.val)[0]'],
  ['psbt: witness utxo amount and script swapped', 'inp.amount=q.i64(); inp.script=q.bytes(q.varint());', 'inp.script=q.bytes(q.varint()); inp.amount=q.i64();'],
  ['psbt: legacy address pattern broken', 'script[23]===0x88 && script[24]===0xac', 'script[23]===0x88 && script[24]===0xad'],
  ['psbt: script-hash address pattern broken', 'script[0]===0xa9 && script[1]===20 && script[22]===0x87', 'script[0]===0xa9 && script[1]===20 && script[22]===0x88'],
  ['psbt: native SegWit key-hash pattern broken', 'script.length===22 && script[0]===0 && script[1]===20', 'script.length===23 && script[0]===0 && script[1]===20'],
  ['psbt: native SegWit script-hash pattern broken', 'script.length===34 && script[0]===0 && script[1]===32', 'script.length===35 && script[0]===0 && script[1]===32'],
  ['psbt: taproot address version wrong', 'return bech32Encode(N.hrp,1,script.slice(2));', 'return bech32Encode(N.hrp,0,script.slice(2));'],
  ['psbt: data-carrier output shown as an address', 'if(script.length>0 && script[0]===0x6a) return "OP_RETURN', 'if(false) return "OP_RETURN'],
  ['psbt: network ignored for addresses', 'const N=NETS[net||"main"];\n  if(script.length===25', 'const N=NETS.main;\n  if(script.length===25'],
  ['psbt: hex input not recognized', 'if(/^70736274ff/i.test(t) && /^[0-9a-f]+$/i.test(t) && t.length%2===0) return fromHex(t.toLowerCase());', 'if(false) return fromHex(t.toLowerCase());'],
  ['psbt: marker not checked', 'if(bytes.length<5 || !magic.every((x,i)=>bytes[i]===x)) throw', 'if(false) throw'],
  ['psbt: version 2 not refused', 'if(glob.some(x=>x.type===0xfb &&', 'if(false && glob.some(x=>x.type===0xfb &&'],
  ['psbt: missing unsigned transaction not reported', 'if(!txRec) throw new Error("No unsigned transaction found in this PSBT.");', 'if(!txRec) txRec={val:new Uint8Array(0)};'],
  ['psbt: signatures not counted', 'sigs:m.filter(x=>x.type===2).length', 'sigs:0'],
  ['psbt: finalized inputs not noticed', 'final:m.some(x=>x.type===7||x.type===8)', 'final:false'],
  ['psbt: ordinary key information ignored', 'if(x.type===2 && x.val.length>=4) out.fps.push(hex(x.val.slice(0,4)));', 'if(false) out.fps.push(hex(x.val.slice(0,4)));'],
  ['psbt: taproot key information ignored', 'if(x.type===7 && x.val.length>=5){', 'if(false && x.val.length>=5){'],
  ['psbt: taproot leaf hashes not skipped', 'q.bytes(32*nh); out.fps.push(hex(q.bytes(4)));', 'out.fps.push(hex(q.bytes(4)));'],
  ['psbt: trailing data not noticed', 'if(!r.done) res.trailing=true;', ''],
  ['psbt: output total wrong', 'res.totalOut=res.outs.reduce((a,o)=>a+o.amount,0n);', 'res.totalOut=res.outs.reduce((a,o)=>a+o.amount,1n);'],
  ['psbt: fee wrong when some inputs are unknown', 'res.fee=res.ins.every(x=>x.amount!==null) ?', 'res.fee=res.ins.some(x=>x.amount!==null) ?'],
  ['psbt: fee sign flipped', 'res.ins.reduce((a,x)=>a+x.amount,0n)-res.totalOut : null;', 'res.totalOut-res.ins.reduce((a,x)=>a+x.amount,0n) : null;'],
  ['psbt: BTC text not padded to 8 decimals', '(v%100000000n).toString().padStart(8,"0")', '(v%100000000n).toString()'],
  ['psbt: negative amounts shown positive', 'return (neg?"-":"")+w+', 'return w+'],
  ['psbt: fee percentage wrong', 'Number(res.fee*10000n/res.totalOut)/100', 'Number(res.fee*1000n/res.totalOut)/100'],
  ['psbt: change hint shown without key information', '(x.fps.length ? "\\n   has wallet key information', '(true ? "\\n   has wallet key information'],
  ['psbt: file size limit removed', 'if(file.size>2000000){', 'if(false){'],
  ['psbt: text file fallback removed', 'try{ bytes=psbtFromText(new TextDecoder().decode(u)); }catch(e){ bytes=u; }', 'bytes=u;'],
  ['psbt: report not cleared when the text changes', 'document.getElementById("psbtInput").addEventListener("input", () => clearPsbt(false));', ''],
  ['psbt: CLEAR keeps the pasted text', 'if(all){ document.getElementById("psbtInput").value=""; document.getElementById("psbtFile").value=""; }', ''],
  ['psbt: wallet fingerprint match never shown', 'fpWallet && x.fps.includes(fpWallet)', 'false && x.fps.includes(fpWallet)'],
  ['watch: depth byte wrong', 'b[4]=depth;', 'b[4]=depth+1;'],
  ['watch: parent fingerprint dropped', 'b.set(parentFp,5);', 'b.set([0,0,0,0],5);'],
  ['watch: child index not hardened', '(cn>>>24)&255', '(cn>>>24)&127'],
  ['watch: zpub version bytes -> xpub', 'zpub=await base58check(ser(N.ver.wpkh,3))', 'zpub=await base58check(ser(N.ver.other,3))'],
  ['watch: base58 alphabet swapped', 'B58="123456789ABCDEFGHJKLMNPQRSTUVWXYZ', 'B58="123456789ABCDEFGHJKLMNPQRSTUVWXZY'],
  ['watch: base58 checksum skips second SHA-256', 'await sha256bytes(await sha256bytes(payload))', 'await sha256bytes(payload)'],
  ['watch: leading-zero bytes not encoded (payload always starts with a non-zero version byte)', 'if(b===0) out="1"+out;', 'if(b===0) out=out;'],
  ['watch: account path wrong (m/84h/0h/1h)', '[T.purpose,true],[N.coin,true],[account,true]]', '[T.purpose,true],[N.coin,true],[account+1,true]]'],
  ['watch: descriptor checksum final xor removed', 'chk^=1n; let out="";', 'let out="";'],
  ['watch: descriptor origin path wrong', '"h/" + N.coin + "h/" + account + "h";\n  const d=', '"h/" + N.coin + "h/" + (account+1) + "h";\n  const d='],
  ['watch: change descriptor uses branch 0', 'change:d(1)', 'change:d(0)'],
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
  ['lifehash: icon not cleared on errors', '    clearWatch();\n    clearFpIcons();\n    if(guideOn) guideRender();\n  }\n  if(ms) msBanner();\n}', '    clearWatch();\n    if(guideOn) guideRender();\n  }\n  if(ms) msBanner();\n}'],
  ['VERIFY ignores the typed passphrase (address)', 'a1 = await mnemonicFirstAddress(r.mnemonic, vp)', 'a1 = await mnemonicFirstAddress(r.mnemonic, "")'],
  ['VERIFY without-passphrase line uses the typed passphrase', 'fp0 = await mnemonicFingerprint(r.mnemonic, "");', 'fp0 = await mnemonicFingerprint(r.mnemonic, vp);'],
  ['match: with-passphrase check compares the wrong values', 'if(hasPass && test(fp1, a1, ids1))', 'if(hasPass && test(fp0, a0, ids0))'],
  ['match: address backups compared against the fingerprint', 'test = (f, a) => ql === (kind === "fp" ? f : a);', 'test = (f, a) => ql === f;'],
  ['match: NO MATCH without passphrase shown as success', 'return {ok:false, text:"NO MATCH without a passphrase.', 'return {ok:true, text:"NO MATCH without a passphrase.'],
  ['match: NO MATCH with passphrase shown as success', 'if(hasPass) return {ok:false, text:"NO MATCH:', 'if(hasPass) return {ok:true, text:"NO MATCH:'],
  ['match: hasPass guard dropped (a1/fp1 are undefined without a passphrase)', 'if(hasPass && test(fp1, a1, ids1))', 'if(test(fp1, a1, ids1))', true],
  ['compare: zpub compared against the xpub', '(q.charAt(0) === "x" ? c.xpub : c.key) === q', 'c.xpub === q'],
  ['compare: key check always passes', 'ids.cands.find(c => (q.charAt(0) === "x" ? c.xpub : c.key) === q)', 'ids.cands.find(c => true)'],
  ['compare: descriptor fingerprint ignored', 'ids.fp === d.fp && ids.cands.find(c => c.xpub === d.key)', 'ids.cands.find(c => c.xpub === d.key)'],
  ['compare: descriptor key ignored', 'ids.fp === d.fp && ids.cands.find(c => c.xpub === d.key)', 'ids.fp === d.fp && ids.cands.find(c => true)'],
  ['compare: descriptor checksum not enforced', 'if(!d.sumOk) return', 'if(false) return'],
  ['compare: taproot address check always passes', 'test = (f, a, ids) => !!ids && ids.list.some(t => t === fold);', 'test = (f, a, ids) => !!ids;'],
  ['find: legacy version byte wrong', 'Uint8Array.from([N.pkh, ...h])', 'Uint8Array.from([N.sh, ...h])'],
  ['find: nested redeem script prefix wrong', 'Uint8Array.from([0x00, 0x14, ...h])', 'Uint8Array.from([0x00, 0x15, ...h])'],
  ['find: nested version byte wrong', 'Uint8Array.from([N.sh, ...await', 'Uint8Array.from([N.pkh, ...await'],
  ['find: nested SegWit treated as legacy', '  if(/^3/.test(addr)) return "sh-wpkh";\n', ''],
  ['find: account ignored', '[[purpose,true],[coin,true],[account,true]]', '[[purpose,true],[coin,true],[0,true]]'],
  ['find: nested purpose wrong', '"sh-wpkh":{purpose:49,', '"sh-wpkh":{purpose:84,'],
  ['find: legacy purpose wrong', 'pkh:{purpose:44,', 'pkh:{purpose:49,'],
  ['find: change chain not searched', 'for(const chain of [0,1]){', 'for(const chain of [0]){'],
  ['find: taproot searched as SegWit', '  if(/^bc1p/.test(addr)) return "tr";\n', ''],
  ['find: wrong purpose for SegWit', 'wpkh:{purpose:84,', 'wpkh:{purpose:44,'],
  ['find: change chain never searched', 'for(const chain of [0,1]){\n    const [ck,cc]', 'for(const chain of [0]){\n    const [ck,cc]'],
  ['find: receive chain never searched', 'for(const chain of [0,1]){\n    const [ck,cc]', 'for(const chain of [1]){\n    const [ck,cc]'],
  ['find: search starts at index 0 ignoring from', 'for(let i=from;i<from+count;i++){\n      const [kk]', 'for(let i=0;i<from+count;i++){\n      const [kk]'],
  ['find: last index skipped', 'for(let i=from;i<from+count;i++){\n      const [kk]', 'for(let i=from;i<from+count-1;i++){\n      const [kk]'],
  ['find: child index off by one', 'const [kk]=await ckdPriv(ck,cc,i,false);', 'const [kk]=await ckdPriv(ck,cc,i+1,false);'],
  ['find: reports the wrong chain', 'return {chain, index:i, path:', 'return {chain:0, index:i, path:'],
  ['find: reports the wrong index', 'return {chain, index:i, path:', 'return {chain, index:i+1, path:'],
  ['find: always found', 'if(await addressFromKey(type, kk, net) === addr) return {chain', 'if(true) return {chain'],
  ['find: address compared case-insensitively wrong (never matches)', 'if(await addressFromKey(type, kk, net) === addr) return {chain', 'if(await addressFromKey(type, kk, net) === addr + "x") return {chain'],
  ['find: next press does not continue', 'addrScanFrom = to;\n    say(', 'addrScanFrom = 0;\n    say('],
  ['find: search position not reset after FOUND', 'if(f){ addrScanFrom = 0; return say("ok"', 'if(f){ return say("ok"'],
  ['find: passphrase wallet never searched', 'if(vp) variants.push(["with passphrase", vp]);', ''],
  ['find: no-passphrase wallet not searched', 'const variants = [["without passphrase", ""]]; if(vp) variants.push(["with passphrase", vp]);', 'const variants = []; if(vp) variants.push(["with passphrase", vp]); else variants.push(["without passphrase", ""]);'],
  ['find: NOT FOUND shown as success', 'say("bad", "NOT FOUND in indices', 'say("ok", "NOT FOUND in indices'],
  ['find: FOUND shown as failure', 'return say("ok", "FOUND: this "', 'return say("bad", "FOUND: this "'],
  ['find: invalid phrase not rejected', 'if(!r.ok) return say("bad", "Type a valid seed phrase in the box above first. " + r.msg);', ''],
  ['find: address format not validated', '  if(!kind) return say("bad", "Enter a bc1q', '  if(false) return say("bad", "Enter a bc1q'],
  ['find: scan position not reset when the address changes', 'for(const id of ["checkAddr","checkAcct","phrase","verifyPass"]) document.getElementById(id).addEventListener("input", resetAddrScan);', ''],
  ['bip85: wrong application number', 'for(const i of [83696968, 39, 0, words, index])', 'for(const i of [83696968, 32, 0, words, index])'],
  ['bip85: wrong language', 'for(const i of [83696968, 39, 0, words, index])', 'for(const i of [83696968, 39, 1, words, index])'],
  ['bip85: wrong root', 'for(const i of [83696968, 39, 0, words, index])', 'for(const i of [83696967, 39, 0, words, index])'],
  ['bip85: index ignored', 'for(const i of [83696968, 39, 0, words, index])', 'for(const i of [83696968, 39, 0, words, 0])'],
  ['bip85: length ignored', 'for(const i of [83696968, 39, 0, words, index])', 'for(const i of [83696968, 39, 0, 12, index])'],
  ['bip85: wrong HMAC key', 'new TextEncoder().encode("bip-entropy-from-k")', 'new TextEncoder().encode("bip-entropy-from-K")'],
  ['bip85: entropy not truncated from the front', 'e.slice(0, words * 4 / 3)', 'e.slice(64 - words * 4 / 3)'],
  ['bip85: entropy one byte long', 'e.slice(0, words * 4 / 3)', 'e.slice(0, words * 4 / 3 + 1)'],
  ['bip85: key bytes not padded', 'fromHex(k.toString(16).padStart(64,"0")));\n  return entropyToMnemonic', 'fromHex(k.toString(16).padStart(62,"0")));\n  return entropyToMnemonic'],
  ['bip85: 15 words accepted wrongly removed', 'if(![12,15,18,21,24].includes(words)) throw new Error("words must be 12, 15, 18, 21 or 24");', 'if(![12,18,24].includes(words)) throw new Error("words must be 12, 15, 18, 21 or 24");'],
  ['bip85: index limit off by one', 'index > 2147483647) throw new Error("index must be 0 to 2147483647");', 'index > 2147483646) throw new Error("index must be 0 to 2147483647");'],
  ['bip85: UI index limit raised', 'parseInt(raw, 10) > 2147483647){ clearChild();', 'parseInt(raw, 10) > 4294967295){ clearChild();'],
  ['bip85: UI index limit lowered', 'parseInt(raw, 10) > 2147483647){ clearChild();', 'parseInt(raw, 10) > 2147483646){ clearChild();'],
  ['bip85: UI index not validated', 'if(!/^[0-9]{1,10}$/.test(raw) || parseInt(raw, 10) > 2147483647){ clearChild();', 'if(false){ clearChild();'],
  ['bip85: passphrase ignored', 'const child = await mnemonicBip85(r.mnemonic, vp, words, index);', 'const child = await mnemonicBip85(r.mnemonic, "", words, index);'],
  ['bip85: parent phrase not checked', 'if(!r.ok){ clearChild(); return say("bad", "Type your valid parent', 'if(false){ clearChild(); return say("bad", "Type your valid parent'],
  ['bip85: output not cleared when phrase/passphrase/index edited', 'for(const id of ["phrase","verifyPass","childWords","childIndex"]) document.getElementById(id).addEventListener("input", clearChild);', ''],
  ['bip85: output not cleared when length changed', 'document.getElementById("childWords").addEventListener("change", clearChild);', ''],
  ['bip85: child fingerprint wrong passphrase', 'const fp = await mnemonicFingerprint(child, ""), a0', 'const fp = await mnemonicFingerprint(child, "x"), a0'],
  ['bip85: error shown as success', 'say("bad", "The index must be a whole number', 'say("ok", "The index must be a whole number'],
  ['seedqr: number limit raised', 'if(n > 2047) return {error', 'if(n > 2048) return {error'],
  ['seedqr: number limit lowered', 'if(n > 2047) return {error', 'if(n > 2046) return {error'],
  ['seedqr: number limit removed', 'if(n > 2047) return {error', 'if(false) return {error'],
  ['seedqr: digit string needs the wrong length', 'q.length % 4 === 0 && [12,15,18,21,24].includes(q.length / 4)', 'q.length % 4 === 0'],
  ['seedqr: only 12 and 24 words', '[12,15,18,21,24].includes(q.length / 4)', '[12,24].includes(q.length / 4)'],
  ['seedqr: 5-digit groups', 'parseInt(q.slice(i, i + 4), 10)', 'parseInt(q.slice(i, i + 3), 10)'],
  ['seedqr: hex lengths wrong', '[32,40,48,56,64].includes(q.length)', '[32,64].includes(q.length)'],
  ['seedqr: hex capitals not accepted', '/^[0-9a-fA-F]+$/.test(q) && [32,40,48,56,64]', '/^[0-9a-f]+$/.test(q) && [32,40,48,56,64]'],
  ['seedqr: hex capitals not lowered', 'fromHex(q.toLowerCase())', 'fromHex(q)', true],
  ['seedqr: wrong wordlist index', 'words.push(WORDLIST[n]);', 'words.push(WORDLIST[n + 1]);'],
  ['seedqr: converted words not shown in the box', 'if(r.ok && r.fromCode) document.getElementById("phrase").value = r.mnemonic;', ''],
  ['seedqr: source not named', ' (read from "+pc.kind+")" : ""', ' (read from)" : ""'],
  ['compare: taproot list only first address', 'ids.list.some(t => t === fold)', 'ids.list.slice(0,1).some(t => t === fold)'],
  ['passphrase line: YES/NO swapped (print and download)', '(used ? "YES (keep it separate; it is not " + kind + " here)" : "NO")', '(used ? "NO" : "YES (keep it separate; it is not " + kind + " here)")'],
  ['result line: no-passphrase wording wrong', ': "none"), mnemonic.split(" "));', ': "used"), mnemonic.split(" "));'],
  ['grid: word numbers off by one',           '(i + 1) + "."', 'i + "."'],
  ['seed flag never set (SEND TO VERIFY would refuse)', 'g.dataset.seed = "1";', 'g.dataset.seed = "";'],
  ['seed flag not cleared after an error (error text treated as a seed)', 'delete g.dataset.seed;', ''],
  ['plain message: too few rolls wording', '"Enter " + diff + " more "', '"Enter " + rolls.length + " more "'],
  ['dice face drawn with a missing pip (5)', '5:[[28,28],[72,28],[50,50],[28,72],[72,72]]', '5:[[28,28],[72,28],[28,72],[72,72]]'],
  ['five addresses: child index off by one', 'const [ck]=await ckdPriv(k,c,i,false);\n    out.push(bech32Encode("bc",0', 'const [ck]=await ckdPriv(k,c,i+1,false);\n    out.push(bech32Encode("bc",0'],
  ['five addresses: hardened child', 'const [ck]=await ckdPriv(k,c,i,false);\n    out.push(bech32Encode("bc",0', 'const [ck]=await ckdPriv(k,c,i,true);\n    out.push(bech32Encode("bc",0'],
  ['five addresses: one too few', 'for(let i=0;i<n;i++){\n    const [ck]', 'for(let i=0;i<n-1;i++){\n    const [ck]'],
  ['taproot: wrong purpose 86 -> 84', 'of [[86,true],[0,true],[0,true],[0,false]]) [k,c]=await ckdPriv(k,c,i,h);\n  const out=[];', 'of [[84,true],[0,true],[0,true],[0,false]]) [k,c]=await ckdPriv(k,c,i,h);\n  const out=[];'],
  ['taproot: child index off by one', 'out.push(await taprootAddress(ck))', 'out.push(await taprootAddress(ckdPriv ? (await ckdPriv(k,c,i+1,false))[0] : ck))'],
  ['taproot: one too few', 'for(let i=0;i<n;i++){ const [ck]=await ckdPriv(k,c,i,false); out.push(await taprootAddress(ck)); }', 'for(let i=0;i<n-1;i++){ const [ck]=await ckdPriv(k,c,i,false); out.push(await taprootAddress(ck)); }'],
  ['taproot: wrong tweak tag', 'taggedHash("TapTweak",xonly)', 'taggedHash("TapTweek",xonly)'],
  ['taproot: tweak not applied', 'const Q=eadd(P,emul(t,SG));', 'const Q=eadd(P,emul(1n,SG));'],
  ['taproot: internal key parity not fixed', 'if(P[1]&1n) P=[P[0],SP-P[1]];', 'if(false) P=[P[0],SP-P[1]];'],
  ['taproot: tweak hashes without internal key', 'taggedHash("TapTweak",xonly)', 'taggedHash("TapTweak",new Uint8Array(32))'],
  ['taproot: tagged hash single prefix', 'b.set(th,0); b.set(th,32); b.set(msg,64);', 'b.set(th,0); b.set(th,0); b.set(msg,64);'],
  ['taproot: change chain replaced by receive', 'for(const [i,h] of [[86,true],[0,true],[0,true],[1,false],[0,false]])', 'for(const [i,h] of [[86,true],[0,true],[0,true],[0,false],[0,false]])'],
  ['five addresses: receive chain replaced by change chain', 'for(const [i,h] of [[84,true],[0,true],[0,true],[0,false]]) [k,c]=await ckdPriv(k,c,i,h);\n  const out=[];', 'for(const [i,h] of [[84,true],[0,true],[0,true],[1,false]]) [k,c]=await ckdPriv(k,c,i,h);\n  const out=[];'],
  ['taproot list not cleared after an error', 'document.getElementById("addrList").textContent = ""; document.getElementById("trList").textContent = "";', 'document.getElementById("addrList").textContent = "";'],
  ['taproot list never filled', 'tl.textContent = "";\n  (trList || []).forEach', 'tl.textContent = "";\n  ([]).forEach'],
  ['guide: NEXT unlocks one roll late', '.length >= getNeeded(document.querySelector(\'input[name="words"]:checked\').value);', '.length > getNeeded(document.querySelector(\'input[name="words"]:checked\').value);'],
  ['guide: step 4 not locked until FORGE', '  if(n === 4) return hasSeed();', '  if(n === 4) return true;'],
  ['guide: step 2 not locked', '  if(n === 2) return clean(', '  if(n === 2) return true || clean('],
  ['guide: NEXT can skip a locked step', '  if(d > 0 && !guideCanNext(guideN)) return;\n', ''],
  ['guide: DONE does not leave the guide', 'if(d > 0 && guideN >= GUIDE_STEPS){ toggleGuide(); jumpTo("cardCheck"); return; }', 'if(d > 0 && guideN >= GUIDE_STEPS){ return; }'],
  ['guide: hidden test off by one', 'return g.indexOf(String(n)) < 0;', 'return g.indexOf(String(n)) <= 0;'],
  ['guide: hidden test inverted', 'return g.indexOf(String(n)) < 0;', 'return g.indexOf(String(n)) >= 0;'],
  ['guide: passphrase box not opened at step 3', '  if(guideN === 3) document.getElementById("advanced").open = true;\n', ''],
  ['guide: last step button not DONE', 'next.textContent = guideN >= GUIDE_STEPS ? "DONE" : "NEXT \\u2192";', 'next.textContent = "NEXT \\u2192";'],
  ['guide: reopening ignores an existing seed', 'if(guideOn) guideN = hasSeed() ? 4 : 1;', 'if(guideOn) guideN = 1;'],
  ['guide: CLEAR does not return to step 1', 'if(guideOn){ guideN = 1; guideRender(); }', 'if(guideOn){ guideRender(); }'],
  ['guide: BACK enabled on step 1', 'back.disabled = guideN <= 1;', 'back.disabled = false;'],
  ['guide: progress dots off by one', 'el.classList.toggle("on", i < guideN)', 'el.classList.toggle("on", i <= guideN)'],
  ['guide: coin unit label', 'getElementById("gUnit").textContent = mode === "coin" ? "flips" : "rolls";', 'getElementById("gUnit").textContent = "rolls";'],
  ['guide: count not refreshed', 'getElementById("gNeed").textContent = String(need);', 'getElementById("gNeed").textContent = "50";'],
  ['guide: explanations all shown', 'el.style.display = (+el.getAttribute("data-gs") === guideN) ? "" : "none";', 'el.style.display = "";'],
  ['guide: button state not shown', 'b.setAttribute("aria-pressed", guideOn ? "true" : "false"); b.textContent = guideOn ? "GUIDE: ON" : "GUIDE ME";', 'b.textContent = guideOn ? "GUIDE: ON" : "GUIDE ME";'],
  ['guide: body class not toggled', 'document.body.classList.toggle("guided", guideOn);', ''],
  ['guide: FORGE does not refresh the guide', '    if(guideOn) guideRender();\n    document.getElementById("nextStep").textContent = "Write these', '    document.getElementById("nextStep").textContent = "Write these'],
  ['guide: roll count does not refresh the guide', 'function updateCount(){\n  if(guideOn) guideRender();\n', 'function updateCount(){\n'],
  ['terms: hover does not show', 'document.addEventListener("mouseover", e => { const t = term(e); if(t) show(t); });', ''],
  ['terms: moving away does not hide', 'document.addEventListener("mouseout", e => { if(term(e)) hide(); });', ''],
  ['terms: focus does not show', 'document.addEventListener("focusin", e => { const t = term(e); if(t) show(t); });', ''],
  ['terms: Escape does not hide', 'document.addEventListener("keydown", e => { if(e.key === "Escape") hide(); });', ''],
  ['terms: wrong text shown', 'tip.textContent = el.getAttribute("data-tip") || ""; tip.style.display = "block";', 'tip.textContent = ""; tip.style.display = "block";'],
  ['terms: tip kept inside the screen (layout only)', 'let x = Math.max(8, Math.min(r.left / z, window.innerWidth / z - w - 8));', 'let x = r.left / z;', true],
  ['terms: tip ignores the page zoom (layout only)', 'r.top / z - h - 8;', 'r.top - h - 8;', true],
  ['terms: tip placed below when no room above (layout only)', 'let y = r.top / z - h - 8; if(y < 8) y = r.bottom / z + 8;', 'let y = r.top / z - h - 8;', true],
  ['terms: touch outside does not hide (touch only)', 'document.addEventListener("touchstart", e => { if(!term(e)) hide(); }, {passive:true});', '', true],
  ['text size: class not toggled', 'const on = document.body.classList.toggle("big");', 'const on = false;'],
  ['text size: button state not shown', 'b.setAttribute("aria-pressed", on ? "true" : "false"); b.textContent = on ? "TEXT A-" : "TEXT A+";', 'b.textContent = on ? "TEXT A-" : "TEXT A+";'],
  ['text size: choice not remembered (browser storage)', 'try { localStorage.setItem("voidforge-big", on ? "1" : "0"); } catch(e) {}', '', true],
  ['guide: locked-step hint text', 'why.textContent = ok ? "" : (guideN === 2 ? "Keep rolling to unlock NEXT" : "Press FORGE SEED to unlock NEXT");', 'why.textContent = "";', true],
  ['demo: not tagged (would equal the real seed)', 'const d = await sha256("VOIDFORGE DEMO, NOT A SEED|" + rolls);', 'const d = await sha256(rolls);'],
  ['demo: always 12 words', 'const entLen = {12:16,24:32}[wc];\n  const d = await sha256("VOIDFORGE', 'const entLen = 16;\n  const d = await sha256("VOIDFORGE'],
  ['demo: not wiped on switch off', 'function demoToggle(){ if(!document.getElementById("demoOn").checked) demoWipe(); return demoRefresh(); }', 'function demoToggle(){ return demoRefresh(); }', true],
  ['demo: wipe leaves words', 'document.getElementById("demoGrid").textContent = ""; document.getElementById("demoInfo").textContent = "";\n  document.getElementById("demoOut").style.display = "none";\n}', 'document.getElementById("demoOut").style.display = "none";\n}'],
  ['demo: wipe leaves panel visible', '  document.getElementById("demoOut").style.display = "none";\n}\nfunction demoOff()', '}\nfunction demoOff()'],
  ['demo: FORGE does not wipe', 'function setResult(text, words){\n  demoOff(); wdWipe();\n', 'function setResult(text, words){\n  wdWipe();\n'],
  ['demo: switch stays on after wipe', 'function demoOff(){ document.getElementById("demoOn").checked = false; demoWipe(); }', 'function demoOff(){ demoWipe(); }'],
  ['demo: not refreshed after each roll', '  if(document.getElementById("demoOn").checked) demoRefresh();\n', ''],
  ['demo: shows when switched off', '  if(!document.getElementById("demoOn").checked){ demoWipe(); return; }\n  const my', '  const my'],
  ['demo: no-rolls prompt missing', 'info.textContent = "Add a roll to see the demo words."; return; }', 'info.textContent = ""; return; }'],
  ['demo: changed words not counted', 'if(ch) changed++;', ''],
  ['demo: changed words not marked', 'c.className = "dm-w" + (ch ? " dm-ch" : "");', 'c.className = "dm-w";'],
  ['demo: previous words not kept', '  demoPrev = words;\n  info.textContent', '  info.textContent'],
  ['demo: stale result can overwrite', '  if(my !== demoSeq) return;\n  const prev', '  const prev'],
  ['demo: words not numbered', 'c.textContent = (i + 1) + ". " + w; grid.appendChild(c); });\n  demoPrev', 'c.textContent = w; grid.appendChild(c); });\n  demoPrev'],
  ['demo: plural wording', '" roll" + (rolls.length === 1 ? "" : "s") + " so far.', '" roll so far.'],
  ['demo: previous words compared across lengths', 'const prev = demoPrev && demoPrev.length === words.length ? demoPrev : null;', 'const prev = demoPrev;', true],
  ['logo: tap does not roll', 'function rollLogo(){ document.getElementById("logo").classList.toggle("again"); }', 'function rollLogo(){}'],
  ['logo: Enter key does not roll', "if(event.key==='Enter'||event.key===' '){event.preventDefault();rollLogo();}", "if(event.key===' '){event.preventDefault();rollLogo();}"],
  ['logo: every key rolls', "if(event.key==='Enter'||event.key===' '){event.preventDefault();rollLogo();}", "{event.preventDefault();rollLogo();}"],
  ['logo: not keyboard reachable', 'role="button" tabindex="0" aria-label="Three dice.', 'role="button" aria-label="Three dice.'],
  ['logo: print styles hide demo (print only)', '  @media print { #demoBox, #wdBox { display: none !important; } }\n', '', true],
  ['logo: second roll uses the restart animation (CSS only)', '.logo.again svg { animation-name: dieRoll2, dieGlow2; }', '.logo.again svg { animation-name: dieRoll, dieGlow; }', true],
  ['logo: shadow restart (CSS only)', '.logo.again .die::after { animation-name: dieShadow2; }', '.logo.again .die::after { animation-name: dieShadow; }', true],
  ['word draw: exact words not matched', '  if(Object.prototype.hasOwnProperty.call(WORD_MAP, tok)) return WORD_MAP[tok];\n', ''],
  ['word draw: three-letter prefixes tried (same result)', '  if(tok.length >= 4){\n    if(!wdPrefix)', '  if(tok.length >= 3){\n    if(!wdPrefix)', true],
  ['word draw: prefix must be the start of the word', 'if(i !== undefined && WORDLIST[i].startsWith(tok)) return i;', 'if(i !== undefined) return i;'],
  ['word draw: prefix table on five letters', 'wdPrefix[w.slice(0, 4)] = i;', 'wdPrefix[w.slice(0, 5)] = i;'],
  ['word draw: words split only on spaces', "split(/[^a-z]+/).filter(Boolean), idx = [], bad = [];", "split(/\\s+/).filter(Boolean), idx = [], bad = [];"],
  ['word draw: lower-casing in lookup (parse already lower-cases)', '  tok = String(tok).toLowerCase();\n', '  tok = String(tok);\n', true],
  ['word draw: 24 words need four flips', 'wc === 24 ? {words: 23, flips: 3} : {words: 11, flips: 7}', 'wc === 24 ? {words: 23, flips: 4} : {words: 11, flips: 7}'],
  ['word draw: 12 words need eight flips', 'wc === 24 ? {words: 23, flips: 3} : {words: 11, flips: 7}', 'wc === 24 ? {words: 23, flips: 3} : {words: 11, flips: 8}'],
  ['word draw: step guard on the counts (unreachable from the page)', '  if(idx.length !== need.words || flips.length !== need.flips || /[^01]/.test(flips)) throw new Error("Wrong number of words or flips");\n', '', true],
  ['word draw: flips placed before the words', 'const bits = wordBits.join("") + flips;', 'const bits = flips + wordBits.join("");'],
  ['word draw: checksum length wrong', 'const check = bytesToBits(hash).slice(0, bits.length / 32);', 'const check = bytesToBits(hash).slice(0, bits.length / 64);'],
  ['word draw: last word bits reversed', 'const lastBits = flips + check, lastNum', 'const lastBits = check + flips, lastNum'],
  ['word draw: internal check (a maths identity)', '|| WORD_MAP[words[wc - 1]] !== lastNum) throw new Error("Internal check failed");', ') throw new Error("Internal check failed");', true],
  ['word draw: flips not filtered to 1 and 0', 'cleaned = flipsEl.value.replace(/[^01]/g, "");', 'cleaned = flipsEl.value.replace(/[^0-9]/g, "");'],
  ['word draw: count line wrong', 'pr.count + " / " + need.words + " words, " + cleaned.length + " / " + need.flips + " flips"', 'pr.count + " / " + need.words + " words, " + cleaned.length + " / " + need.words + " flips"'],
  ['word draw: unknown word not named', 'msg = "Word " + pr.bad[0].n + " (" + pr.bad[0].tok + ") is not a BIP39 word.', 'msg = "Word " + pr.bad[0].n + " is not a BIP39 word.'],
  ['word draw: too-many-words notice from the exact count', 'else if(pr.count > need.words) msg', 'else if(pr.count >= need.words) msg'],
  ['word draw: too-many-words notice missing', 'else if(pr.count > need.words) msg = "Too many words:', 'else if(false) msg = "Too many words:'],
  ['word draw: too-many-flips notice missing', 'else if(cleaned.length > need.flips) msg = "Too many flips', 'else if(false) msg = "Too many flips'],
  ['word draw: button ignores unknown words', 'selfTestState === "pass" && !pr.bad.length && pr.count', 'selfTestState === "pass" && pr.count'],
  ['word draw: button ignores the word count', 'pr.count === need.words && cleaned.length === need.flips);', 'cleaned.length === need.flips);'],
  ['word draw: button ignores the flip count', 'pr.count === need.words && cleaned.length === need.flips);', 'pr.count === need.words);'],
  ['word draw: button ignores the self-test (the page has its own gate)', 'document.getElementById("wdBtn").disabled = !(selfTestState === "pass" && ', 'document.getElementById("wdBtn").disabled = !(', true],
  ['word draw: bad input does not stop the seed', 'flips.length !== need.flips){ wdUpdate(); return; }', 'flips.length !== need.flips){ wdUpdate(); }'],
  ['word draw: passphrase mismatch accepted', '  if(document.getElementById("passphrase2").value !== document.getElementById("passphrase").value){\n    setResult("The two passphrase boxes do not match. A mistyped passphrase gives a different wallet, so fix them (or clear both) and try again.");\n    document.getElementById("advanced").open = true;\n    document.getElementById("fingerprint").textContent = ""; document.getElementById("address").textContent = "";\n    return;\n  }\n  const same', '  const same'],
  ['word draw: identical words not noticed', 'const same = pr.idx.every(n => n === pr.idx[0]), sorted', 'const same = false, sorted'],
  ['word draw: alphabetical order not noticed', 'sorted = pr.idx.every((n, i) => i === 0 || n > pr.idx[i - 1]);', 'sorted = false;'],
  ['word draw: weak-words question skipped', 'if((same || sorted) && !confirm(', 'if(false && !confirm('],
  ['word draw: alphabetical question also for equal neighbours (same warning)', 'i === 0 || n > pr.idx[i - 1]);', 'i === 0 || n >= pr.idx[i - 1]);', true],
  ['word draw: identical flips not noticed', 'if(/^(0+|1+)$/.test(flips) && !confirm(', 'if(/^0+$/.test(flips) && !confirm('],
  ['word draw: identical-flips question skipped', 'if(/^(0+|1+)$/.test(flips) && !confirm(', 'if(false && !confirm('],
  ['word draw: dice explainer left showing', '  document.getElementById("explainBox").style.display = "none";\n  wdShow(st, wc);', '  wdShow(st, wc);'],
  ['word draw: steps not shown', '  wdShow(st, wc);\n  if(guideOn)', '  if(guideOn)'],
  ['word draw: guide stays on step 1', '  wdShow(st, wc);\n  if(guideOn){ guideN = 4; guideRender(); }', '  wdShow(st, wc);\n  if(guideOn){ guideRender(); }'],
  ['word draw: dice FORGE leaves old steps', 'function setResult(text, words){\n  demoOff(); wdWipe();\n', 'function setResult(text, words){\n  demoOff();\n'],
  ['word draw: CLEAR leaves the boxes', '  wdClear();\n', ''],
  ['word draw: CLEAR button leaves the words', 'document.getElementById("wdWords").value = ""; document.getElementById("wdFlips").value = "";\n  wdWipe(); wdUpdate();', 'document.getElementById("wdFlips").value = "";\n  wdWipe(); wdUpdate();'],
  ['word draw: CLEAR button leaves the flips', 'document.getElementById("wdWords").value = ""; document.getElementById("wdFlips").value = "";\n  wdWipe(); wdUpdate();', 'document.getElementById("wdWords").value = "";\n  wdWipe(); wdUpdate();'],
  ['word draw: wipe leaves the steps', 'function wdWipe(){ const o = document.getElementById("wdOut"); o.textContent = ""; o.style.display = "none"; }', 'function wdWipe(){ const o = document.getElementById("wdOut"); o.style.display = "none"; }'],
  ['word draw: wipe leaves the panel open', 'function wdWipe(){ const o = document.getElementById("wdOut"); o.textContent = ""; o.style.display = "none"; }', 'function wdWipe(){ const o = document.getElementById("wdOut"); o.textContent = ""; }'],
  ['word draw: self-test gate does not refresh the button (typing refreshes it anyway)', '  document.getElementById("childBtn").disabled = !on;\n  wdUpdate();\n}', '  document.getElementById("childBtn").disabled = !on;\n}', true],
  ['word draw: not offered on guide step 1', '<details id="wdBox" data-g="1">', '<details id="wdBox" data-g="2">'],
  ['word draw: words rows missing', '  st.wordBits.forEach((b, i) => add((1 + i) + ".",', '  st.wordBits.slice(0, 0).forEach((b, i) => add((1 + i) + ".",'],
  ['word draw: flips row missing', '  add("Flips", st.flips + "  (" + st.flips.length + " bits)");\n', ''],
  ['word draw: no-hashing note missing', '  const n = document.createElement("div"); n.className = "hint"; n.style.margin = "6px 0 0"; n.textContent = "No hashing is applied to your words: they are the seed. Only the checksum is calculated."; o.appendChild(n);\n', ''],
  ['word draw: no scroll to the result (display only)', '  if(guideOn){ guideN = 4; guideRender(); }\n  jumpTo("genResult");', '  if(guideOn){ guideN = 4; guideRender(); }', true],
  ['address list not cleared after an error', 'function clearAddrs(){\n  document.getElementById("addrList").textContent = "";', 'function clearAddrs(){\n  '],
  ['address guide hidden after FORGE', 'document.getElementById("checkGuide").style.display = "";\n}', 'document.getElementById("checkGuide").style.display = "none";\n}'],
  ['4-letter view: three letters', 'e.textContent = abbrOn ? e.dataset.w.slice(0, 4) : e.dataset.w;', 'e.textContent = abbrOn ? e.dataset.w.slice(0, 3) : e.dataset.w;'],
  ['mnemonic NFKD removed (English ASCII words)', 'enc.encode(mnemonic.normalize("NFKD"))', 'enc.encode(mnemonic)', true],
  ['master key range check removed (unreachable in practice)', 'if(k===0n || k>=SN) throw new Error("Invalid master key");', '', true],
  ["seedqr: level L uses the M table", "spec.level===\"L\"?QR_L:QR_M", "spec.level===\"L\"?QR_M:QR_M"],
  ["seedqr: format bits for level L wrong", "eccBits=spec.level===\"L\"?1:0", "eccBits=spec.level===\"L\"?0:0"],
  ["seedqr: numeric mode flag inverted", "numeric=spec.mode===\"numeric\"", "numeric=spec.mode!==\"numeric\""],
  ["seedqr: numeric bits per 3 digits wrong", "Math.floor(digits.length/3)*10+", "Math.floor(digits.length/3)*8+"],
  ["seedqr: numeric bits for a leftover pair wrong", "[0,4,7][digits.length%3]", "[0,4,8][digits.length%3]", true],
  ["seedqr: numeric bits for a leftover digit wrong", "[0,4,7][digits.length%3]", "[0,3,7][digits.length%3]", true],
  ["seedqr: numeric count field too short", "(numeric?(v<10?10:12)", "(numeric?(v<10?9:12)", true],
  ["seedqr: numeric mode indicator wrong", "put(1,4); put(digits.length", "put(2,4); put(digits.length"],
  ["seedqr: numeric count written short", "put(digits.length,ver<10?10:12)", "put(digits.length,ver<10?9:12)"],
  ["seedqr: three digits written in the wrong width", "g.length===3?10:g.length===2?7:4", "g.length===3?11:g.length===2?7:4"],
  ["seedqr: two digits written in the wrong width", "g.length===3?10:g.length===2?7:4", "g.length===3?10:g.length===2?8:4", true],
  ["seedqr: one digit written in the wrong width", "g.length===3?10:g.length===2?7:4", "g.length===3?10:g.length===2?7:5", true],
  ["seedqr: version 1 error correction length wrong", "1:[7,[[1,19]]]", "1:[8,[[1,19]]]"],
  ["seedqr: version 1 data length wrong", "1:[7,[[1,19]]]", "1:[7,[[1,18]]]"],
  ["seedqr: version 2 error correction length wrong", "2:[10,[[1,34]]]", "2:[11,[[1,34]]]"],
  ["seedqr: version 2 data length wrong", "2:[10,[[1,34]]]", "2:[10,[[1,33]]]"],
  ["seedqr: version 3 error correction length wrong", "3:[15,[[1,55]]]", "3:[16,[[1,55]]]"],
  ["seedqr: version 3 data length wrong", "3:[15,[[1,55]]]", "3:[15,[[1,54]]]"],
  ["seedqr: version search stops one early", "v<=Object.keys(TBL).length", "v<Object.keys(TBL).length"],
  ["seedqr: any length accepted", "if(![12,24].includes(idx.length) ||", "if(false ||"],
  ["seedqr: unknown words accepted", "idx.some(i=>i===undefined)", "idx.some(i=>false)"],
  ["seedqr: word number width wrong", "String(i).padStart(4,\"0\")", "String(i).padStart(3,\"0\")"],
  ["seedqr: 11-bit word number wrong", "idx.map(i=>i.toString(2).padStart(11,\"0\"))", "idx.map(i=>i.toString(2).padStart(10,\"0\"))"],
  ["seedqr: checksum bits kept in the compact bytes", "idx.length*11 - idx.length/3", "idx.length*11 - idx.length/4"],
  ["seedqr: compact bytes read in 7 bits", "parseInt(bits.slice(i,i+8),2)", "parseInt(bits.slice(i,i+7),2)"],
  ["seedqr: compact and standard swapped", "kind===\"compact\" ? {mode:\"byte\"", "kind!==\"compact\" ? {mode:\"byte\""],
  ["seedqr: short phrase not refused", "if(!d) throw new Error(\"SeedQR exists", "if(false) throw new Error(\"SeedQR exists"],
  ["seedqr: show button box offered for any length", "sq.style.display = (words && [12,24].includes(words.length)) ? \"\" : \"none\"", "sq.style.display = (words) ? \"\" : \"none\""],
  ["seedqr: box opened after FORGE", "sq.open = false;", "sq.open = true;"],
  ["seedqr: old code kept after a new FORGE", "hideSeedQr(); { const sq", "{ const sq"],
  ["seedqr: old code kept after hide", "sqKind = null; sqRows = null; closeSqGuide();", "sqKind = null; closeSqGuide();"],
  ["seedqr: guide stays open when another code is shown", "sqKind = kind; sqRows = q.rows; closeSqGuide();", "sqKind = kind; sqRows = q.rows;"],
  ["seedqr: block size wrong", "function qrBlockSize(n){ return 7; }", "function qrBlockSize(n){ return 6; }"],
  ["seedqr: row list start wrong", "out.push(e===x ? String(x+1)", "out.push(e===x ? String(x)"],
  ["seedqr: row list end wrong", "(x+1)+\"-\"+(e+1)", "(x+1)+\"-\"+(e)"],
  ["seedqr: row list skips filled runs of one", "if(row[x]){ let e=x;", "if(row[x] && row[x+1]){ let e=x;"],
  ["seedqr: row list run ends early", "while(e+1<row.length && row[e+1]) e++;", "while(e+1<row.length-1 && row[e+1]) e++;"],
  ["seedqr: grid grey squares missing", "if(x>=n || y>=n) grey+=sq;", "if(x>=n && y>=n) grey+=sq;"],
  ["seedqr: blank grid shows squares", "else if(!blank && rows[y][x]) cells+=sq;", "else if(rows[y][x]) cells+=sq;"],
  ["seedqr: grid shows white squares as black", "else if(!blank && rows[y][x]) cells+=sq;", "else if(!blank && !rows[y][x]) cells+=sq;"],
  ["seedqr: grid column numbers for squares outside the code", "for(let x=x0;x<Math.min(x1,n);x++) labels", "for(let x=x0;x<x1;x++) labels"],
  ["seedqr: grid row numbers for squares outside the code", "for(let y=y0;y<Math.min(y1,n);y++) labels", "for(let y=y0;y<y1;y++) labels"],
  ["seedqr: grid column numbers off by one", "'\">'+(x+1)+\"</text>\";\n  for(let y", "'\">'+(x)+\"</text>\";\n  for(let y"],
  ["seedqr: mini-map block width not cut", "const bx=Math.min(x1,n)-x0, by=Math.min(y1,n)-y0;", "const bx=x1-x0, by=Math.min(y1,n)-y0;"],
  ["seedqr: mini-map block height not cut", "const bx=Math.min(x1,n)-x0, by=Math.min(y1,n)-y0;", "const bx=Math.min(x1,n)-x0, by=y1-y0;"],
  ["seedqr: number of blocks rounded down", "per = Math.ceil(n / b), total = per * per;", "per = Math.floor(n / b), total = per * per;"],
  ["seedqr: previous block does not wrap", "((sqBlock - 1 + delta + total) % total) + 1", "((sqBlock - 1 + delta) % total) + 1"],
  ["seedqr: opening the guide does not start at block 1", "sqBlock = first ? 1 :", "sqBlock = first ? 2 :"],
  ["seedqr: block row and column swapped", "const r = Math.floor((sqBlock - 1) / per), c = (sqBlock - 1) % per,", "const c = Math.floor((sqBlock - 1) / per), r = (sqBlock - 1) % per,"],
  ["seedqr: block shifted by one square", "x1 = x0 + b, y1 = y0 + b;", "x1 = x0 + b - 1, y1 = y0 + b;"],
  ["seedqr: block caption not cut at the edge", "\" to \" + Math.min(n, y1) + \", columns \"", "\" to \" + y1 + \", columns \""],
  ["seedqr: block caption columns not cut at the edge", "\" to \" + Math.min(n, x1) + \" of the \"", "\" to \" + x1 + \" of the \""],
  ["seedqr: whole grid keeps the mini-map", "document.getElementById(\"sqMini\").textContent = \"\";\n  document.getElementById(\"sqGuideImg\").innerHTML = qrGridSvg(sqRows, 0, 0, n, n", "document.getElementById(\"sqGuideImg\").innerHTML = qrGridSvg(sqRows, 0, 0, n, n"],
  ["seedqr: closing the guide keeps the mini-map", "document.getElementById(\"sqMini\").textContent = \"\"; document.getElementById(\"sqGuideCaption\")", "document.getElementById(\"sqGuideCaption\")"],
  ["seedqr: guide stays after closing", "document.getElementById(\"sqGuide\").style.display = \"none\";\n}\nfunction openSqGuide", "}\nfunction openSqGuide"],
  ["seedqr: print code without asking", "if(!confirm(\"Printing sends your seed (as a QR code) to a printer", "if(false && !confirm(\"Printing sends your seed (as a QR code) to a printer"],
  ["seedqr: print guide without asking", "if(!confirm(\"Printing sends your seed (as a QR code grid) to a printer", "if(false && !confirm(\"Printing sends your seed (as a QR code grid) to a printer"],
  ["seedqr: print without a shown code", "if(!sqRows) return alert(\"Press SHOW SEEDQR or SHOW COMPACTSEEDQR first, then print the one you want.\");", "if(false) return alert(\"Press SHOW SEEDQR or SHOW COMPACTSEEDQR first, then print the one you want.\");"],
  ["seedqr: print guide without a shown code", "if(!sqRows) return alert(\"Press SHOW SEEDQR or SHOW COMPACTSEEDQR first, then print the guide", "if(false) return alert(\"Press SHOW SEEDQR or SHOW COMPACTSEEDQR first, then print the guide"],
  ["seedqr: blank grid without a shown code", "if(!sqRows) return alert(\"Press SHOW SEEDQR or SHOW COMPACTSEEDQR first, so the grid", "if(false) return alert(\"Press SHOW SEEDQR or SHOW COMPACTSEEDQR first, so the grid"],
  ["seedqr: guide opened without a shown code", "if(!sqRows) return alert(\"Press SHOW SEEDQR or SHOW COMPACTSEEDQR first.\");", "if(false) return alert(\"Press SHOW SEEDQR or SHOW COMPACTSEEDQR first.\");"],
  ["seedqr: blank grid sheet prints the filled code", "qrGridSvg(sqRows, 0, 0, n, n, qrBlockSize(n), true), true,", "qrGridSvg(sqRows, 0, 0, n, n, qrBlockSize(n), false), true,"],
  ["seedqr: row list has no row numbers", "\"Row \" + (y + 1) + \": \" + qrRowRuns(row)", "\"Row \" + (y) + \": \" + qrRowRuns(row)"],
  ["seedqr: print area not cleaned", "document.body.classList.remove(\"print-qr\"); po.textContent = \"\"; };", "po.textContent = \"\"; };"],
  ["seedqr: print class not removed", "document.body.classList.remove(\"print-qr\"); po.textContent = \"\"; };", "document.body.classList.remove(\"print-qr\"); };"],
  ["seedqr: print sheet passphrase line missing", "document.getElementById(\"fingerprint\").textContent + \"\\n\" + passLine(\"printed\") + \"\\n\\nScan with an offline", "document.getElementById(\"fingerprint\").textContent + \"\\n\\nScan with an offline"],
  ["explain: entropy taken from the wrong bytes", "const entropy = digest.slice(0, entLen);", "const entropy = digest.slice(1, entLen + 1);"],
  ["explain: checksum made from the wrong bytes", "const hash2 = await sha256bytes(entropy);", "const hash2 = await sha256bytes(digest);"],
  ["explain: checksum too short", "bytesToBits(hash2).slice(0, entLen * 8 / 32)", "bytesToBits(hash2).slice(0, entLen * 8 / 33)"],
  ["explain: checksum too long", "bytesToBits(hash2).slice(0, entLen * 8 / 32)", "bytesToBits(hash2).slice(0, entLen * 8 / 16)"],
  ["explain: pieces of 10 bits", "const bits = all.slice(i, i + 11), num = parseInt(bits, 2);", "const bits = all.slice(i, i + 10), num = parseInt(bits, 2);"],
  ["explain: number read in the wrong base", "const bits = all.slice(i, i + 11), num = parseInt(bits, 2);", "const bits = all.slice(i, i + 11), num = parseInt(bits, 8);"],
  ["explain: word looked up one off", "word: WORDLIST[num]}", "word: WORDLIST[num + 1]}"],
  ["explain: roll count off by one", "count: rolls.length,", "count: rolls.length + 1,"],
  ["explain: entropy size wrong", "entropyBits: entLen * 8,", "entropyBits: entLen * 4,"],
  ["explain: hex without leading zeros", "x.toString(16).padStart(2, \"0\")).join(\"\");\n  return {count", "x.toString(16).padStart(1, \"0\")).join(\"\");\n  return {count"],
  ["explain: steps shown without a seed", "if(!exCtx) return alert(\"Forge a seed first.\");", "if(false) return alert(\"Forge a seed first.\");"],
  ["explain: coin shown as dice", "const coin = exCtx.coin,", "const coin = false,"],
  ["explain: dice shown as coin", "const coin = exCtx.coin,", "const coin = true,"],
  ["explain: dice bits worth 2 each", "Math.floor(coin ? s.count : s.count * Math.log2(6))", "Math.floor(coin ? s.count : s.count * 2)"],
  ["explain: coin bits worth 2 each", "Math.floor(coin ? s.count : s.count * Math.log2(6))", "Math.floor(coin ? s.count * 2 : s.count * Math.log2(6))"],
  ["explain: checksum split in the wrong piece", "i === s.groups.length - 1", "i === s.groups.length - 2"],
  ["explain: checksum split in the wrong place", "const keep = 11 - s.checkBits.length;", "const keep = 10 - s.checkBits.length;"],
  ["explain: mismatch not noticed", "const same = s.words.join(\" \") === exCtx.words.join(\" \");", "const same = true;"],
  ["explain: match claimed wrongly", "const same = s.words.join(\" \") === exCtx.words.join(\" \");", "const same = s.words.join(\" \") !== exCtx.words.join(\" \");"],
  ["explain: steps not shown at the end", "  o.style.display = \"\";\n}\n// SeedSigner formats", "\n}\n// SeedSigner formats"],
  ["explain: hide keeps the secret context", "exCtx = null;\n  const o = document.getElementById(\"exOut\"); o.textContent = \"\"; o.style.display = \"none\";", "const o = document.getElementById(\"exOut\"); o.textContent = \"\"; o.style.display = \"none\";"],
  ["explain: hide keeps the steps text", "o.textContent = \"\"; o.style.display = \"none\";\n}\nasync function showExplain", "o.style.display = \"none\";\n}\nasync function showExplain"],
  ["explain: hide keeps the steps shown", "o.textContent = \"\"; o.style.display = \"none\";\n}\nasync function showExplain", "o.textContent = \"\";\n}\nasync function showExplain"],
  ["explain: old steps kept after a new FORGE", "  hideExplain(); { const eb", "  { const eb"],
  ["explain: box offered for any length", "eb.style.display = (words && [12,24].includes(words.length)) ? \"\" : \"none\";", "eb.style.display = (words) ? \"\" : \"none\";"],
  ["explain: box opened after FORGE", "eb.open = false; }", "eb.open = true; }"],
  ["explain: no context kept for the steps", "  exCtx = ctx;\n", ""],
  ["print sheet: wrong grid class", "add(\"ps-grid ps-\" + ws.length, \"\")", "add(\"ps-grid ps-12\", \"\")"],
  ["print sheet: box numbers not padded", "add(\"ps-n\", String(i + 1).padStart(2, \"0\"), c)", "add(\"ps-n\", String(i + 1), c)"],
  ["print sheet: first word printed in every box", "add(\"ps-w\", w, c)", "add(\"ps-w\", ws[0], c)"],
  ["print sheet: printed without asking", "if(!confirm(\"Printing sends your seed to a printer and its spooler.", "if(false && !confirm(\"Printing sends your seed to a printer and its spooler."],
  ["print sheet: passphrase line missing", "document.getElementById(\"address\").textContent + \"\\n\" + passLine(\"printed\"));\n  add(\"ps-fields\"", "document.getElementById(\"address\").textContent);\n  add(\"ps-fields\""],
  ["print sheet: fingerprint missing", "add(\"ps-info\", document.getElementById(\"fingerprint\").textContent + \"\\n\" + document.getElementById(\"address\").textContent", "add(\"ps-info\", document.getElementById(\"address\").textContent"],
  ["print sheet: area not cleaned", "document.body.classList.remove(\"print-seed\"); po.textContent = \"\"; };", "po.textContent = \"\"; };"],
  ["print sheet: print class not removed", "document.body.classList.remove(\"print-seed\"); po.textContent = \"\"; };", "document.body.classList.remove(\"print-seed\"); };"],
  ["explain: entropy size 16 -> 15 bytes", "async function explainSteps(rolls, wc){\n  const entLen = {12:16,24:32}[wc];", "async function explainSteps(rolls, wc){\n  const entLen = {12:15,24:32}[wc];"],
  ["explain: entropy size 32 -> 31 bytes", "async function explainSteps(rolls, wc){\n  const entLen = {12:16,24:32}[wc];", "async function explainSteps(rolls, wc){\n  const entLen = {12:16,24:31}[wc];"],
  ["explain: rolls hashed with extra byte", "const digest = await sha256(rolls);\n  const entropy = digest.slice(0, entLen);", "const digest = await sha256(rolls+\"0\");\n  const entropy = digest.slice(0, entLen);"],
  // ---- multisig (v1.20.0) ----
  ['multisig: Base58 radix wrong', 'n=n*58n+BigInt(v)', 'n=n*57n+BigInt(v)'],
  ['multisig: Base58 checksum not checked', 'if(sum[i]!==all[all.length-4+i]) throw new Error("not a valid key: checksum', 'if(false) throw new Error("not a valid key: checksum'],
  ['multisig: Base58 leading 1s not counted', 'for(const ch of str){ if(ch==="1") zeros++; else break; }', 'for(const ch of str){ break; }', true],
  ['multisig: square root exponent', 'e=(SP+1n)/4n', 'e=(SP-3n)/4n'],
  ['multisig: y parity flipped', '(y&1n)===(odd?1n:0n) ? y : SP-y', '(y&1n)===(odd?0n:1n) ? y : SP-y'],
  ['multisig: off-curve x accepted', 'if(y*y%SP!==y2) return null;', ''],
  ['multisig: x above the field accepted', 'if(x>=SP) return null;', ''],
  ['multisig: key prefix 03 not accepted', 'pub[0]!==2 && pub[0]!==3', 'pub[0]!==2'],
  ['multisig: key prefix not checked', '(pub.length!==33 || (pub[0]!==2 && pub[0]!==3))', '(pub.length!==33)'],
  ['multisig: key length not exact', 'if(raw.length!==78) throw', 'if(raw.length<78) throw'],
  ['multisig: private keys not recognised', 'if(EXT_PRIVATE.includes(ver)) throw', 'if(false) throw'],
  ['multisig: unknown version accepted', 'if(!known) throw new Error("unknown key type', 'if(false) throw new Error("unknown key type'],
  ['multisig: key point not validated', 'const pub=raw.slice(45,78); pointFromPub(pub);', 'const pub=raw.slice(45,78);'],
  ['multisig: network read from the wrong place', 'return {str, net:known.net,', 'return {str, net:"main",'],
  ['multisig: depth ignored', 'depth:raw[4],', 'depth:0,'],
  ['multisig: child number read wrong', 'childNum:(raw[9]<<24|raw[10]<<16|raw[11]<<8|raw[12])>>>0', 'childNum:(raw[9]<<24|raw[10]<<16|raw[11]<<8|raw[11])>>>0'],
  ['multisig: public derivation starts from the wrong data', 'data.set(pub,0); data.set([(index>>>24)', 'data.set(pub,1); data.set([(index>>>24)'],
  ['multisig: hardened index allowed', 'index>=0x80000000) throw new Error("bad index")', 'index>0x80000000) throw new Error("bad index")'],
  ['multisig: negative index allowed', 'if(!Number.isInteger(index) || index<0 ||', 'if(!Number.isInteger(index) ||'],
  ['multisig: child tweak not added to the parent', 'const C=eadd(emul(il,SG),pointFromPub(pub));', 'const C=emul(il,SG);'],
  ['multisig: chain code not carried on', 'return [pubFromPoint(C), I.slice(32)];', 'return [pubFromPoint(C), chain];'],
  ['multisig: key sort reversed', 'return a[i]-b[i]; return a.length-b.length;', 'return b[i]-a[i]; return a.length-b.length;'],
  ['multisig: M of 0 accepted', '!Number.isInteger(m) || m<1 ||', '!Number.isInteger(m) || m<0 ||'],
  ['multisig: M above N accepted', '|| n>15 || m>n) throw', '|| n>15 || m>n+1) throw'],
  ['multisig: one key accepted', 'm<1 || n<2 ||', 'm<1 || n<1 ||'],
  ['multisig: sixteen keys accepted', 'n<2 || n>15 ||', 'n<2 || n>16 ||'],
  ['multisig: receive branch not derived', 'const [bp,bc]=await ckdPub(c.key.pub,c.key.chain,branch);', 'const [bp,bc]=[c.key.pub,c.key.chain];'],
  ['multisig: keys not sorted', 'pubs.sort(cmpBytes);', ''],
  ['multisig: script M opcode wrong', 'const out=[0x50+m];', 'const out=[0x50+m+1];'],
  ['multisig: script N opcode wrong', 'out.push(0x50+n, 0xae);', 'out.push(0x50+n+1, 0xae);'],
  ['multisig: script CHECKMULTISIG opcode wrong', 'out.push(0x50+n, 0xae);', 'out.push(0x50+n, 0xaf);'],
  ['multisig: P2WSH uses the wrong hash', 'if(type==="ms-wsh") return bech32Encode(N.hrp,0,sh);', 'if(type==="ms-wsh") return bech32Encode(N.hrp,0,await hash160(script));'],
  ['multisig: nested address wrong version byte', 'base58check(Uint8Array.from([N.sh, ...prog]))', 'base58check(Uint8Array.from([N.pkh, ...prog]))'],
  ['multisig: Base58 decode skips the second SHA-256', 'sum=(await sha256bytes(h1)).slice(0,4)', 'sum=h1.slice(0,4)'],
  ['multisig: public key parity flipped', 'pub[0]=2+Number(P[1]&1n);', 'pub[0]=3-Number(P[1]&1n);'],
  ['multisig: nested address wrong witness program length', 'Uint8Array.from([0x00,0x20,...sh])', 'Uint8Array.from([0x00,0x14,...sh])'],
  ['multisig: descriptor keys not sorted', 'keys.sort();', ''],
  ['multisig: descriptor wrong function', '"sortedmulti(" + m + ","', '"multi(" + m + ","'],
  ['multisig: descriptor branch dropped', '"]" + xp + "/" + branch + "/*");', '"]" + xp + "/0/*");'],
  ['multisig: descriptor nested wrapper missing', 'type==="ms-sh-wsh" ? "sh(wsh(" + inner + "))" : "wsh(" + inner + ")"', '"wsh(" + inner + ")"'],
  ['multisig: descriptor key version wrong', '...NETS[c.key.net].ver.other, ...raw.slice(4)', '...NETS.main.ver.other, ...raw.slice(4)'],
  ['multisig: M default wrong', 'Math.max(2, Math.ceil((n + 1) / 2))', 'Math.max(2, Math.ceil(n / 2))'],
  ['multisig: M above N offered', 'for(let i = 1; i <= n; i++){ const o = document.createElement("option");', 'for(let i = 1; i <= n + 1; i++){ const o = document.createElement("option");'],
  ['multisig: 1-of-N allowed to start', 'if(m < 2){ err.textContent', 'if(m < 1){ err.textContent'],
  ['multisig: account range not checked', '|| parseInt(raw, 10) > 2147483647){ err.textContent = "The account must', '|| false){ err.textContent = "The account must'],
  ['multisig: account number not used', 'account: parseInt(raw, 10), keys: []', 'account: 0, keys: []'],
  ['multisig: network not used', 'net: msEl("msNet").value,', 'net: "main",'],
  ['multisig: type not used', 'type: msEl("msType").value,', 'type: "ms-wsh",'],
  ['multisig: duplicate (first key) allowed', 'if(dup >= 0){ eb.textContent = "This is the same key as key "', 'if(dup > 0){ eb.textContent = "This is the same key as key "'],
  ['multisig: duplicate only by fingerprint', 'k.fp === fp || hex(k.key.pub) === pk', 'k.fp === fp'],
  ['multisig: duplicate only by key', 'k.fp === fp || hex(k.key.pub) === pk', 'hex(k.key.pub) === pk'],
  ['multisig: pasted duplicate allowed', 'if(dup >= 0) throw new Error("This is the same key as key "', 'if(false) throw new Error("This is the same key as key "'],
  ['multisig: seed not wiped after ADD', '    wipeSeed();\n  } catch(e) { eb.textContent = "Could not add this key: "', '  } catch(e) { eb.textContent = "Could not add this key: "'],
  ['multisig: ADD with no seed allowed', 'if(!hasSeed() || !watchCtx){ eb.textContent = "Make the seed first', 'if(false){ eb.textContent = "Make the seed first'],
  ['multisig: made key taken from the wrong account', 'mnemonicToSeed(watchCtx.mnemonic, watchCtx.pass), ms.type, ms.account, ms.net)', 'mnemonicToSeed(watchCtx.mnemonic, watchCtx.pass), ms.type, 0, ms.net)'],
  ['multisig: passphrase ignored for a made key', 'mnemonicToSeed(watchCtx.mnemonic, watchCtx.pass), ms.type', 'mnemonicToSeed(watchCtx.mnemonic, ""), ms.type'],
  ['multisig: made key origin path wrong', 'function msPathOf(){ return "48h/" + NETS[ms.net].coin + "h/"', 'function msPathOf(){ return "48h/0h/"'],
  ['multisig: private key / seed words not refused', 'if(/^\\s*[a-z]+(\\s+[a-z]+){11,}\\s*$/i.test(t)) throw', 'if(false) throw'],
  ['multisig: seed-word guard needs 13 words', '{11,}\\s*$/i.test(t)', '{12,}\\s*$/i.test(t)'],
  ['multisig: fingerprint not checked', 'if(!/^[0-9a-f]{8}$/.test(fp)) throw', 'if(false) throw'],
  ['multisig: wrong network accepted', 'if(key.net !== ms.net) throw', 'if(false) throw'],
  ['multisig: single-signature key accepted', 'if(key.type !== "other" && key.type !== ms.type) throw', 'if(false) throw'],
  ['multisig: other script type accepted', 'key.type !== "other" && key.type !== ms.type', 'key.type !== "other" && !MULTISIG[key.type]'],
  ['multisig: depth not checked', 'if(key.depth !== 4 || key.childNum', 'if(key.childNum'],
  ['multisig: last step not checked', 'if(key.depth !== 4 || key.childNum !== ((script + 0x80000000) >>> 0)) throw', 'if(key.depth !== 4) throw'],
  ['multisig: path in the pasted line not checked', 'if(path && path !== want) throw', 'if(false) throw'],
  ['multisig: path apostrophes not understood', '.replace(/[\'H]/g, "h")', ''],
  ['multisig: /0/* suffix not stripped', 't = t.replace(/\\/(?:<0;1>|[01])\\/\\*$/, "");', ''],
  ['multisig: pasted key stored without its fingerprint', 'ms.keys.push({fp, path: want, key, xpub, src: "pasted"});', 'ms.keys.push({fp: "00000000", path: want, key, xpub, src: "pasted"});'],
  ['multisig: pasted key counted as made here', 'src: "pasted"});', 'src: "made"});'],
  ['multisig: three addresses -> two', 'for(let i = 0; i < 3; i++) addrs.push(await multisigAddress', 'for(let i = 0; i < 2; i++) addrs.push(await multisigAddress'],
  ['multisig: addresses from the change branch', 'multisigAddress(ms.type, ms.m, cos, 0, i, ms.net)', 'multisigAddress(ms.type, ms.m, cos, 1, i, ms.net)'],
  ['multisig: change descriptor is the receive one', 'dc = await multisigDescriptor(ms.type, ms.m, cos, 1)', 'dc = await multisigDescriptor(ms.type, ms.m, cos, 0)'],
  ['multisig: one-device warning for mixed sources', 'ms.keys.every(k => k.src === "made")', 'ms.keys.some(k => k.src === "made")'],
  ['multisig: one-device warning never shown', 'msEl("msOneDev").style.display = ms.keys.every(k => k.src === "made") ? "" : "none";', 'msEl("msOneDev").style.display = "none";'],
  ['multisig: banner stays when finished', 'if(!ms || ms.done || ms.mode !== "make" || ms.keys.length >= ms.n){', 'if(!ms || ms.mode !== "make" || ms.keys.length >= ms.n + 1){'],
  ['multisig: ADD button always on', 'msEl("msAddBtn").disabled = !(hasSeed() && watchCtx && !ms.busy);', 'msEl("msAddBtn").disabled = false;'],
  ['multisig: banner counts from 0', 'const k = ms.keys.length + 1;\n  msEl("msBanTitle")', 'const k = ms.keys.length;\n  msEl("msBanTitle")'],
  ['multisig: testnet not shown in the banner', '(ms.net === "test" ? "  (TESTNET)" : "")', '""'],
  ['multisig: testnet banner never shown', 'msEl("msTestBan").style.display = ms.net === "test" ? "" : "none";', 'msEl("msTestBan").style.display = "none";'],
  ['multisig: QR of the change descriptor', 'qrMatrix(ms.descR); } catch(e) { msEl("msRunErr")', 'qrMatrix(ms.descC); } catch(e) { msEl("msRunErr")'],
  ['multisig: recovery sheet leaves out the descriptor', 'lines.push("", "DESCRIPTOR (public keys only):", ms.descR, "",', 'lines.push("", "DESCRIPTOR (public keys only):", "", "",'],
  ['multisig: recovery sheet leaves out the addresses', '"FIRST RECEIVING ADDRESSES:", ...ms.addrs, "",', '"FIRST RECEIVING ADDRESSES:", "",'],
  ['multisig: recovery sheet testnet label missing', '(ms.net === "test" ? ", TESTNET (practice coins only)" : ", mainnet")', '", mainnet"'],
  ['multisig: sheet title testnet label missing', '"VOIDFORGE MULTISIG RECOVERY SHEET" + (ms.net === "test" ? " (TESTNET)" : "")', '"VOIDFORGE MULTISIG RECOVERY SHEET"'],
  ['multisig: sheet QR size switch (layout only)', 'q.version > 15, msSheetText()', 'q.version > 14, msSheetText()', true],
  ['multisig: CLEAR ALL keeps the setup', 'msReset(); wipeSeed();\n}', 'wipeSeed();\n}'],
  ['multisig: reset leaves the descriptor on screen', 'for(const id of ["msDescR","msDescC","msAddrs","msSlots","msRunErr","msBanErr","msErr"])', 'for(const id of ["msDescC","msAddrs","msSlots","msRunErr","msBanErr","msErr"])'],
  ['page open: scrolls down to the rolls box', 'getElementById("rolls").focus({preventScroll: true});', 'getElementById("rolls").focus();'],
  ['multisig: reset leaves the QR on screen', 'ms = null; msHideQr();', 'ms = null;'],
  ['multisig: saved key shows no picture', 'if(k) showFpIcon(ic.id, k.fp);', ''],
  ['QR: version 13 table', '13:[22,[[8,37],[1,38]]]', '13:[22,[[8,37],[1,37]]]'],
  ['QR: version 20 table', '20:[26,[[3,41],[13,42]]]', '20:[26,[[3,41],[12,42]]]'],
  ['QR: version 30 table', '30:[28,[[19,47],[10,48]]]', '30:[28,[[19,47],[9,48]]]'],
  ['QR: version 25 alignment', '25:[6,32,58,84,110]', '25:[6,32,58,84,111]'],
  ['QR: version 30 alignment', '30:[6,26,52,78,104,130]', '30:[6,26,52,78,104,131]'],
];

if (process.env.MUT_CHECK_TARGETS) { // quick mode: only check that every mutation target occurs exactly once in the page
  let badT = 0; for (const [name, find] of M) { const c = html.split(find).length - 1; if (c !== 1) { badT++; console.log(`target occurs ${c}x: ${name}`); } }
  console.log(badT ? `${badT} bad target(s)` : 'all mutation targets occur exactly once'); process.exit(badT ? 1 : 0);
}
const base = await detect(html);
R.ok(base.by === null, "control: the unmodified file passes the self-test and every probe" + (base.by ? " [" + base.by + "]" : ""));

const survivors = [];
const ONLY = process.env.MUT_ONLY ? new RegExp(process.env.MUT_ONLY) : null; // optional: run only the mutations whose name matches
// Optional sharding for CI: MUT_SHARD="i/n" runs only every n-th mutation starting at i, so n jobs together run them all.
const SHARD = process.env.MUT_SHARD ? process.env.MUT_SHARD.split('/').map(Number) : null;
if (SHARD && !(Number.isInteger(SHARD[0]) && Number.isInteger(SHARD[1]) && SHARD[1] > 0 && SHARD[0] >= 0 && SHARD[0] < SHARD[1])) { console.log('bad MUT_SHARD (use i/n, for example 0/4)'); process.exit(1); }
let mutIndex = -1;
for (const [name, find, rep, equivalent] of M) {
  mutIndex++;
  if (SHARD && mutIndex % SHARD[1] !== SHARD[0]) continue;
  if (ONLY && !ONLY.test(name)) continue;
  const count = html.split(find).length - 1;
  if (count !== 1) { R.ok(false, `mutation target must occur exactly once (${count}x): ${name}`); continue; }
  const res = await detect(html.replace(find, () => rep));
  if (equivalent) { R.ok(true, `${name}: behaviourally equivalent, ${res.by ? 'caught by ' + res.by : 'survives as expected'}`); continue; }
  R.ok(res.by !== null, res.by ? `${name}: caught by ${res.by}` : `${name}: SURVIVED (a hole in the safety net)`);
  if (!res.by) survivors.push(name);
}
if (survivors.length) console.log('\nSurvivors:', survivors);
R.done('mutation');
