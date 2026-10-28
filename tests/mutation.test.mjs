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
    const bad = [['abandon', 'abandon'], 'abandon '.repeat(11).split(' ').concat('zzzz'), entropyToMnemonic(new Uint8Array(20), wordlist).split(' ')];
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
    if (pr.n !== 1 || !/^VOIDFORGE SEEDQR \(12 words, 25 x 25 squares\)/.test(pr.text) || !/<svg/.test(pr.html) || /print-qr/.test(pr.cls) === false || pr.text.includes('SECRETPASS') || sw.split(' ').some(x => pr.text.includes(x + ' ')) || !pr.text.includes($('fingerprint').textContent) || !/Passphrase used: YES/.test(pr.text)) fails.push('seedqr: PRINT THIS QR sheet (code, fingerprint, no words, no passphrase)');
    w.dispatchEvent(new w.Event('afterprint')); if ($('printQr').textContent !== '' || w.document.body.classList.contains('print-qr')) fails.push('seedqr: print area cleaned up after printing');
    w.printSqGuide();
    if (pr.n !== 2 || !/HAND-COPY GUIDE \(12 words, 25 x 25 squares\)/.test(pr.text) || !/Row 1: /.test(pr.text) || !/Row 25: /.test(pr.text) || /Row 26/.test(pr.text) || pr.text.includes('SECRETPASS') || sw.split(' ').some(x => pr.text.includes(x + ' '))) fails.push('seedqr: PRINT HAND-COPY GUIDE sheet (rows, no words, no passphrase)');
    w.dispatchEvent(new w.Event('afterprint')); conf.n = 0; w.printSqBlank();
    if (pr.n !== 3 || conf.n !== 0 || !/BLANK 25 x 25 GRID FOR SEEDQR/.test(pr.text) || /Row 1: /.test(pr.text)) fails.push('seedqr: PRINT BLANK GRID sheet (no question, no rows)');
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
    w.print = () => {}; w.confirm = () => true; w.alert = () => {};
  } catch (e) { fails.push('seedqr: the probe crashed: ' + e.message); }
  if ($('fpIcon').querySelector('svg')) { /* keep icon until an error */ }
  // passphrase confirmation must block a mismatch
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
  let f; try { f = await probe(w); } catch (e) { return { by: 'end-to-end probe (page error: ' + String(e && e.message).slice(0, 60) + ')' }; }
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
  ['lifehash: icon not cleared on errors', '    clearWatch();\n    clearFpIcons();\n  }\n}', '    clearWatch();\n  }\n}'],
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
  ["seedqr: show button box offered for any length", "(words && [12,24].includes(words.length)) ? \"\" : \"none\"", "(words) ? \"\" : \"none\""],
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
];

if (process.env.MUT_CHECK_TARGETS) { // quick mode: only check that every mutation target occurs exactly once in the page
  let badT = 0; for (const [name, find] of M) { const c = html.split(find).length - 1; if (c !== 1) { badT++; console.log(`target occurs ${c}x: ${name}`); } }
  console.log(badT ? `${badT} bad target(s)` : 'all mutation targets occur exactly once'); process.exit(badT ? 1 : 0);
}
const base = await detect(html);
R.ok(base.by === null, "control: the unmodified file passes the self-test and every probe" + (base.by ? " [" + base.by + "]" : ""));

const survivors = [];
const ONLY = process.env.MUT_ONLY ? new RegExp(process.env.MUT_ONLY) : null; // optional: run only the mutations whose name matches
for (const [name, find, rep, equivalent] of M) {
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
