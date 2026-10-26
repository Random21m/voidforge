// Differential test: VOIDFORGE's seed math against INDEPENDENT implementations
// (@scure/bip39 and @scure/bip32), on random inputs. The expected values never
// come from the code under test. Run: npm ci && node tests/oracle.test.mjs
import nc from 'node:crypto';
import { entropyToMnemonic, mnemonicToSeedSync, validateMnemonic } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english';
import { HDKey } from '@scure/bip32';
import { bech32 } from '@scure/base';
import { ripemd160 } from '@noble/hashes/ripemd160';
import { sha256 } from '@noble/hashes/sha256';
import { loadPage, ready, readHtml, rnd, makeReporter } from './harness.mjs';

const R = makeReporter();
const w = await ready(loadPage(readHtml()));
const sha = (s) => new Uint8Array(nc.createHash('sha256').update(s).digest());
const fpOracle = (mn, pw) => HDKey.fromMasterSeed(mnemonicToSeedSync(mn, pw)).fingerprint.toString(16).padStart(8, '0');

const addrOracle = (mn, pw) => {
  const k = HDKey.fromMasterSeed(mnemonicToSeedSync(mn, pw)).derive("m/84'/0'/0'/0/0");
  return bech32.encode('bc', [0, ...bech32.toWords(ripemd160(sha256(k.publicKey)))]);
};

// Passphrases chosen to stress NFKD normalisation and odd input.
const PASS = ['', 'TREZOR', 'correct horse battery staple', 'pässwörd', 'ｆｕｌｌｗｉｄｔｈ', '日本語パスワード', '  spaces  ', 'a'.repeat(200), 'é', 'é', 'ﬁ'];

R.ok(w.document.getElementById('selfTestBadge').textContent.includes('PASSED'), 'page self-test passes before the oracle run');

// 1. dice and coin rolls -> mnemonic and master fingerprint
let bad = 0, n = 0;
for (const [kind, len, bytes, words] of [['dice', 50, 16, 12], ['dice', 99, 32, 24], ['coin', 128, 16, 12], ['coin', 256, 32, 24]]) {
  for (let i = 0; i < 75; i++) {
    const rolls = rnd(len, kind === 'dice' ? 6 : 2), pw = PASS[nc.randomInt(PASS.length)];
    const want = entropyToMnemonic(sha(rolls).slice(0, bytes), wordlist);
    const got = await w.rollsToMnemonic(rolls, words);
    const gotFp = await w.mnemonicFingerprint(got, pw);
    n++;
    if (got !== want || gotFp !== fpOracle(want, pw)) { bad++; console.log('MISMATCH', kind, words, JSON.stringify(pw), rolls); }
  }
}
R.ok(bad === 0, `${n} random dice/coin inputs: mnemonic and fingerprint match @scure (${bad} mismatches)`);

// 2. fingerprints for every BIP39 length (VERIFY accepts all five)
bad = 0; n = 0;
for (const bytes of [16, 20, 24, 28, 32]) for (let i = 0; i < 20; i++) {
  const mn = entropyToMnemonic(new Uint8Array(nc.randomBytes(bytes)), wordlist), pw = PASS[nc.randomInt(PASS.length)];
  const r = await w.checkPhrase(mn);
  n++;
  if (!r.ok || (await w.mnemonicFingerprint(r.mnemonic, pw)) !== fpOracle(mn, pw)) { bad++; console.log('MISMATCH len', bytes, mn); }
}
R.ok(bad === 0, `${n} random 12/15/18/21/24-word phrases: accepted, fingerprints match (${bad} mismatches)`);

// 2b. first receive address (BIP84 m/84'/0'/0'/0/0) against @scure/bip32 + @scure/base + @noble/hashes
bad = 0; n = 0;
for (const bytes of [16, 20, 24, 28, 32]) for (let i = 0; i < 12; i++) {
  const mn = entropyToMnemonic(new Uint8Array(nc.randomBytes(bytes)), wordlist), pw = PASS[nc.randomInt(PASS.length)];
  n++;
  if ((await w.mnemonicFirstAddress(mn, pw)) !== addrOracle(mn, pw)) { bad++; console.log('ADDR MISMATCH', bytes, JSON.stringify(pw), mn); }
}
R.ok(bad === 0, `${n} random phrases (all lengths, odd passphrases): first receive address matches the independent libraries (${bad} mismatches)`);

// 3. phrase checker agrees with @scure on valid, corrupted, and random phrases
bad = 0; n = 0;
for (let i = 0; i < 300; i++) {
  const base = entropyToMnemonic(new Uint8Array(nc.randomBytes([16, 20, 24, 28, 32][nc.randomInt(5)])), wordlist).split(' ');
  let words = base.slice();
  const mode = nc.randomInt(3);
  if (mode === 1) words[nc.randomInt(words.length)] = wordlist[nc.randomInt(2048)];             // swap one word
  if (mode === 2) words = Array.from({ length: [12, 15, 18, 21, 24][nc.randomInt(5)] }, () => wordlist[nc.randomInt(2048)]); // random words
  const phrase = words.join(' ');
  n++;
  if ((await w.checkPhrase(phrase)).ok !== validateMnemonic(phrase, wordlist)) { bad++; console.log('DISAGREE', phrase); }
}
R.ok(bad === 0, `${n} valid/corrupted/random phrases: checker agrees with @scure (${bad} disagreements)`);

// 4. the same, end to end through the UI path (clean -> generate -> fingerprint)
bad = 0;
const $ = (id) => w.document.getElementById(id);
for (let i = 0; i < 6; i++) {
  const coin = i % 2 === 1, len = coin ? (i < 3 ? 128 : 256) : (i < 3 ? 50 : 99), words = len === 50 || len === 128 ? 12 : 24;
  const radio = w.document.querySelector(`input[name=mode][value=${coin ? 'coin' : 'dice'}]`); radio.checked = true; radio.onchange();
  const wr = w.document.querySelector(`input[name=words][value="${words}"]`); wr.checked = true; wr.onchange();
  const rolls = rnd(len, coin ? 2 : 6); $('rolls').value = rolls; $('rolls').oninput();
  const pw = PASS[nc.randomInt(PASS.length)]; $('passphrase').value = pw; $('passphrase2').value = pw;
  await w.generate();
  const want = entropyToMnemonic(sha(rolls).slice(0, words === 12 ? 16 : 32), wordlist);
  const fp = ($('fingerprint').textContent.match(/: ([0-9a-f]{8})/) || [])[1];
  const ad = ($('address').textContent.match(/: (bc1[0-9a-z]+)/) || [])[1];
  if ($('genResult').textContent.split('\n')[0] !== want || fp !== fpOracle(want, pw) || ad !== addrOracle(want, pw)) { bad++; console.log('UI MISMATCH', coin, words); }
}
R.ok(bad === 0, `6 end-to-end UI runs (words, fingerprint, address) match the independent libraries (${bad} mismatches)`);

R.done('oracle');
