# Review guide

VOIDFORGE is meant to be read. The security-relevant code is a few hundred lines in `voidforge.html`. Line numbers are approximate (v1.5.1).

| What | Where | Look for |
|---|---|---|
| BIP39 wordlist | line ~372 | Any changed word. The self-test hashes it against the official `english.txt` (`2f5eed53...dbda`); verify that hash yourself. |
| Roll to mnemonic | `rollsToMnemonic` ~576, `entropyToMnemonic` ~489 | Entropy truncation, checksum bits, anything that mixes in other data (time, `Math.random`). |
| Input cleaning | `clean` ~401 | Anything that alters or drops valid input. |
| Fingerprint | `ripemd160` ~508, `eadd`/`emul` ~547, `mnemonicToSeed` ~556, `fingerprintFromSeed` ~563 | Correctness only; it does not affect the seed. Not constant-time (offline use). |
| First receive address | `masterFromSeed`, `ckdPriv`, `bech32Encode`, `firstAddressFromSeed` (search these names) | Display only; it does not affect the seed. Check the derivation path (`m/84'/0'/0'/0/0`: 84, 0, 0 hardened, then 0, 0), the mod-n key addition, and that the bech32 checksum constant is 1 (BIP173). Tested against the published BIP84 vector and two independent libraries. |
| Result display | `setResult`, `hasSeed` | `setResult` is the only place that sets the result area; `hasSeed()` (a flag set only when a real seed is showing) guards SEND TO VERIFY, PRINT and DOWNLOAD so an error message is never treated as a seed. The word grid is display only. |
| Passphrase confirm and tap buttons | `generate`, `buildTapRow` | The two passphrase boxes must match before forging; tap buttons only append to the roll box. |
| Self-test and gate | `runSelfTests` ~597, `gateOk` ~814 | Known-answer vectors are real; failure disables the tool. |
| Outputs | `generate` ~658, `downloadTool` ~788, print/download | Seed or passphrase leaving the page unexpectedly. |
| Network | whole file | `fetch`, `XMLHttpRequest`, `WebSocket`, `sendBeacon`, external `src`/`href`, CSP meta (line 5). |

Tests worth reading too: `tests/oracle.test.mjs` compares the seed math with `@scure` on random inputs, and `tests/mutation.test.mjs` shows which deliberate breaks the in-page self-test catches and which only the CI probe catches.

Independent checks anyone can run: compare with SeedSigner's `tools/mnemonic.py`, or Ian Coleman's BIP39 tool run offline ("Base 10"/"Hex" mode for dice, "Binary" for coin flips).

Known limits: the randomness meter only catches lazy input; the curve code is not constant-time; coin-mode test vectors come from an independent implementation of SeedSigner's method (SeedSigner publishes none); Coldcard is untested; tested in Chromium but not Firefox or Safari.

## Asking for a review (copy and adapt)

> Hi, I wrote VOIDFORGE, a single-file offline dice/coin to BIP39 seed generator (github.com/Random21m/voidforge). It is meant to be read, not trusted. Could you spend about an hour on REVIEW.md's table? Priorities: (1) is the wordlist exactly the official one, (2) does anything besides SHA256 of the typed rolls influence the seed, (3) is there any way the seed or passphrase leaves the page. I would also welcome a second opinion on whether it is worth publishing at all. I will credit you in the changelog if you want, and I will not describe it as audited unless you say I may.
