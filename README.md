<p align="center"><img src="logo.svg" alt="VOIDFORGE logo: a die showing five pips" width="128" height="128"></p>

# VOIDFORGE

Offline dice- and coin-based BIP39 seed phrase generator (12 or 24 words). One HTML file, no dependencies, no network.

<p align="center"><a href="https://github.com/Random21m/voidforge/releases/latest"><b>&#11015; Download the latest release</b></a><br>
Get <code>voidforge.html</code> and <code>SHA256SUMS</code> from the release page, check the hash, then copy the file to a USB stick for your offline computer. This is the only place to download it; there is no hosted web version, by design.</p>

> **Not independently audited.** For serious amounts, generate on dedicated hardware (SeedSigner, Coldcard) and use VOIDFORGE to cross-check the words and fingerprint.

**Use it only on an offline (air-gapped) computer.** Download `voidforge.html` from a release (see [RELEASING.md](RELEASING.md)), check its SHA256, copy it to a USB stick, open it, and confirm the green "SELF-TEST PASSED" badge. Full documentation is inside the file (ABOUT & DOCS card).

## Quick start

1. Download `voidforge.html` from the [latest release](../../releases/latest) and check it: `sha256sum -c SHA256SUMS`.
2. Copy it to a USB stick and open it in a desktop browser (Safari 14+, Chrome or Firefox) on an **offline computer**. Do not use a phone: phones and file previews often will not run the page, and a phone is the wrong place for a seed anyway.
3. Confirm the green **SELF-TEST PASSED (29/29)** badge and the **NETWORK: OFFLINE** tag. A red notice saying the script is not running means the page did not start; do not use it.
4. Choose 12 or 24 words and Dice or Coin, enter your physical rolls or flips (type, paste, or tap the buttons), and press FORGE SEED. The words appear as a numbered grid. A passphrase, if you want one, goes in "Advanced options".
5. Write the words down, then compare the words and the master fingerprint with a second independent offline tool before trusting real funds.

**Browser testing:** automated tests run in Chromium, and the current release (v1.5.0) was checked by hand in Firefox and Safari on a desktop computer (self-test badge, layout, and the published dice example all matched). The page needs Safari 14 or newer. Phones are not supported.

**Coin flips:** decide which side is 1 and which is 0 (the usual choice is heads = 1, tails = 0), use it for every flip, and keep the exact 1/0 string with your backup. Only the string is hashed, so any consistent choice works, but the mapping cannot be recovered from the words.

- Shows the master fingerprint **and the first native SegWit (BIP84) receive address** so you can cross-check with a wallet; asks you to type any passphrase twice; tap buttons for dice 1-6 and coin 1/0. VERIFY can check a phrase with and without a passphrase and tell you whether a fingerprint or address from your backup matches with a passphrase, without one, or neither.
- Guides: [RECOVERY.md](RECOVERY.md) (what to back up, how to restore) and [SECURITY.md](SECURITY.md) (reporting, known limits).
- Method: `SHA256(rolls or flips as text)` → BIP39. Matches SeedSigner's published dice examples; coin mode uses SeedSigner's method (1/0 string).
- Tests: `npm ci && npm test` (unit tests, differential tests against `@scure/bip39` and `@scure/bip32`, and mutation tests that break the code on purpose to prove the safety net catches it)
- Want to review it? See [REVIEW.md](REVIEW.md).
- Do not host this as a web page (no GitHub Pages). Download-only.
- License: MIT
