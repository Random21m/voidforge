<p align="center"><img src="logo.svg" alt="VOIDFORGE logo: a die showing five pips" width="128" height="128"></p>

# VOIDFORGE

Offline dice- and coin-based BIP39 seed phrase generator (12 or 24 words). One HTML file, no dependencies, no network.

<p align="center"><a href="https://youtu.be/ALpbUXv1AyE">&#9654; Watch the tutorial video</a></p>

<p align="center"><a href="https://github.com/Random21m/voidforge/releases/latest"><b>&#11015; Download the latest release</b></a><br>
Get <code>voidforge.html</code> and <code>SHA256SUMS</code> from the release page, check the hash, then copy the file to a USB stick for your offline computer. This is the only place to download it; there is no hosted web version, by design.</p>


> **Not independently audited.** For serious amounts, generate on dedicated hardware (SeedSigner, Coldcard) and use VOIDFORGE to cross-check the words and fingerprint.

## Disclaimer: please read

VOIDFORGE is free software provided **"as is", without warranty of any kind** (see [LICENSE](LICENSE)). You are solely responsible for your own funds, your backups and how you use it. The author is not liable for any loss.

- **Not independently audited.** It can contain bugs. It is not a substitute for a hardware wallet. For serious amounts, use dedicated hardware (SeedSigner, Coldcard, etc.) and use VOIDFORGE only to cross-check.
- **Lost words or passphrase = lost funds.** Nobody, including the author, can recover them. Write the words (and any passphrase, kept separately) on paper and store copies safely.
- **Test before you trust it.** Check the release SHA256, run it on an offline computer, restore the wallet from your written backup in a second tool, and move a **small** amount first. See [RECOVERY.md](RECOVERY.md).
- **Your randomness is your responsibility.** Weak, biased or reused dice and coin results make a weak wallet. The built-in check is advisory only.
- **Never use it on a networked, shared or untrusted computer,** and never type or photograph your real seed words on a phone or online service.
- This is not financial, legal or security advice. If someone else tells you they used it, they used it at their own risk.

**Use it only on an offline (air-gapped) computer.** Download `voidforge.html` from a release (see [RELEASING.md](RELEASING.md)), check its SHA256, copy it to a USB stick, open it, and confirm the green "SELF-TEST PASSED" badge. Full documentation is inside the file (ABOUT & DOCS card).

## Quick start

1. Download `voidforge.html` from the [latest release](../../releases/latest) and check it: `sha256sum -c SHA256SUMS`.
2. Copy it to a USB stick and open it in a desktop browser (Safari 14+, Chrome or Firefox) on an **offline computer**. Do not use a phone: phones and file previews often will not run the page, and a phone is the wrong place for a seed anyway.
3. Confirm the green **SELF-TEST PASSED (34/34)** badge and the **NETWORK: OFFLINE** tag. A red notice saying the script is not running means the page did not start; do not use it.
4. Choose 12 or 24 words and Dice or Coin, enter your physical rolls or flips (type, paste, or tap the buttons), and press FORGE SEED. The words appear as a numbered grid. A passphrase, if you want one, goes in "Advanced options".
5. Write the words down, then compare the words and the master fingerprint with a second independent offline tool before trusting real funds.

**Browser testing:** automated tests run in Chromium. v1.7.0, v1.8.0, v1.8.1 and v1.9.0 were checked by hand in Firefox and Safari on a desktop computer (self-test badge, dice buttons, watch-only box, QR codes and, in v1.8.0, the fingerprint picture all worked; v1.5.0 also matched the published dice example). v1.7.1 only added disclaimer text, and v1.8.1 only changed one message and the release process. v1.9.0 added the roll chart. The watch-only QR was scanned into Blue Wallet on a phone and worked (same first receiving address as VOIDFORGE; a zpub import shows no master fingerprint by design, while the descriptor does). The descriptors were imported into Sparrow Wallet, and the fingerprint picture matched what Sparrow shows for four wallets. Electrum and Nunchuk have not been tested. Please report anything odd in other browsers. The page needs Safari 14 or newer. Phones are not supported.

**Coin flips:** decide which side is 1 and which is 0 (the usual choice is heads = 1, tails = 0), use it for every flip, and keep the exact 1/0 string with your backup. Only the string is hashed, so any consistent choice works, but the mapping cannot be recovered from the words.

- **Roll chart:** a small bar chart under the roll box shows how many times each face (or coin side) has come up. It is for your eyes only and does not change the seed or the randomness check, which still cannot prove your dice or coin are fair.
- **Fingerprint picture:** a small LifeHash picture next to the master fingerprint (the same one Sparrow Wallet shows), for a quick visual match.
- **Watch-only export:** after FORGE, copy the wallet's public key (zpub) or descriptor into a watch-only wallet app to see addresses and balance without the seed. Public keys only; it cannot spend. SHOW QR draws it as a QR code on screen for scanning.
- Shows the master fingerprint **and the first native SegWit (BIP84) receive address** so you can cross-check with a wallet; asks you to type any passphrase twice; tap buttons for dice 1-6 and coin 1/0. VERIFY can check a phrase with and without a passphrase and tell you whether a fingerprint or address from your backup matches with a passphrase, without one, or neither.
- Guides: [RECOVERY.md](RECOVERY.md) (what to back up, how to restore) and [SECURITY.md](SECURITY.md) (reporting, known limits).
- Method: `SHA256(rolls or flips as text)` → BIP39. Matches SeedSigner's published dice examples; coin mode uses SeedSigner's method (1/0 string).
- Tests: `npm ci && npm test` (unit tests, differential tests against `@scure/bip39` and `@scure/bip32` plus descriptor fixtures from `embit`, QR fixtures from `qrcode` and the `lifehash` package for the fingerprint picture, and mutation tests that break the code on purpose to prove the safety net catches it)
- Want to review it? See [REVIEW.md](REVIEW.md).
- Do not host this as a web page (no GitHub Pages). Download-only.
- License: MIT
