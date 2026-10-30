<p align="center"><img src="logo.svg" alt="VOIDFORGE logo: a die showing five pips" width="128" height="128"></p>

# VOIDFORGE

An offline, educational tool that turns dice rolls or coin flips into a BIP39 seed phrase (12 or 24 words), then helps you back it up and set up a wallet, including multisig. One HTML file, no dependencies, no network.

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
3. Confirm the green **SELF-TEST PASSED (66/66)** badge and the **NETWORK: OFFLINE** tag. A red notice saying the script is not running means the page did not start; do not use it.
4. Choose 12 or 24 words and Dice or Coin, enter your physical rolls or flips (type, paste, or tap the buttons), and press FORGE SEED. The words appear as a numbered grid. A passphrase, if you want one, goes in "Advanced options".
5. Write the words down, then compare the words and the master fingerprint with a second independent offline tool before trusting real funds.

**Browser testing:** automated tests run in Chromium. v1.7.0, v1.8.0, v1.8.1, v1.9.0, v1.10.0, v1.10.1 and v1.11.0 were checked by hand in Firefox and Safari on a desktop computer (self-test badge, dice buttons, watch-only box, QR codes and, in v1.8.0, the fingerprint picture all worked; v1.5.0 also matched the published dice example). v1.7.1 only added disclaimer text, and v1.8.1 only changed one message and the release process. v1.9.0 added the roll chart. v1.10.0 added the five-address list, the 4-letter view and the check guide. The watch-only QR was scanned into Blue Wallet on a phone and worked (same first receiving address as VOIDFORGE; a zpub import shows no master fingerprint by design, while the descriptor does). The descriptors were imported into Sparrow Wallet, and the fingerprint picture matched what Sparrow shows for four wallets. The maintainer reports that later releases, up to v1.18.0, also work in Firefox and Safari on a desktop computer (reported by hand, without a per-version checklist). Electrum and Nunchuk have not been tested. Please report anything odd in other browsers. The page needs Safari 14 or newer. Phones are not supported.

**Coin flips:** decide which side is 1 and which is 0 (the usual choice is heads = 1, tails = 0), use it for every flip, and keep the exact 1/0 string with your backup. Only the string is hashed, so any consistent choice works, but the mapping cannot be recovered from the words.

- **First 5 addresses and a check guide:** after FORGE the first five receiving addresses are listed (with COPY ALL) and a short guide explains how to compare them in a second wallet app. Comparing five addresses is much stronger than comparing one.
- **First 4 letters view:** a button on the word grid shows only the first four letters of each word (every BIP39 word is unique by them), for stamping metal backups. Display only; it does not change the stored words.
- **Roll chart:** a small bar chart under the roll box shows how many times each face (or coin side) has come up. It is for your eyes only and does not change the seed or the randomness check, which still cannot prove your dice or coin are fair.
- **Taproot addresses:** the first five Taproot (BIP86, `bc1p...`) receiving addresses are also listed, for checking in wallets that use Taproot. The zpub, descriptors and QR codes still describe the SegWit wallet.
- **Printable backup sheet:** PRINT SEED gives a two-column numbered sheet with the fingerprint, first address and space for notes (the passphrase is never printed).
- **Compare a key or descriptor:** in CHECK YOUR BACKUP the backup box accepts a zpub/xpub, a wpkh descriptor or a Taproot address from a wallet app and says MATCH or NO MATCH against your words (public keys only; it cannot show the words).
- **Is this address yours?** Paste a bc1q or bc1p address; VOIDFORGE searches the receive and change chains of your words (and passphrase) and tells you the address number. Searches 50 per chain per press.
- **SeedQR input:** the words box in CHECK YOUR BACKUP also reads a SeedSigner SeedQR digit string or CompactSeedQR hex and shows the words (typed in; no camera).
- **Child seed (BIP85):** derives a new seed phrase from your parent words and passphrase (12, 18 or 24 words, any index) for a separate wallet. Shown on screen only. The parent plus the word count and index recreate it.
- **Fingerprint picture:** a small LifeHash picture next to the master fingerprint (the same one Sparrow Wallet shows), for a quick visual match.
- **Find the last word:** in CHECK A BACKUP, type all but the last word of a seed (11, 14, 17, 20 or 23 words) and the tool lists the words that make the checksum valid. Display only.
- **Transaction (PSBT) inspector:** paste or choose a partly signed Bitcoin transaction to see its inputs, outputs, addresses and fee before you sign it on a hardware wallet. Read only: it never signs and never uses your seed.
- **Testnet and multisig cosigner keys:** a Network menu switches the watch-only export and the address finder to testnet, and the Multisig cosigner types give the BIP48 key and origin for a multisig wallet (Sparrow, Specter, Nunchuk, Electrum). Public keys only.
- **Address types and accounts:** the watch-only export can be switched to Taproot, Nested SegWit (ypub) or Legacy, with any account number, and "Is this address yours?" finds bc1q, bc1p, 3... and 1... addresses for the chosen account.
- **Paper backup as a SeedQR:** after FORGE (12 or 24 words), SHOW SEEDQR or SHOW COMPACTSEEDQR displays the code on screen. HAND-COPY GUIDE walks through it in 7x7 blocks with row/column numbers and a mini-map so you can copy it with a pen or pencil onto grid paper, like SeedSigner. You can also print the QR, the guide or a blank grid (printing asks for confirmation, since it sends your seed to a printer). Verify a copy by scanning it into a SeedSigner and comparing the fingerprint.
- **How your seed was made:** after FORGE, an optional SECRET-marked view walks through five steps from your rolls to the words (SHA-256, raw entropy, checksum, 11-bit pieces, word numbers) and checks itself against the real words.
- **Printed backup sheet:** PRINT SEED makes a clean sheet with numbered boxes for the words, the fingerprint, first address and fields to fill in (never the passphrase).
- **Browser safety checklist:** in ABOUT & DOCS, eight short habits with the reason for each (go offline first, a clean browser window, translation, clipboard history, print and PDF copies, downloads, restarting afterwards).
- **Guide me, plain-word tips, larger text:** the GUIDE ME button (top left) walks a first-time user through making a seed one screen at a time (choose, roll, optional passphrase, FORGE and write down, check and back up). Each step says why, and NEXT stays locked until the step is done. Underlined words (passphrase, fingerprint, zpub, descriptor, watch-only) explain themselves on hover, tap or keyboard focus. TEXT A+ enlarges everything. These are display helpers only: they do not change any seed, key or address.
- **Rolling-dice logo and a demo of how rolls scramble:** the logo is three dice that tumble in and roll again when tapped (still when a device asks for reduced motion). An optional switch under the roll counter, "Watch the words change (demo only)", shows demo words that change completely with every roll, so you can see why one wrong roll gives a different wallet. The demo words are made with a demo tag, so they are never your real seed; they are labelled NOT YOUR SEED, wiped on switch-off, clear or forge, and never printed or saved.
- **Multisig setup (M-of-N):** the MULTISIG WALLET card guides you through a 2-of-3 (or any M-of-N up to 7 keys) one key at a time. Make each seed with the normal tools, back it up, then ADD THIS KEY: only the public key is kept and the seed is wiped from the page. Public keys from other devices can be pasted in (private keys, seed words, duplicates, wrong network or wrong path are refused). The result is a `wsh(sortedmulti(...))` or `sh(wsh(sortedmulti(...)))` descriptor as text, QR code and a printable recovery sheet with no seeds, plus the first addresses to compare in your wallet. Making all keys on one device works but is warned against.
- **Word draw (physical word tiles):** if you pick your words by hand from tiles (such as SeedSigner's open-source SeedPills), type the 11 (or 23) words you drew, with the first four letters of each being enough, and the 7 (or 3) coin flips. VOIDFORGE works out the last word with the standard BIP39 checksum and shows each step. Nothing is hashed, repeated words are accepted because every tile goes back in the bag, and the flips are never filled in for you. The result works in any BIP39 wallet and uses the same fingerprint, address, SeedQR, print and watch-only tools as the dice method.
- **Watch-only export:** after FORGE, copy the wallet's public key (zpub) or descriptor into a watch-only wallet app to see addresses and balance without the seed. Public keys only; it cannot spend. SHOW QR draws it as a QR code on screen for scanning.
- Shows the master fingerprint **and the first native SegWit (BIP84) receive address** so you can cross-check with a wallet; asks you to type any passphrase twice; tap buttons for dice 1-6 and coin 1/0. VERIFY can check a phrase with and without a passphrase and tell you whether a fingerprint or address from your backup matches with a passphrase, without one, or neither.
- Guides: [RECOVERY.md](RECOVERY.md) (what to back up, how to restore) and [SECURITY.md](SECURITY.md) (reporting, known limits).
- Method: `SHA256(rolls or flips as text)` → BIP39. Matches SeedSigner's published dice examples; coin mode uses SeedSigner's method (1/0 string).
- Tests: `npm ci && npm test` (unit tests, differential tests against `@scure/bip39` and `@scure/bip32` plus descriptor fixtures from `embit`, QR fixtures from `qrcode` and the `lifehash` package for the fingerprint picture, and mutation tests that break the code on purpose to prove the safety net catches it)
- Want to review it? See [REVIEW.md](REVIEW.md).
- Do not host this as a web page (no GitHub Pages). Download-only.
- License: MIT
