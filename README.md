<p align="center"><img src="logo.svg" alt="VOIDFORGE logo: a die showing five pips" width="128" height="128"></p>

# VOIDFORGE

Offline dice- and coin-based BIP39 seed phrase generator (12 or 24 words). One HTML file, no dependencies, no network.

> **Not independently audited.** For serious amounts, generate on dedicated hardware (SeedSigner, Coldcard) and use VOIDFORGE to cross-check the words and fingerprint.

**Use it only on an offline (air-gapped) computer.** Download `voidforge.html` from a release (see [RELEASING.md](RELEASING.md)), check its SHA256, copy it to a USB stick, open it, and confirm the green "SELF-TEST PASSED" badge. Full documentation is inside the file (ABOUT & DOCS card).

- Method: `SHA256(rolls or flips as text)` → BIP39. Matches SeedSigner's published dice examples; coin mode uses SeedSigner's method (1/0 string).
- Tests: `npm install jsdom && node tests/test.js`
- Want to review it? See [REVIEW.md](REVIEW.md).
- Do not host this as a web page (no GitHub Pages). Download-only.
- License: MIT
