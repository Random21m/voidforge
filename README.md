# VOIDFORGE

**Offline dice-based BIP39 Bitcoin seed phrase generator.**

A single-file HTML tool that turns physical dice rolls into a standard BIP39 mnemonic. Runs completely offline in any modern browser. Designed for air-gapped use.

## ⚠️ CRITICAL SECURITY WARNING

**ONLY USE THIS TOOL OFFLINE.**

- Never open this file in a browser on a computer that is connected to the internet if you are generating a seed for real funds.
- Never type a real seed phrase into any phone, website, or online tool.
- For any seed that will hold Bitcoin, use an air-gapped computer (a machine that has never been and will never be connected to the internet).
- Always cross-check the result with a second independent offline tool before trusting it with real funds.
- This is an educational and verification tool. Use at your own risk.

## Features

- Generate 12-word (50 rolls) or 24-word (99 rolls) BIP39 seeds
- Verify any BIP39 seed phrase (word validity + checksum)
- Cyberpunk UI with custom SVG logo
- SeedSigner / Coldcard compatible dice method (SHA256 of the roll string)
- Zero dependencies — pure HTML + JavaScript
- Works from a USB stick on Windows, macOS, or Linux

## How to use

1. Download or clone this repository.
2. Copy `voidforge.html` (or `index.html`) to a USB stick.
3. On an **air-gapped** computer, double-click the file to open it in your browser.
4. Enter your physical dice rolls (digits 1–6) and generate or verify a seed.

No internet connection is required after you have the file.

## Method

```
SHA256(roll_string) → entropy bytes → BIP39 mnemonic + checksum
```

- 50 rolls → first 16 bytes of the hash → 12-word seed (128-bit)
- 99 rolls → full 32-byte hash → 24-word seed (256-bit)

This matches the dice-only generation used by SeedSigner and Coldcard.

## License

MIT — see [LICENSE](LICENSE).

---

Built for people who want high-entropy, verifiable, offline seed generation.
