# VOIDFORGE

**Offline dice- and coin-based BIP39 Bitcoin seed phrase generator.**

A single-file HTML tool that turns physical dice rolls or coin flips into a standard BIP39 mnemonic. Runs completely offline in any modern browser. Designed for air-gapped use.

## ⚠️ CRITICAL SECURITY WARNING

**ONLY USE THIS TOOL OFFLINE.**

- Never open this file in a browser on a computer that is connected to the internet if you are generating a seed for real funds.
- Never type a real seed phrase into any phone, website, or online tool.
- For any seed that will hold Bitcoin, use an air-gapped computer (a machine that has never been and will never be connected to the internet).
- Always cross-check the result with a second independent offline tool before trusting it with real funds.
- This is an educational and verification tool. Use at your own risk.

## Features

- Generate 12/15/18/21/24-word BIP39 seeds
- **Dice mode** (1–6) or **Coin mode** (H/T)
- Entropy fairness feedback
- Visual dice faces / recent rolls
- Optional note and roll history
- Verify any BIP39 seed phrase (word validity + checksum)
- Master fingerprint display (verify offline)
- Download for USB
- Dark/light mode
- Cyberpunk UI with custom SVG logo
- Zero dependencies — pure HTML + JavaScript
- Works from a USB stick on Windows, macOS, or Linux

## How to use

1. Download or clone this repository.
2. Copy `voidforge.html` (or `index.html`) to a USB stick.
3. On an **air-gapped** computer, double-click the file to open it in your browser.
4. Choose **Dice** or **Coin** mode.
5. Enter your physical rolls (digits 1–6) or flips (H/T) and generate or verify a seed.

No internet connection is required after you have the file.

## Method

```
SHA256(input_string) → entropy bytes → BIP39 mnemonic + checksum
```

**Dice mode**
- 50 rolls → 12-word seed
- 99 rolls → 24-word seed

**Coin mode**
- 128 flips → 12-word seed
- 256 flips → 24-word seed

This matches the dice-only generation approach used by SeedSigner and Coldcard (SHA256 of the raw input string).

## License

MIT — see [LICENSE](LICENSE).

---

Built for people who want high-entropy, verifiable, offline seed generation.
