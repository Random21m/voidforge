# VOIDFORGE

**Offline dice-based BIP39 Bitcoin seed phrase generator.**

A single-file HTML tool that turns physical dice rolls into a standard BIP39 mnemonic. Runs completely offline in any modern browser. Designed for air-gapped use.

## Features

- Generate 12-word (50 rolls) or 24-word (99 rolls) BIP39 seeds
- Verify any BIP39 seed phrase (word validity + checksum)
- Cyberpunk UI with custom SVG logo
- SeedSigner / Coldcard compatible dice method (SHA256 of the roll string)
- Zero dependencies — pure HTML + JavaScript
- Works from a USB stick on Windows, macOS, or Linux

## How to use

1. Download or clone this repository.
2. Copy `voidforge.html` to a USB stick (or open it locally).
3. Double-click the file to open it in your browser.
4. Enter your physical dice rolls (digits 1–6) and generate or verify a seed.

No internet connection is required after you have the file.

## Method

```
SHA256(roll_string) → entropy bytes → BIP39 mnemonic + checksum
```

- 50 rolls → first 16 bytes of the hash → 12-word seed (128-bit)
- 99 rolls → full 32-byte hash → 24-word seed (256-bit)

This matches the dice-only generation used by SeedSigner and Coldcard.

## Security

- **For real funds**: run this only on an air-gapped computer.
- Never type a real seed phrase into a phone, website, or internet-connected machine.
- Always cross-check generated phrases with a second independent offline tool (e.g. the offline Ian Coleman BIP39 tool or Sparrow Wallet).
- This is an educational / verification tool. Use at your own risk.

## License

MIT — see [LICENSE](LICENSE) if present, or treat as MIT.

---

Built for people who want high-entropy, verifiable, offline seed generation.
