# Backup and recovery guide

A seed is only as safe as your backup. This page covers what to keep and how to restore. It is guidance, not a guarantee: test your backup before trusting real funds to it.

## What to write down

1. **The words** (12 or 24), in order, on paper or metal. Number them.
2. **Your passphrase,** if you used one, kept **separately** from the words. Without it you get a different, empty wallet; with a lost passphrase the funds are unrecoverable.
3. **The master fingerprint and first receive address** shown by VOIDFORGE (they are not secret). They let you confirm later that a restore produced the same wallet.
4. **The exact roll or flip string** (optional but useful). For coins, also write which side you counted as 1 and which as 0 (the usual choice is heads = 1, tails = 0). The words alone do not tell you this, and with the string you can rebuild the same seed.

Never store the words as a photo, text, email, cloud note or password-manager entry.

## Check the backup before you rely on it

1. On the same offline computer, press **FORGE SEED**, write everything down, then use **VERIFY** and type the words back from your paper. It should say valid and show the same fingerprint and address as FORGE. If you used a passphrase, also type it into VERIFY's passphrase box: the "With passphrase" line must match what FORGE showed (the "Without passphrase" line will differ, which is expected). VERIFY never displays or saves the passphrase.
2. Compare the words, fingerprint and first address with a **second independent tool** (for example a hardware wallet or SeedSigner set up with the same words, or a wallet that can import a seed).
3. Import the words into a wallet that supports BIP39 and BIP84 (native SegWit, "bc1q" addresses). Its first receive address should equal the one VOIDFORGE showed. If you used a passphrase, enter it exactly as written in the wallet's passphrase field.
4. Only then move real funds, and start with a small amount.

## Restoring

- Choose "restore wallet" / "import seed" in a BIP39-compatible wallet and enter the words (and the passphrase, if any).
- Make sure the wallet uses the **native SegWit (BIP84)** address type to see the same addresses VOIDFORGE showed. Other address types (legacy, nested SegWit, Taproot) come from different paths and show different addresses for the same seed; that is normal.
- Fingerprints are the same for all wallet types, so a matching master fingerprint plus a matching first address means the restore is right.

## Common problems

- **Different addresses after restore:** wrong address type, wrong passphrase, or one wrong word that still passes the checksum. Recheck each word, then the passphrase.
- **Passphrase typed with different characters:** capital letters, spaces and accents all matter. VOIDFORGE's two passphrase boxes must match exactly before it will forge.
- **Words in the wrong order:** the order is part of the seed.
