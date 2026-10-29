# Backup and recovery guide

A seed is only as safe as your backup. This page covers what to keep and how to restore. It is guidance, not a guarantee: test your backup before trusting real funds to it.

## What to write down

1. **The words** (12 or 24), in order, on paper or metal. Number them.
2. **Your passphrase,** if you used one, kept **separately** from the words. Without it you get a different, empty wallet; with a lost passphrase the funds are unrecoverable.
3. **The master fingerprint and first receive address** shown by VOIDFORGE (they are not secret). They let you confirm later that a restore produced the same wallet.
4. **The exact roll or flip string** (optional but useful). For coins, also write which side you counted as 1 and which as 0 (the usual choice is heads = 1, tails = 0). The words alone do not tell you this, and with the string you can rebuild the same seed.

Never store the words as a photo, text, email, cloud note or password-manager entry.

## Check the backup before you rely on it

1. On the same offline computer, press **FORGE SEED** and write everything down (the printout and download say plainly whether a passphrase was used). Then use **VERIFY**: type the words back from your paper, add the passphrase if you used one, and paste the fingerprint or first address you wrote down into the last box. VERIFY says **MATCH (with passphrase)**, **MATCH (without passphrase)**, or **NO MATCH**. Matching the first address is the stronger check. VERIFY never displays or saves the passphrase.
2. Compare the words, fingerprint and the **first five addresses** (or paste the wallet app's zpub, descriptor or any address into CHECK YOUR BACKUP; SegWit, plus Taproot if your wallet uses it; shown under the first address after FORGE; there is also a short guide on the page) with a **second independent tool** (for example a hardware wallet or SeedSigner set up with the same words, or a wallet that can import a seed).
3. Import the words into a wallet that supports BIP39 and BIP84 (native SegWit, "bc1q" addresses). Its first receive address should equal the one VOIDFORGE showed. If you used a passphrase, enter it exactly as written in the wallet's passphrase field.
4. Only then move real funds, and start with a small amount.

## Add the wallet to a watch-only app (optional)

A watch-only wallet shows this wallet's addresses and balance and can create unsigned transactions, but it holds no secret keys and cannot spend. VOIDFORGE shows what to paste in the **Watch-only wallet** box after FORGE (open it by pressing its title). Because it stays on the screen only, write it down or copy it on the offline computer and carry it to your other device on a USB stick or as a QR code made offline.

- **Sparrow:** New Wallet, then Airgapped Hardware Wallet / Watch Only (or "Descriptor" under Script Type), paste the descriptor.
- **Electrum:** New wallet, Standard wallet, "Use a master key", paste the zpub.
- **Blue Wallet:** Add wallet, Import wallet, paste the zpub (it becomes watch-only).
- **Nunchuk / Bitcoin Core:** import the descriptor (use the change descriptor too if the app asks for it separately).
- **QR codes:** press SHOW QR under the zpub or descriptor and scan the screen with the app's camera/scan button. Scanning support differs by app (zpub and descriptor QR codes are widely accepted, but not by every app). If a scan fails, increase the screen brightness, keep the code large and still, or use COPY instead.

**zpub or descriptor?** Both give the same addresses. A zpub has no field for the wallet's master fingerprint, so an app that imports a zpub may show no fingerprint; the descriptor includes it (the 8 characters in square brackets, the same as VOIDFORGE's master fingerprint). If you will later sign with a hardware wallet or another offline signer, import the descriptor so the fingerprint is recorded.

Afterwards check that the app's first receiving address equals the **First receive address** VOIDFORGE showed. If you used a passphrase, the export is only for that passphrase. Treat the zpub like private financial information: anyone who has it can see all your addresses and balance, though they cannot spend. Spending later needs the seed words, for example on a hardware wallet or a restored wallet.

## Restoring

- Choose "restore wallet" / "import seed" in a BIP39-compatible wallet and enter the words (and the passphrase, if any).
- Make sure the wallet uses the **native SegWit (BIP84)** address type to see the same addresses VOIDFORGE showed. Other address types (legacy, nested SegWit, Taproot) come from different paths and show different addresses for the same seed; that is normal.
- Fingerprints are the same for all wallet types, so a matching master fingerprint plus a matching first address means the restore is right.

## Common problems

- **Not sure whether you used a passphrase:** the words cannot tell you. Enter your recorded fingerprint or address in VERIFY and try with and without your passphrase; the MATCH line tells you which one reproduces it.
- **Different addresses after restore:** wrong address type, wrong passphrase, or one wrong word that still passes the checksum. Recheck each word, then the passphrase.
- **Passphrase typed with different characters:** capital letters, spaces and accents all matter. VOIDFORGE's two passphrase boxes must match exactly before it will forge.
- **Words in the wrong order:** the order is part of the seed.

## Child seeds (BIP85)

A child seed made with the Child seed (BIP85) tool is not stored anywhere. To get it back you need the parent words, the parent passphrase if one was used, the word count and the index. Write the word count and index down with the parent backup. Anyone who has the parent can recreate every child, and losing the parent loses every child.

## Multisig wallets (v1.20.0)

A multisig wallet made with VOIDFORGE needs two things to be recovered: **M of the N seeds**, and the **descriptor** (or the printed recovery sheet, or all N public keys with their fingerprints and `48h/0h/0h/2h` paths). The descriptor holds no secrets.

1. In Sparrow choose *File > New Wallet > Multi Signature*, or import the descriptor text directly (*New Wallet > Descriptor*). In Nunchuk or Bitcoin Core use *import descriptor*.
2. Check that the first receiving addresses match the ones on your recovery sheet before you send anything.
3. To spend, each signer uses its own seed in a signing device or wallet; VOIDFORGE does not sign.

Key origin used: `m/48'/0'/<account>'/2'` for native SegWit (P2WSH) or `.../1'` for nested SegWit (P2SH-P2WSH); testnet uses `1'` instead of `0'`.
