# Security

## Status

VOIDFORGE is **not independently audited**. It is a single HTML file you can read, with automated tests (known-answer vectors, differential tests against independent libraries, and tests that deliberately break the code). That raises confidence; it is not a substitute for an audit. For large amounts, generate on dedicated hardware (SeedSigner, Coldcard, etc.) and use VOIDFORGE only to cross-check.

## Reporting a vulnerability

Please report privately, not in a public issue:

1. On GitHub, open the repository's **Security** tab and choose **Report a vulnerability** (private advisory), or
2. If that is unavailable, open an issue that says only "security report, please contact me" and **no details**; the maintainer will arrange a private channel.

Please include the version (shown at the bottom of the page), the browser, and steps to reproduce. Reports of anything that could leak a seed, passphrase or rolls, produce a wrong seed or address, or weaken the offline guarantees are the most important.

## What is in scope

- Wrong seed words, fingerprint or first receive address for given inputs
- Anything that causes the page to make a network request, store data, or expose a seed, rolls or passphrase
- Weaknesses in the self-test gate or the release/verification process

## Known limits (not vulnerabilities)

- The secp256k1 code is not constant-time. This is acceptable offline but is why the tool must never run on a networked or shared computer.
- The self-test runs inside the same file it checks, so a tampered file could fake a pass. Verify the SHA256 and the build attestation (see RELEASING.md).
- The randomness check is advisory and cannot prove your dice or coin are fair.
- Only the BIP84 (native SegWit, mainnet) first address is shown; other wallet types use other paths.
- Not supported on phones or in file previews.

## Supported versions

Only the latest release is supported.
