# Releasing and verifying VOIDFORGE

## Do not host it as a live web page
VOIDFORGE must run offline. Do **not** enable GitHub Pages or any hosting for this repo, and do not add an `index.html` or any page that points people at an online copy. Distribute only a downloaded release file.

## For maintainers: cutting a release
1. Edit `voidforge.html`; bump the version in the footer and the changelog card.
2. `npm ci && npm test` must pass (unit tests, oracle tests against `@scure`, mutation tests).
3. `sha256sum voidforge.html > SHA256SUMS` and write the file's content ID to `CID.txt` (CIDv1, raw, sha2-256: `python3 -c "import hashlib,base64; h=hashlib.sha256(open('voidforge.html','rb').read()).digest(); print('b'+base64.b32encode(bytes([1,0x55,0x12,0x20])+h).decode().lower().rstrip('='))" > CID.txt`), commit, push, and wait for the green check on the `test` workflow.
4. On GitHub: Releases, Create a new release, create the tag (for example `v1.2.3`), and paste the SHA256 into the description. Publish.
5. The `release` workflow then runs by itself: it re-runs the tests, checks `SHA256SUMS`, records a signed build-provenance attestation, and attaches `voidforge.html`, `SHA256SUMS` and `CID.txt` to the release (from v1.19.1; for older tags that have no `CID.txt` the workflow cannot be re-run). Check the Actions tab for a green run.
   - If it fails, or for an older release, run it by hand: Actions, `release`, Run workflow, enter the tag.
6. Optional: sign the tag with GPG (`git tag -s`) if you have a key you use regularly. Do not let it block a release.

Workflow actions are pinned to full commit hashes (version in the trailing comment), so a moved tag cannot change what runs. To update one, look up the new tag's commit with `git ls-remote --tags https://github.com/actions/<name>` and change the hash and comment together. The release workflow has run successfully on GitHub for v1.3.0.

## For users: verifying a download
Do this on a machine you trust, then move the file by USB.
```
sha256sum -c SHA256SUMS
gh attestation verify voidforge.html --repo Random21m/voidforge     # needs the GitHub CLI
```
`CID.txt` holds the same check as a content ID (CIDv1, raw, sha2-256), the format IPFS-style tools use. It is a second, independent way to confirm the file: compute it yourself with the one-line command in step 3 above and compare it with `CID.txt`.
The attestation proves the file came from this repository's release workflow at a specific commit. It does not prove the code is safe; that depends on review. Verify the file you downloaded, not the copy saved by the in-page "DOWNLOAD FOR USB" button (the browser re-serializes the page, so its hash differs).

## Current build
`voidforge.html` v1.20.0, SHA256: `f903e7ec49c2d3f67ecd4473b871082ca92c6089b5d4ead45969a19ddeed5a16`
Content ID (CIDv1): `bafkreihzapt6ysoc2p3h5tkeoo4hccbmvewgbcnv2tvniwljugo553k2cy`
(Recompute after any edit.)
