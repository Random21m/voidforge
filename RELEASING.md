# Releasing and verifying VOIDFORGE

## Do not host it as a live web page
VOIDFORGE must run offline. Do **not** enable GitHub Pages or any hosting for this repo, and do not add an `index.html` or any page that points people at an online copy. Distribute only a downloaded release file.

## For maintainers: cutting a release
1. Edit `voidforge.html`; bump the version in the footer and changelog card.
2. `node tests/test.js` must print `ALL CHECKS PASSED`.
3. `sha256sum voidforge.html > SHA256SUMS` and paste the hash into the release notes.
4. Tag the release. If you have a GPG key you use regularly, sign everything:
   ```
   git tag -s v1.2.2 -m "VOIDFORGE 1.2.2"
   gpg --armor --detach-sign SHA256SUMS
   ```
   If you do not, use `git tag -a v1.2.2 -m "VOIDFORGE 1.2.2"` and rely on the published SHA256 for now. Add signing later; do not let it block a release.
5. Create a GitHub release attaching `voidforge.html` and `SHA256SUMS` (plus `SHA256SUMS.asc` if signed).

## For users: verifying a download
```
sha256sum -c SHA256SUMS          # and, if signed: gpg --verify SHA256SUMS.asc SHA256SUMS
```
Do this on a machine you trust, then move the file by USB. Verify the file you downloaded, not the copy saved by the in-page "DOWNLOAD FOR USB" button (the browser re-serializes the page, so its hash differs).

## Current build
`voidforge.html` v1.2.2, SHA256: `56fa3401688749df95d847c61435922ec1bf89d9a44b5863ec458cb620c76cc6`
(Recompute after any edit.)
