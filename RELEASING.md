# Releasing and verifying VOIDFORGE

## Do not host it as a live web page
VOIDFORGE must run offline. Do **not** enable GitHub Pages or any hosting for this repo, and do not add an `index.html` or any page that points people at an online copy. Distribute only a downloaded release file.

## For maintainers: cutting a release
1. Edit `voidforge.html`; bump the version in the footer and the changelog card.
2. `npm ci && npm test` must pass (unit tests, oracle tests against `@scure`, mutation tests).
3. `sha256sum voidforge.html > SHA256SUMS`, commit, push, and wait for the green check on the `test` workflow.
4. On GitHub: Releases, Create a new release, create the tag (for example `v1.2.3`), and paste the SHA256 into the description. Publish.
5. The `release` workflow then runs by itself: it re-runs the tests, checks `SHA256SUMS`, records a signed build-provenance attestation, and attaches `voidforge.html` and `SHA256SUMS` to the release. Check the Actions tab for a green run.
   - If it fails, or for an older release, run it by hand: Actions, `release`, Run workflow, enter the tag.
6. Optional: sign the tag with GPG (`git tag -s`) if you have a key you use regularly. Do not let it block a release.

Workflow actions are pinned to full commit hashes (version in the trailing comment), so a moved tag cannot change what runs. To update one, look up the new tag's commit with `git ls-remote --tags https://github.com/actions/<name>` and change the hash and comment together. The release workflow has run successfully on GitHub for v1.3.0.

## For users: verifying a download
Do this on a machine you trust, then move the file by USB.
```
sha256sum -c SHA256SUMS
gh attestation verify voidforge.html --repo Random21m/voidforge     # needs the GitHub CLI
```
The attestation proves the file came from this repository's release workflow at a specific commit. It does not prove the code is safe; that depends on review. Verify the file you downloaded, not the copy saved by the in-page "DOWNLOAD FOR USB" button (the browser re-serializes the page, so its hash differs).

## Current build
`voidforge.html` v1.18.0, SHA256: `98a70b5f6297970947112a26a5b4ba0b46675825979c03a07f19c9a43097c576`
(Recompute after any edit.)
