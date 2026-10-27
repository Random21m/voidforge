# Contributing

VOIDFORGE is one HTML file (`voidforge.html`) with no dependencies. Please keep it that way.

- **Security problems:** report privately at https://github.com/Random21m/voidforge/security/advisories/new, not in a public issue (see [SECURITY.md](SECURITY.md)).
- **Never post real seed words, passphrases, rolls or keys** in an issue or pull request.
- **Bugs and ideas:** open an issue and say which version and browser you used.
- **Code changes:** run `npm ci && npm test` (unit, independent-library comparison and mutation tests) and keep the in-page self-test green. Any change to `voidforge.html` needs a new version, an updated `SHA256SUMS`, and a note in the changelog. Changes that touch key handling, randomness or anything that shows private data will get extra scrutiny.
- **No network access, no analytics, no external scripts or fonts, and nothing money-related** in the app.

Releases are published by the maintainer only; see [RELEASING.md](RELEASING.md).
