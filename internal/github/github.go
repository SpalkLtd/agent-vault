// Package github mints short-lived GitHub App INSTALLATION access tokens (ghs_)
// on demand (server-to-server, "Mode B"). It signs a JWT with the App private
// key, exchanges it for an installation token, and caches that token in memory,
// re-minting before expiry. The token acts as the App/bot — gated by the App's
// own permissions and ruleset bypass membership, independent of any human. The
// only durable secret is the App private key (PEM), held DEK-encrypted by the
// store; nothing is rotated.
package github

// APIBase is GitHub's REST API root. A var so tests can point it at httptest.
var APIBase = "https://api.github.com"
