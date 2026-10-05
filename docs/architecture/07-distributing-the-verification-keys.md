# Distributing the verification keys

SPIRE Server verifies a token with the public key named by its key ID, so it needs every replica's current public keys, from a source it can trust: whoever can add a key to that source can sign tokens for any instance.

## The key sets

Each replica serves two JSON Web Key Sets (RFC 7517):

- **`/jwks/local.json`**: its own keys only: the one published ahead, the active one, and those retired within a token lifetime. Served with `Cache-Control: no-cache`, since a cache in between could hide a key published ahead. This is what peers and aggregators fetch.
- **`/.well-known/jwks.json`**: with peers, its own keys merged with theirs, cached for `cache_max_age` (30 seconds); without peers, the same as the local set. This is what SPIRE Server fetches.

The keys carry only public material and `use=sig`.

## Merging

The peered replicas and the aggregators merge with the same rules:

- **Polling**: every source at startup, then every `poll_interval` (30 seconds), concurrently, each within `fetch_timeout` (5 seconds).
- **Verified TLS**, with a pinned CA, never an insecure fallback, and redirects never followed: the configured URL itself must answer.
- **Bounded input**: at most 1 MiB, and at most 100 keys per set. A larger set is a failed fetch, never truncated to an arbitrary subset.
- **Filtering**: only public signing keys of an allowed algorithm (RSA of at least 2048 bits, or ECDSA P-256) pass. A key carrying private key material is rejected and logged as an error.
- **Conflicts fail closed**: a key ID published with different material by two sources is excluded, and logged on every poll while the conflict lasts.
- **Stale keys**: an unreachable source's last keys are kept for `stale_key_retention` (5 minutes, a token's lifetime), so that its in-flight tokens keep verifying. A reachable source's dropped keys disappear at the next fetch.
- **No circulation**: replicas fetch only each other's *local* sets, never a merged one, so a key leaves every merged set once its owner stops publishing it. The configuration refuses a peer's merged set.

## In SPIRE Server

The server plugin fetches the merged set at `jwks_url` the same way: periodically, over verified TLS, with the same bounds and filtering. Then:

- **Selection by key ID**: a token's key ID selects exactly one key. The plugin never tries several, so the number of keys does not multiply the work.
- **Unknown key IDs**: the plugin fetches the set again at once, at most once per `jwks_min_refetch_interval` (5 seconds), then rejects the token if the key is still unknown. A new key is found before the next refresh, without letting tokens with invented key IDs turn into a flood of fetches. A malformed key ID is rejected before any lookup or fetch.
- **Last known good**: when fetches fail, the last fetched keys stay in use for `jwks_stale_key_retention` (5 minutes). Past that, every attestation is refused until a fetch succeeds. Unavailability never loosens verification.

## Why not pin a public key?

The keys rotate daily, and on every restart, by design. No key is stable enough to configure in SPIRE Server. The endpoint's TLS identity takes its place in the trust chain: SPIRE Server pins the CA of the endpoint's certificate, and the endpoint serves the keys.
