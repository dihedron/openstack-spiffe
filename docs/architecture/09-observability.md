# Observability

## Logs

Every component logs in a structured format: to standard error, and so to the journal, for the issuer; through SPIRE's logger for the plugins. Each request to the issuer gets a request ID, returned in `X-Request-Id` and carried by every record written while handling it. No component ever logs a token, a key, a credential, user data or metadata values.

## The audit trail

Audit records are written whatever the log level, even when logging is turned off, so that turning operational logging down never removes the audit trail:

| Record | Written by | When | Carries |
| ---------------- | -------------- | ------------------------ | ---------------------------------------------------- |
| `token_issued` | Signer replica | Every token issued | Request ID, Nova's user ID, client address and certificate, project and instance IDs, `jti`, key ID, issuance and expiry times |
| `key_lifecycle` | Signer replica | Every key transition | Event, key ID, algorithm, key thumbprint |
| `agent_attested` | Server plugin | Every successful attestation | Project and instance IDs, SPIFFE ID, `jti`, key ID, issuance and expiry times |
| `reattest_alert` | Server plugin | A quick re-attestation | Instance and project IDs, both tokens' `jti`s, the interval |

**Correlation.** The token's ID, `jti`, appears in the issuer's `token_issued` record and in the server plugin's `agent_attested` record. Joined, they tie every agent identity to the Nova call, the replica and the key that produced its token. Tokens minted with stolen credentials then show up as issuances without a matching metadata read; a stolen token as an attestation that does not match the instance's agent.

**Syslog.** Both the issuer and the server plugin can also send their audit records to the local syslog daemon, in the format journald and rsyslog parse (RFC 3164, with a JSON message), so that they reach a central, append-only store. Delivery never delays a token or an attestation: a bounded queue feeds the socket, and records that cannot be sent are dropped and counted. The copy in the regular log remains.

## Health

Each signer replica and aggregator serves `/liveness`, answering as long as the process serves, and `/readiness`, answering from the latest background checks so that probes never wait on a dependency: the key store (which includes the first key's publication), Keystone and, when instance verification is on, Nova for a replica; at least one replica fetched recently for an aggregator. Peers are not a readiness check: a replica's merged set always holds its own keys, and taking it out of Nova's rotation because a peer is down would gain nothing.

## Metrics

The signer replicas and aggregators can export OpenTelemetry metrics, to Prometheus on a listener of their own or to an OpenTelemetry Collector: tokens issued, every `/attest` call by outcome and reason, latencies end to end and per dependency, key and key set state, peer fetches, rate limiting, dropped audit records, readiness. Metrics never carry an instance ID, user ID, token ID or client address. A per-project count is an option, capped. They are off by default, never served on the service's listener, and need TLS with client certificates beyond loopback. The state metrics are read from each component when they are collected, so they cost nothing on the request path.
