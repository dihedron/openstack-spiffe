package config

// CrossCheck records the findings that only emerge when looking at several
// files together: replica IDs must be unique across signers (they are part of
// every kid), and, if an aggregator is given, each signer must publish a new
// key long enough before using it for the aggregator to pick it up and its
// consumers to see it, cached copies included. Files
// that could not be decoded are skipped.
func CrossCheck(signers []*Result[Signer], aggregator *Result[Aggregator]) {
	owners := map[string]string{}
	for _, signer := range signers {
		cfg := signer.Config
		if cfg == nil {
			continue
		}
		if cfg.ReplicaID != "" {
			if owner, ok := owners[cfg.ReplicaID]; ok {
				signer.errorf(KindInconsistency, "replica_id", "%q is also used by %s: the two replicas would issue colliding kids", cfg.ReplicaID, owner)
			} else {
				owners[cfg.ReplicaID] = signer.File
			}
		}
		if aggregator == nil || aggregator.Config == nil {
			continue
		}
		agg := aggregator.Config
		window := publicationWindow(agg.PollInterval, agg.FetchTimeout, agg.CacheMaxAge)
		if cfg.KeyStore.PublishAhead <= window {
			signer.errorf(KindInconsistency, "key_store.publish_ahead",
				"%v must exceed the poll_interval + fetch_timeout + cache_max_age of %s (%v): otherwise tokens may carry a kid the aggregated JWKS does not publish yet",
				cfg.KeyStore.PublishAhead, aggregator.File, window)
		}
	}
}
