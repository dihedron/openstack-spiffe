# Metrics

The signer replicas and the aggregators can export metrics: how many tokens they issue, why they refuse requests, how long issuance takes, the state of their keys, and more. They are off by default. This chapter turns them on; the *Operator's Guide* explains what to watch.

## Choosing an exporter

- **Prometheus** (`exporter: prometheus`): each process serves `GET /metrics` on a listener of its own, never on its service port. By default that listener is `127.0.0.1:9464`, reachable only from the host itself: run a collector agent on each host (Prometheus' agent mode, the OpenTelemetry Collector, Grafana Alloy) to scrape it.
- **OpenTelemetry** (`exporter: otlp`): each process pushes its metrics, every 30 seconds, to an OpenTelemetry Collector, over OTLP and verified TLS. Nothing listens on the hosts.

## Prometheus on loopback

```yaml
metrics:
  enabled: true
  exporter: prometheus
```

To be scraped from another host, the listener needs TLS, and scrapers need a client certificate: a non-loopback `listen_addr` without `tls_cert_path`, `tls_key_path` and `client_ca_path` is a configuration error.

```yaml
metrics:
  enabled: true
  exporter: prometheus
  prometheus:
    listen_addr: "0.0.0.0:9464"
    tls_cert_path: "/etc/openstack-spire-issuer/metrics.crt"
    tls_key_path: "/etc/openstack-spire-issuer/metrics.key"
    client_ca_path: "/etc/openstack-spire-issuer/scrapers-ca.pem"
```

## Pushing to an OpenTelemetry Collector

```yaml
metrics:
  enabled: true
  exporter: otlp
  otlp:
    endpoint: "https://otel-collector.example.org:4318"
    ca_cert_path: "/etc/ssl/otel-collector-ca.pem"
```

If the collector requires credentials, such as an `Authorization` header, put them in an environment variable of the unit (in `signer.env`, for instance, as `OTEL_COLLECTOR_HEADERS="Authorization=Bearer%20<token>"`), and name the variable in `headers_env`. They never go into the configuration file. The standard `OTEL_*` environment variables of OpenTelemetry cannot redirect the metrics: every setting comes from the configuration file.

## Per-project counts

`project_attribute: true` adds the project ID to the issued tokens counter, for at most `max_projects` projects (500); tokens of further projects are counted under `other`. This shows each tenant's activity to whoever can read the metrics, so the configuration check warns about it. Enable it only if the metrics stay with the cloud's operators.

## Checking

After restarting the replica:

```bash
curl -s http://127.0.0.1:9464/metrics | grep openstack_spire_tokens_issued_total
```

With OTLP, look for the `openstack_spire.` metrics in your collector, with the replica's `replica_id` as `service.instance.id`.
