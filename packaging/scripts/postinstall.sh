#!/bin/sh
# Makes systemd aware of the units. It never enables or starts them: on a
# fresh install they stay disabled until the operator configures the service;
# on an upgrade only the units that were running are restarted.
set -e

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload || true
	systemctl try-restart openstack-spire-issuer.service openstack-spire-issuer-aggregator.service || true
fi
