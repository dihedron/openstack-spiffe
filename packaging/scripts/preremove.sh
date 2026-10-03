#!/bin/sh
# Stops and disables the units when the package is removed, but not when it
# is upgraded (deb passes "upgrade", rpm passes 1 or more).
set -e

case "$1" in
	remove | 0)
		if [ -d /run/systemd/system ]; then
			systemctl disable --now openstack-spire-issuer.service openstack-spire-issuer-aggregator.service || true
		else
			systemctl disable openstack-spire-issuer.service openstack-spire-issuer-aggregator.service >/dev/null 2>&1 || true
		fi
		;;
esac
