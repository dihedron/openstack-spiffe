#!/bin/sh
# Creates the system user and group the systemd units run as.
set -e

name=openstack-spire-issuer

if ! getent group "$name" >/dev/null; then
	groupadd --system "$name"
fi
if ! getent passwd "$name" >/dev/null; then
	useradd --system --gid "$name" --no-create-home --home-dir /nonexistent \
		--shell /usr/sbin/nologin --comment "OpenStack SPIRE token issuer" "$name"
fi
