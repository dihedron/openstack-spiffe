#!/bin/sh
# Makes systemd forget the removed units. The system user is deliberately
# kept, so that any file it still owns stays attributed to it.
set -e

if [ -d /run/systemd/system ]; then
	systemctl daemon-reload || true
fi
