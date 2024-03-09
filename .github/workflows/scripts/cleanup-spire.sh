#!/usr/bin/env bash

killall -9 spire-agent || true
killall -9 spire-server || true
rm -f /tmp/spire-server/private/api.sock
rm -f /tmp/spire-agent/public/api.sock
