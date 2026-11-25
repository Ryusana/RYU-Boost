#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
swiftc Shared/Profile.swift Shared/OpenVPNProfile.swift Shared/StoredProfile.swift Shared/OpenVPNLifecycle.swift Shared/RouteScore.swift Shared/TunnelHealth.swift Shared/NodeCatalog.swift Shared/SelectiveRoutes.swift Tests/main.swift -o "$tmp/ryu_test"
"$tmp/ryu_test"
swiftc -frontend -parse App/*.swift Shared/*.swift Tunnel/*.swift
printf 'Syntax parse PASS (not iOS SDK typecheck)\n'
