# ARPVPN Site-to-Site Mesh + IP Access Control Roadmap

This file now tracks only the remaining mesh and ACL work. Completed items are kept in release notes and tests.

## Mesh Control Plane
- [ ] Generate inter-server peer entries with deterministic naming and key rotation support.
- [ ] Render `AllowedIPs` based on advertised routes for each remote server.
- [ ] Add apply planner with rollback across affected interfaces.
- [ ] Add route install/remove hooks for Linux route table updates.
- [ ] Add health reconciliation loop for drift detection and auto-heal.
- [ ] Add key rotation workflows for inter-server peers.

## Access Control
- [ ] Add per-peer/per-group egress ACL enforcement using `nftables` sets/chains (preferred) with `iptables` fallback.
- [ ] Add policy priorities and explicit default-deny option.
- [ ] Add domain-to-IP expansion support with cached DNS resolution for policy targets.
- [ ] Add explicit allowlists for LAN management ranges and infra services.
- [ ] Add approval mode for high-impact changes such as full-mesh rebuilds and default-deny enablement.
- [ ] Add safeguards for self-lockout scenarios.

## Observability
- [ ] Add per-link metrics: handshake age, packet loss indicators, byte counters, route counts.
- [ ] Add policy hit counters and blocked-flow summaries.
- [ ] Add RRD history panels for inter-server links and policy hit trends.

## Testing and Rollout
- [ ] Failure-injection tests for partial apply/rollback behavior.
- [ ] Restart-persistence tests on docker02 for route and policy state.
- [ ] Tailscale subnet routers and ACL/tag model alignment.
- [ ] NetBird route distribution and policy-group alignment.
- [ ] Netmaker gateway/egress model alignment.
- [ ] Firezone resource policy and default-deny model alignment.

Reference docs:
- https://tailscale.com/kb/1019/subnets
- https://tailscale.com/kb/1018/acls
- https://docs.netbird.io/how-to/routing-traffic-to-private-networks
- https://docs.netbird.io/how-to/restricting-user-access-to-resources
- https://docs.netmaker.io/docs/server-installation/register-alt-client
- https://www.netmaker.io/resources
- https://www.firezone.dev/docs/quickstart
