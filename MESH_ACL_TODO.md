# ARPVPN Site-to-Site Mesh + IP Access Control TODO

Goal: add first-class site-to-site and multi-site mesh VPN capabilities across ARPVPN servers, plus policy-driven control over which destination IPs/subnets are reachable through the VPN.

## Phase 1: Data Model and Control Plane
- [ ] Add `vpn_links` model for server-to-server links (source server, target server, interface, status, key metadata).
- [ ] Add `topology` model with `point_to_point`, `hub_spoke`, and `full_mesh` presets.
- [ ] Add `route_advertisements` model for per-server announced subnets.
- [ ] Add `access_policies` model for source peer/group -> destination CIDR allow/deny rules.
- [ ] Add conflict detection for overlapping CIDRs and duplicate route ownership.

## Phase 2: UI and API
- [ ] Add UI wizard: create site-to-site link between two ARPVPN servers.
- [ ] Add UI wizard: create 3+ server mesh from a server list and subnet map.
- [ ] Add API endpoints for links/topologies/routes/policies (`/api/v1/mesh/*`).
- [ ] Add dry-run API for topology validation before apply.
- [ ] Add export/import for topology JSON.

## Phase 3: WireGuard Rendering and Apply Logic
- [ ] Generate inter-server peer entries with deterministic naming and key rotation support.
- [ ] Render `AllowedIPs` based on advertised routes for each remote server.
- [ ] Add apply planner with rollback (transaction-like behavior across all affected interfaces).
- [ ] Add route install/remove hooks for Linux route table updates.
- [ ] Add health reconciliation loop for drift detection and auto-heal.

## Phase 4: Beyond-VPN IP Access Control
- [ ] Add per-peer/per-group egress ACL enforcement using `nftables` sets/chains (preferred) with `iptables` fallback.
- [ ] Add policy priorities and explicit default-deny option.
- [ ] Add domain-to-IP expansion support (optional) with cached DNS resolution for policy targets.
- [ ] Add explicit allowlists for LAN management ranges and infra services.
- [ ] Add policy simulation output: matched rule, action, and reason.

## Phase 5: Observability and Operations
- [ ] Add per-link metrics: handshake age, packet loss indicators, byte counters, route counts.
- [ ] Add mesh diagnostics page: link state matrix and route propagation status.
- [ ] Add policy hit counters and blocked-flow summaries.
- [ ] Add structured event logs for link/policy changes and failures.
- [ ] Add RRD history panels for inter-server links and policy hit trends.

## Phase 6: Security and Governance
- [ ] Enforce role gates: only admins/support can edit mesh/policies; clients read scoped state only.
- [ ] Add signed change records (who, what, when) for all mesh/policy operations.
- [ ] Add approval mode for high-impact changes (full-mesh rebuild, default-deny enablement).
- [ ] Add safeguards for self-lockout scenarios (management access protections).
- [ ] Add key rotation workflows for inter-server peers.

## Phase 7: Testing and Rollout
- [ ] Unit tests for topology validation, route conflict checks, and policy evaluation.
- [ ] Integration tests with 2-node site-to-site and 3-node mesh topologies.
- [ ] Failure-injection tests for partial apply/rollback behavior.
- [ ] Docker02 environment tests for route + policy persistence across restarts.
- [ ] Phased rollout behind feature flags (`mesh_v1`, `acl_v1`).

## Reference Patterns (WireGuard Ecosystem)
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
