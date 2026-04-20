from __future__ import annotations

from typing import Any, Dict, Optional
from urllib.parse import urljoin

import requests


class ArpvpnApiClient:
    def __init__(self, base_url: str, bearer_token: str = "", timeout: int = 30, verify: bool = True, session: Optional[requests.Session] = None):
        self.base_url = base_url.rstrip("/") + "/"
        self.timeout = timeout
        self.verify = verify
        self.session = session or requests.Session()
        self.bearer_token = bearer_token

    def set_bearer_token(self, token: str):
        self.bearer_token = token

    def _request(self, method: str, path: str, *, params: Optional[Dict[str, Any]] = None, payload: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        request_headers: Dict[str, str] = dict(headers or {})
        if self.bearer_token:
            request_headers.setdefault("Authorization", f"Bearer {self.bearer_token}")
        response = self.session.request(
            method.upper(),
            urljoin(self.base_url, path.lstrip("/")),
            params=params,
            json=payload,
            headers=request_headers,
            timeout=self.timeout,
            verify=self.verify,
        )
        response.raise_for_status()
        content_type = response.headers.get("Content-Type", "")
        if "application/json" in content_type:
            return response.json()
        return response.text

    def about(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/about"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def audit_events(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/audit/events"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def auth_csrf(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/auth/csrf"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def auth_force_logout(self, user_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/auth/force-logout/{user_id}"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def auth_modes(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/auth/modes"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def auth_rbac(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/auth/rbac"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def auth_refresh_token(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/auth/refresh"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def auth_revoke_token(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/auth/revoke"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def auth_revoke_all_tokens(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/auth/revoke-all"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def auth_issue_token(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/auth/token"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def get_global_config(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/config/global"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def update_global_config(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/config/global"
        return self._request("PUT", path, params=params, payload=payload, headers=headers)

    def start_impersonation(self, user_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/impersonation/start/{user_id}"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def stop_impersonation(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/impersonation/stop"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def list_invitations(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/invitations"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def create_invitation(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/invitations"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def get_invitation(self, invitation_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/invitations/{invitation_id}"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def accept_invitation(self, invitation_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/invitations/{invitation_id}/accept"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def resend_invitation(self, invitation_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/invitations/{invitation_id}/resend"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def revoke_invitation(self, invitation_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/invitations/{invitation_id}/revoke"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def get_job(self, job_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/jobs/{job_id}"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def network_inventory(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/network/inventory"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def profile(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/profile"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def profile_update(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/profile"
        return self._request("PUT", path, params=params, payload=payload, headers=headers)

    def profile_password_update(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/profile/password"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def setup_bootstrap(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/setup/bootstrap"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def setup_status(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/setup/status"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def stats_alerts(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/stats/alerts"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def stats_alerts_csv(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/stats/alerts.csv"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def stats_failures(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/stats/failures"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def stats_history(self, uuid, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/stats/history/{uuid}"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def stats_overview(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/stats/overview"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def stats_peers(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/stats/peers"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def stats_peers_csv(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/stats/peers.csv"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def stats_rollups(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/stats/rollups"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def stats_rollups_csv(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/stats/rollups.csv"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def stats_rrd(self, uuid, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/stats/rrd/{uuid}"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def stats_statistics(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/stats/statistics"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def system_backup(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/system/backup"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def system_diagnostics(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/system/diagnostics"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def system_health(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/system/health"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def system_restart(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/system/restart"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def system_restore(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/system/restore"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def system_version(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/system/version"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def list_tenants(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/tenants"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def create_tenant(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/tenants"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def delete_tenant(self, tenant_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/tenants/{tenant_id}"
        return self._request("DELETE", path, params=params, payload=payload, headers=headers)

    def get_tenant(self, tenant_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/tenants/{tenant_id}"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def update_tenant(self, tenant_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/tenants/{tenant_id}"
        return self._request("PUT", path, params=params, payload=payload, headers=headers)

    def get_tenant_config(self, tenant_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/tenants/{tenant_id}/config"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def update_tenant_config(self, tenant_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/tenants/{tenant_id}/config"
        return self._request("PUT", path, params=params, payload=payload, headers=headers)

    def list_tenant_members(self, tenant_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/tenants/{tenant_id}/members"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def create_tenant_member(self, tenant_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/tenants/{tenant_id}/members"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def get_tenant_runtime(self, tenant_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/tenants/{tenant_id}/runtime"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def update_tenant_runtime(self, tenant_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/tenants/{tenant_id}/runtime"
        return self._request("PUT", path, params=params, payload=payload, headers=headers)

    def allocate_tenant_runtime(self, tenant_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/tenants/{tenant_id}/runtime/allocate"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def control_tenant_runtime(self, tenant_id, action, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/tenants/{tenant_id}/runtime/{action}"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def update_tenant_tls_status(self, tenant_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/tenants/{tenant_id}/tls"
        return self._request("PUT", path, params=params, payload=payload, headers=headers)

    def get_tenant_tls_status(self, tenant_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/tenants/{tenant_id}/tls/status"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def get_theme_choice(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/themes"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def set_theme_choice(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/themes"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def tls_certificate_status(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/tls/certificate"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def tls_issue_letsencrypt(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/tls/letsencrypt"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def tls_mode_update(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/tls/mode"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def tls_generate_self_signed(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/tls/self-signed"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def tls_status(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/tls/status"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def list_users(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/users"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def create_user(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/users"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def export_users(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/users/export"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def import_users(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/users/import"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def delete_user(self, user_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/users/{user_id}"
        return self._request("DELETE", path, params=params, payload=payload, headers=headers)

    def get_user(self, user_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/users/{user_id}"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def update_user(self, user_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/users/{user_id}"
        return self._request("PUT", path, params=params, payload=payload, headers=headers)

    def list_wireguard_interfaces(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/wireguard/interfaces"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def create_wireguard_interface(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/wireguard/interfaces"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def delete_wireguard_interface(self, interface_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/wireguard/interfaces/{interface_id}"
        return self._request("DELETE", path, params=params, payload=payload, headers=headers)

    def get_wireguard_interface(self, interface_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/wireguard/interfaces/{interface_id}"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def update_wireguard_interface(self, interface_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/wireguard/interfaces/{interface_id}"
        return self._request("PUT", path, params=params, payload=payload, headers=headers)

    def download_wireguard_interface(self, interface_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/wireguard/interfaces/{interface_id}/download"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def wireguard_interface_qr(self, interface_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/wireguard/interfaces/{interface_id}/qr"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def operate_wireguard_interface(self, interface_id, action, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/wireguard/interfaces/{interface_id}/{action}"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def list_wireguard_peers(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/wireguard/peers"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def create_wireguard_peer(self, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = "/api/v1/wireguard/peers"
        return self._request("POST", path, params=params, payload=payload, headers=headers)

    def delete_wireguard_peer(self, peer_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/wireguard/peers/{peer_id}"
        return self._request("DELETE", path, params=params, payload=payload, headers=headers)

    def get_wireguard_peer(self, peer_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/wireguard/peers/{peer_id}"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def update_wireguard_peer(self, peer_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/wireguard/peers/{peer_id}"
        return self._request("PUT", path, params=params, payload=payload, headers=headers)

    def download_wireguard_peer(self, peer_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/wireguard/peers/{peer_id}/download"
        return self._request("GET", path, params=params, payload=payload, headers=headers)

    def wireguard_peer_qr(self, peer_id, payload: Optional[Dict[str, Any]] = None, params: Optional[Dict[str, Any]] = None, headers: Optional[Dict[str, str]] = None) -> Any:
        path = f"/api/v1/wireguard/peers/{peer_id}/qr"
        return self._request("GET", path, params=params, payload=payload, headers=headers)
