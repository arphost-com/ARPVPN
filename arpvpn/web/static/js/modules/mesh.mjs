import { prependAlert, AlertType } from "./utils.mjs";

const alertsId = "meshAlerts";

function getCsrfToken() {
    const meta = document.querySelector("meta[name='arpvpn-csrf-token']");
    return meta ? (meta.getAttribute("content") || "").trim() : "";
}

function splitList(value) {
    return String(value || "")
        .split(/[\n,]/)
        .map((item) => item.trim())
        .filter(Boolean);
}

function buildHeaders(includeJson = false) {
    const headers = { Accept: "application/json" };
    if (includeJson) {
        headers["Content-Type"] = "application/json";
    }
    const csrfToken = getCsrfToken();
    if (csrfToken) {
        headers["X-CSRFToken"] = csrfToken;
    }
    return headers;
}

async function apiRequest(method, url, payload = null) {
    const response = await fetch(url, {
        method,
        credentials: "same-origin",
        headers: buildHeaders(payload !== null),
        body: payload !== null ? JSON.stringify(payload) : undefined,
    });
    const contentType = response.headers.get("content-type") || "";
    const responsePayload = contentType.includes("application/json") ? await response.json() : null;
    if (!response.ok || (responsePayload && responsePayload.ok === false)) {
        const message = responsePayload?.error?.message || response.statusText || "Request failed.";
        throw new Error(message);
    }
    return responsePayload ? responsePayload.data : null;
}

function pairwise(items) {
    const pairs = [];
    for (let left = 0; left < items.length; left += 1) {
        for (let right = left + 1; right < items.length; right += 1) {
            pairs.push([items[left], items[right]]);
        }
    }
    return pairs;
}

function parseRouteMap(text) {
    const mappings = [];
    const lines = String(text || "")
        .split("\n")
        .map((line) => line.trim())
        .filter(Boolean);
    lines.forEach((line) => {
        const chunks = line.split("=");
        if (chunks.length !== 2) {
            throw new Error(`Invalid subnet map line: ${line}`);
        }
        const serverId = chunks[0].trim();
        if (!serverId) {
            throw new Error(`Missing server id in subnet map line: ${line}`);
        }
        splitList(chunks[1]).forEach((cidr) => {
            mappings.push({ owner_server: serverId, cidr });
        });
    });
    return mappings;
}

function setBusy(form, busy) {
    if (!form) {
        return;
    }
    form.querySelectorAll("button, input, select, textarea").forEach((element) => {
        element.disabled = busy;
    });
}

function success(message) {
    prependAlert(alertsId, message, AlertType.SUCCESS, 5000, true);
}

function failure(message) {
    prependAlert(alertsId, message, AlertType.DANGER, 9000, true);
}

async function createSiteToSite(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const name = document.getElementById("siteToSiteName").value.trim();
    const serverA = document.getElementById("siteToSiteServerA").value.trim();
    const serverB = document.getElementById("siteToSiteServerB").value.trim();
    const linkStatus = document.getElementById("siteToSiteLinkStatus").value;
    const serverARoutes = splitList(document.getElementById("siteToSiteServerARoutes").value);
    const serverBRoutes = splitList(document.getElementById("siteToSiteServerBRoutes").value);

    if (!name || !serverA || !serverB) {
        failure("Topology name and both server ids are required.");
        return;
    }

    setBusy(form, true);
    try {
        const topology = await apiRequest("POST", "/api/v1/mesh/topologies", {
            name,
            preset: "point_to_point",
            server_ids: [serverA, serverB],
        });
        const link = await apiRequest("POST", "/api/v1/mesh/links", {
            source_server: serverA,
            target_server: serverB,
            topology_uuid: topology.uuid,
            status: linkStatus,
            enabled: true,
        });
        for (const cidr of serverARoutes) {
            await apiRequest("POST", "/api/v1/mesh/routes", {
                owner_server: serverA,
                cidr,
                via_link_uuid: link.uuid,
                enabled: true,
            });
        }
        for (const cidr of serverBRoutes) {
            await apiRequest("POST", "/api/v1/mesh/routes", {
                owner_server: serverB,
                cidr,
                via_link_uuid: link.uuid,
                enabled: true,
            });
        }
        success(`Created site-to-site topology ${name}. Reloading...`);
        window.setTimeout(() => window.location.reload(), 600);
    } catch (error) {
        failure(error.message);
    } finally {
        setBusy(form, false);
    }
}

async function createFullMesh(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const name = document.getElementById("fullMeshName").value.trim();
    const servers = splitList(document.getElementById("fullMeshServers").value);
    const routeMapText = document.getElementById("fullMeshRouteMap").value;

    if (!name || servers.length < 3) {
        failure("Full mesh requires a topology name and at least three servers.");
        return;
    }

    setBusy(form, true);
    try {
        const topology = await apiRequest("POST", "/api/v1/mesh/topologies", {
            name,
            preset: "full_mesh",
            server_ids: servers,
        });
        for (const [sourceServer, targetServer] of pairwise(servers)) {
            await apiRequest("POST", "/api/v1/mesh/links", {
                source_server: sourceServer,
                target_server: targetServer,
                topology_uuid: topology.uuid,
                status: "pending",
                enabled: true,
            });
        }
        const mappings = parseRouteMap(routeMapText);
        for (const mapping of mappings) {
            await apiRequest("POST", "/api/v1/mesh/routes", {
                owner_server: mapping.owner_server,
                cidr: mapping.cidr,
                enabled: true,
            });
        }
        success(`Created full mesh topology ${name}. Reloading...`);
        window.setTimeout(() => window.location.reload(), 600);
    } catch (error) {
        failure(error.message);
    } finally {
        setBusy(form, false);
    }
}

async function addRoute(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const ownerServer = document.getElementById("meshRouteOwner").value.trim();
    const cidr = document.getElementById("meshRouteCidr").value.trim();
    const viaLinkUuid = document.getElementById("meshRouteLink").value.trim();

    setBusy(form, true);
    try {
        await apiRequest("POST", "/api/v1/mesh/routes", {
            owner_server: ownerServer,
            cidr,
            via_link_uuid: viaLinkUuid,
            enabled: true,
        });
        success(`Added route ${cidr}. Reloading...`);
        window.setTimeout(() => window.location.reload(), 600);
    } catch (error) {
        failure(error.message);
    } finally {
        setBusy(form, false);
    }
}

async function addPolicy(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const name = document.getElementById("meshPolicyName").value.trim();
    const sourceKind = document.getElementById("meshPolicySourceKind").value;
    const sourceId = document.getElementById("meshPolicySourceId").value.trim();
    const destinations = splitList(document.getElementById("meshPolicyDestinations").value);
    const action = document.getElementById("meshPolicyAction").value;
    const priority = Number.parseInt(document.getElementById("meshPolicyPriority").value || "100", 10);

    setBusy(form, true);
    try {
        await apiRequest("POST", "/api/v1/mesh/policies", {
            name,
            source_kind: sourceKind,
            source_id: sourceId,
            destinations,
            action,
            priority,
            enabled: true,
        });
        success(`Added policy ${name}. Reloading...`);
        window.setTimeout(() => window.location.reload(), 600);
    } catch (error) {
        failure(error.message);
    } finally {
        setBusy(form, false);
    }
}

async function simulatePolicy(event) {
    event.preventDefault();
    const form = event.currentTarget;
    const result = document.getElementById("policySimulationResult");
    const payload = {
        source_kind: document.getElementById("policySourceKind").value,
        source_id: document.getElementById("policySourceId").value.trim(),
        destination: document.getElementById("policyDestination").value.trim(),
    };

    setBusy(form, true);
    try {
        const data = await apiRequest("POST", "/api/v1/mesh/policy-simulate", payload);
        result.hidden = false;
        result.textContent = JSON.stringify(data.result, null, 2);
        success("Policy simulation completed.");
    } catch (error) {
        if (result) {
            result.hidden = true;
        }
        failure(error.message);
    } finally {
        setBusy(form, false);
    }
}

async function deleteResource(button) {
    const endpoint = button.dataset.deleteEndpoint || "";
    const label = button.dataset.deleteLabel || "item";
    if (!endpoint) {
        return;
    }
    if (!window.confirm(`Delete ${label}?`)) {
        return;
    }
    button.disabled = true;
    try {
        await apiRequest("DELETE", endpoint, {});
        success(`Deleted ${label}. Reloading...`);
        window.setTimeout(() => window.location.reload(), 500);
    } catch (error) {
        failure(error.message);
        button.disabled = false;
    }
}

function init() {
    const siteToSiteWizardForm = document.getElementById("siteToSiteWizardForm");
    const fullMeshWizardForm = document.getElementById("fullMeshWizardForm");
    const addMeshRouteForm = document.getElementById("addMeshRouteForm");
    const addMeshPolicyForm = document.getElementById("addMeshPolicyForm");
    const simulatePolicyForm = document.getElementById("simulatePolicyForm");
    const refreshButton = document.getElementById("refreshMeshDiagnostics");

    if (siteToSiteWizardForm) {
        siteToSiteWizardForm.addEventListener("submit", createSiteToSite);
    }
    if (fullMeshWizardForm) {
        fullMeshWizardForm.addEventListener("submit", createFullMesh);
    }
    if (addMeshRouteForm) {
        addMeshRouteForm.addEventListener("submit", addRoute);
    }
    if (addMeshPolicyForm) {
        addMeshPolicyForm.addEventListener("submit", addPolicy);
    }
    if (simulatePolicyForm) {
        simulatePolicyForm.addEventListener("submit", simulatePolicy);
    }
    if (refreshButton) {
        refreshButton.addEventListener("click", () => window.location.reload());
    }
    document.querySelectorAll("[data-delete-endpoint]").forEach((button) => {
        button.addEventListener("click", () => {
            void deleteResource(button);
        });
    });
}

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
} else {
    init();
}
