const secretField = document.getElementById("web_secret_key");
const toggleSecretKey = document.getElementById("toggleSecretKey");
const toggleSecretKeyIcon = document.getElementById("toggleSecretKeyIcon");

if (secretField && toggleSecretKey && toggleSecretKeyIcon) {
    secretField.setAttribute("type", "password");

    toggleSecretKey.addEventListener("click", function () {
        const type = secretField.getAttribute("type") === "password" ? "text" : "password";
        secretField.setAttribute("type", type);
        if (type === "password") {
            toggleSecretKeyIcon.classList.add("fa-eye-slash");
            toggleSecretKeyIcon.classList.remove("fa-eye");
        } else {
            toggleSecretKeyIcon.classList.add("fa-eye");
            toggleSecretKeyIcon.classList.remove("fa-eye-slash");
        }
    }, false);
}

const tlsMode = document.getElementById("web_tls_mode");
const tlsServerName = document.getElementById("web_tls_server_name");
const letsencryptEmail = document.getElementById("web_tls_letsencrypt_email");
const proxyIncomingHostname = document.getElementById("web_proxy_incoming_hostname");
const redirectHttpToHttps = document.getElementById("web_redirect_http_to_https");
const generateSelfSigned = document.getElementById("web_tls_generate_self_signed");
const issueLetsencrypt = document.getElementById("web_tls_issue_letsencrypt");
const restartAppButton = document.getElementById("restartAppButton");
const restartAppStatus = document.getElementById("restartAppStatus");

function getCsrfToken() {
    const meta = document.querySelector("meta[name='arpvpn-csrf-token']");
    return meta ? (meta.getAttribute("content") || "").trim() : "";
}

function setDisabled(el, disabled) {
    if (!el) {
        return;
    }
    el.disabled = disabled;
}

function syncTlsForm() {
    if (!tlsMode) {
        return;
    }
    const mode = tlsMode.value;
    const isSelfSigned = mode === "self_signed";
    const isLetsEncrypt = mode === "letsencrypt";
    const isReverseProxy = mode === "reverse_proxy";
    const needsTlsServerName = isSelfSigned || isLetsEncrypt;
    const supportsHttps = mode !== "http";

    setDisabled(tlsServerName, !needsTlsServerName);
    setDisabled(letsencryptEmail, !isLetsEncrypt);
    setDisabled(proxyIncomingHostname, !isReverseProxy);
    setDisabled(redirectHttpToHttps, !supportsHttps);
    setDisabled(generateSelfSigned, !isSelfSigned);
    setDisabled(issueLetsencrypt, !isLetsEncrypt);

    if (redirectHttpToHttps && !supportsHttps) {
        redirectHttpToHttps.checked = false;
    }
    if (generateSelfSigned && !isSelfSigned) {
        generateSelfSigned.checked = false;
    }
    if (issueLetsencrypt && !isLetsEncrypt) {
        issueLetsencrypt.checked = false;
    }
}

if (tlsMode) {
    tlsMode.addEventListener("change", syncTlsForm);
    syncTlsForm();
}

if (restartAppButton) {
    restartAppButton.addEventListener("click", async function () {
        restartAppButton.disabled = true;
        if (restartAppStatus) {
            restartAppStatus.hidden = false;
            restartAppStatus.classList.remove("text-danger");
            restartAppStatus.classList.add("text-muted");
            restartAppStatus.textContent = "Submitting restart request...";
        }
        try {
            const response = await fetch(restartAppButton.dataset.endpoint || "/api/v1/system/restart", {
                method: "POST",
                credentials: "same-origin",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "X-CSRFToken": getCsrfToken()
                },
                body: JSON.stringify({
                    reason: "Apply settings changes",
                    mode: "auto",
                    delay_seconds: 1
                })
            });
            const payload = await response.json();
            if (!response.ok || !payload.ok) {
                throw new Error((payload.error && payload.error.message) || "Restart request failed.");
            }
            if (restartAppStatus) {
                restartAppStatus.classList.remove("text-danger");
                restartAppStatus.classList.add("text-muted");
                restartAppStatus.textContent = `Restart requested via ${payload.data.mode}.`;
            }
        } catch (error) {
            if (restartAppStatus) {
                restartAppStatus.classList.remove("text-muted");
                restartAppStatus.classList.add("text-danger");
                restartAppStatus.textContent = error.message || "Restart request failed.";
            }
            restartAppButton.disabled = false;
        }
    });
}

// ---------------------------------------------------------------------------
// Updates tab
// ---------------------------------------------------------------------------
const updatePanel = document.getElementById("updatePanel");

if (updatePanel) {
    const endpoint = updatePanel.dataset.endpoint || "/api/v1/system/update";
    const el = (id) => document.getElementById(id);
    const badge = el("updateBadge");
    const checkButton = el("updateCheckButton");
    const installButton = el("updateInstallButton");
    const installLabel = el("updateInstallLabel");
    const message = el("updateMessage");
    const changesWrap = el("updateChangesWrap");
    const changes = el("updateChanges");
    const progressWrap = el("updateProgressWrap");
    const logBox = el("updateLog");
    const stepLabel = el("updateStep");
    let latestTag = null;
    let pollTimer = null;
    let installedVersion = null;

    function showMessage(kind, text) {
        if (!text) {
            message.hidden = true;
            return;
        }
        message.hidden = false;
        message.className = `alert alert-${kind} mb-3`;
        message.textContent = text;
    }

    function formatTime(value) {
        if (!value) {
            return "never";
        }
        const parsed = new Date(value);
        return Number.isNaN(parsed.getTime()) ? value : parsed.toLocaleString();
    }

    function renderChanges(list) {
        changes.textContent = "";
        if (!list || !list.length) {
            changesWrap.hidden = true;
            return;
        }
        for (const item of list) {
            const heading = document.createElement("div");
            heading.className = "font-weight-bold";
            heading.textContent = item.version;
            const notes = document.createElement("pre");
            notes.className = "small mb-3";
            notes.style.whiteSpace = "pre-wrap";
            notes.textContent = item.notes || "";
            changes.appendChild(heading);
            changes.appendChild(notes);
        }
        changesWrap.hidden = false;
    }

    function updaterExplanation(updater) {
        if (updater.mode === "managed") {
            return updater.detail || "This install is updated by its deployment pipeline.";
        }
        if (updater.mode === "error") {
            return `The updater reported a problem: ${updater.detail || "unknown error"}`;
        }
        return "The ARPVPN updater container is not running, so updates cannot be installed from here. " +
            "Docker installs include it from version 3.1.0. See the installation guide for how to add it, " +
            "or update the way you installed ARPVPN.";
    }

    function render(data) {
        if (installedVersion && data.current_version !== installedVersion) {
            showMessage("success", `ARPVPN is now running ${data.current_version}. Reloading...`);
            window.setTimeout(() => window.location.reload(), 2500);
        }
        installedVersion = installedVersion || data.current_version;
        el("updateCurrent").textContent = data.current_version || "unknown";
        el("updateLatest").textContent = data.latest_version || "no published releases found";
        el("updateChecked").textContent = formatTime(data.checked_at);
        latestTag = data.latest_tag;
        badge.hidden = !data.update_available;
        renderChanges(data.update_available ? data.changes : []);

        const job = data.job || {};
        const running = job.state === "running" || job.request_pending;
        if (job.log || running) {
            progressWrap.hidden = false;
            logBox.textContent = job.log || "Waiting for the updater to pick up the request...";
            logBox.scrollTop = logBox.scrollHeight;
            stepLabel.textContent = running ? `(${job.request_pending ? "queued" : job.step || "running"})` : "";
        }

        installButton.hidden = !data.update_available;
        installButton.disabled = !data.can_update;
        installLabel.textContent = data.latest_version ? `Install ${data.latest_version}` : "Install update";

        if (data.check_error) {
            showMessage("warning", data.check_error);
        } else if (running) {
            showMessage("info", "Update in progress. ARPVPN restarts near the end, so this page may lose its connection for a minute.");
        } else if (job.state === "failed") {
            showMessage("danger", job.message || "The last update failed.");
        } else if (data.update_available && !data.can_update) {
            showMessage("secondary", updaterExplanation(data.updater || {}));
        } else if (data.update_available) {
            showMessage("warning", `ARPVPN ${data.latest_version} is available.`);
        } else if (job.state === "success" && job.message) {
            showMessage("success", job.message);
        } else {
            showMessage("success", "ARPVPN is up to date.");
        }

        if (running) {
            schedulePoll(4000);
        }
    }

    function schedulePoll(delay) {
        window.clearTimeout(pollTimer);
        pollTimer = window.setTimeout(() => load(false, true), delay);
    }

    async function load(refresh, polling) {
        try {
            const response = await fetch(`${endpoint}${refresh ? "?refresh=1" : ""}`, {
                credentials: "same-origin",
                headers: {"Accept": "application/json"}
            });
            const payload = await response.json();
            if (!response.ok || !payload.ok) {
                throw new Error((payload.error && payload.error.message) || "Unable to load update status.");
            }
            render(payload.data);
        } catch (error) {
            if (polling) {
                showMessage("info", "ARPVPN is restarting with the new version. Reconnecting...");
                schedulePoll(5000);
            } else {
                showMessage("danger", error.message || "Unable to load update status.");
            }
        }
    }

    checkButton.addEventListener("click", () => load(true, false));

    installButton.addEventListener("click", async () => {
        if (!latestTag) {
            return;
        }
        installButton.disabled = true;
        showMessage("info", "Requesting the update...");
        try {
            const response = await fetch(endpoint, {
                method: "POST",
                credentials: "same-origin",
                headers: {
                    "Content-Type": "application/json",
                    "Accept": "application/json",
                    "X-CSRFToken": getCsrfToken()
                },
                body: JSON.stringify({tag: latestTag})
            });
            const payload = await response.json();
            if (!response.ok || !payload.ok) {
                throw new Error((payload.error && payload.error.message) || "Update request failed.");
            }
            load(false, true);
        } catch (error) {
            showMessage("danger", error.message || "Update request failed.");
            installButton.disabled = false;
        }
    });

    if (window.location.hash === "#updates" && window.jQuery) {
        window.jQuery("#updates-tab").tab("show");
    }
    load(false, false);
}
