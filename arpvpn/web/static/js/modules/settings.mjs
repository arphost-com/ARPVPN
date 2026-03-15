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
