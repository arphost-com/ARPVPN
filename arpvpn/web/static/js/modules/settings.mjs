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
const generateSelfSigned = document.getElementById("web_tls_generate_self_signed");
const issueLetsencrypt = document.getElementById("web_tls_issue_letsencrypt");

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

    setDisabled(tlsServerName, !needsTlsServerName);
    setDisabled(letsencryptEmail, !isLetsEncrypt);
    setDisabled(proxyIncomingHostname, !isReverseProxy);
    setDisabled(generateSelfSigned, !isSelfSigned);
    setDisabled(issueLetsencrypt, !isLetsEncrypt);

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
