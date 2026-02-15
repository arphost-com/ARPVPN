import {prependAlert} from "./utils.mjs";

const alertContainer = "alerts";

function setVisibility(elements, visible) {
    elements.forEach((element) => {
        element.style.display = visible ? "" : "none";
    });
}

const modeField = document.getElementById("mode");
const clientModeFields = Array.from(document.querySelectorAll(".client-fields"));
const siteToSiteModeFields = Array.from(document.querySelectorAll(".site-to-site-fields"));

function updatePeerModeFields() {
    if (!modeField) return;
    const isSiteToSite = modeField.value === "site_to_site";
    setVisibility(clientModeFields, !isSiteToSite);
    setVisibility(siteToSiteModeFields, isSiteToSite);
}

if (modeField) {
    updatePeerModeFields();
    modeField.addEventListener("change", updatePeerModeFields);
}

const privateKeyField = document.getElementById("private_key");
if (privateKeyField) {
    privateKeyField.setAttribute("type", "password");
}

const togglePrivateKey = document.getElementById("togglePrivateKey");
if (togglePrivateKey && privateKeyField) {
    togglePrivateKey.addEventListener("click", function () {
        const icon = document.getElementById("togglePrivateKeyIcon");
        const field = privateKeyField;
        const type = field.getAttribute("type") === "password" ? "text" : "password";
        field.setAttribute("type", type);
        if (!icon) return;
        if (type === "password") {
            icon.classList.add("fa-eye-slash");
            icon.classList.remove("fa-eye");
        } else {
            icon.classList.add("fa-eye");
            icon.classList.remove("fa-eye-slash");
        }
    }, false);
}

const removePeerButton = document.getElementById("removePeer");
if (removePeerButton) {
    removePeerButton.addEventListener("click", function () {
        const alertType = "danger";
        $.ajax({
            type: "delete",
            url: location.href,
            success: function () {
                location.replace("/wireguard");
            },
            error: function (resp) {
                prependAlert(alertContainer, "<strong>Oops, something went wrong</strong>: " + resp["responseText"],
                    alertType);
                $("#removeModal").modal("toggle");
            },
        });
    });
}
