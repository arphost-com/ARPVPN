import {postJSON, prependAlert} from "./utils.mjs";

const ifaceName = $("#name");
const gwIface = $("#gateway");
const onUp = $("#on_up")
const onDown = $("#on_down")
const localRoutesEnabled = $("#local_routes_enabled")
const localRoutesFields = $("#localRoutesFields")
const alertContainer = "alerts";

let oldName = ifaceName.val();
let oldGw = gwIface.val();

function replaceOnUpDownComands(oldVal, newVal) {
    let value = onUp.val();
    value = value.replaceAll(oldVal, newVal);
    onUp.val(value);

    value = onDown.val();
    value = value.replaceAll(oldVal, newVal);
    onDown.val(value);
}

ifaceName.focusout(function () {
    const newName = ifaceName.val();
    if (!newName) return;
    replaceOnUpDownComands(oldName, newName);
    oldName = newName;
});

gwIface.change(function () {
    const newGw = gwIface.val();
    if (!newGw) return;
    replaceOnUpDownComands(oldGw, newGw);
    oldGw = newGw;
});

function updateLocalRoutesVisibility() {
    if (localRoutesEnabled.is(":checked")) {
        localRoutesFields.show();
    } else {
        localRoutesFields.hide();
    }
}

localRoutesEnabled.change(updateLocalRoutesVisibility);
updateLocalRoutesVisibility();

const privateKeyField = document.getElementById("private_key");
const togglePrivateKeyButton = document.getElementById("togglePrivateKey");
if (privateKeyField && togglePrivateKeyButton) {
    privateKeyField.setAttribute("type", "password");
    togglePrivateKeyButton.addEventListener("click", function () {
        const icon = document.getElementById("togglePrivateKeyIcon")
        const field = document.getElementById("private_key");
        const type = field.getAttribute("type") === "password" ? "text" : "password";
        field.setAttribute("type", type);
        if (type === "password") {
            icon.classList.add("fa-eye-slash");
            icon.classList.remove("fa-eye");
        }
        else {
            icon.classList.add("fa-eye");
            icon.classList.remove("fa-eye-slash");
        }
    }, false);
}

const removeIfaceBtn = $(".removeIfaceBtn");
removeItem(removeIfaceBtn, "interface", function () {
    location.replace("/wireguard");
});

const removePeerBtn = $(".removePeerBtn");
removeItem(removePeerBtn, "peer", function () {
    location.reload();
});

function removeItem(removeBtn, itemType, onSuccess) {
    removeBtn.click(function (e) {
        const item = e.target.id.split("-")[1];
        const url = "/wireguard/"+itemType+"s/"+item;
        const alertType = "danger";
        $.ajax({
            type: "delete",
            url: url,
            success: onSuccess,
            error: function(resp) {
                prependAlert(alertContainer, "<strong>Oops, something went wrong</strong>: " + resp["responseText"],
                    alertType);
                $("#removeModal").modal("toggle");
            },
        });
    });
}

const startOrStopIfaceBtn = $(".startOrStopIfaceBtn");
startOrStopIfaceBtn.click(function (e) {
    const button = e.target;
    const iface = button.value;
    const action = button.innerText;

    const url = `/wireguard/interfaces/${iface}/${action}`;
    const alertType = "danger";
    const loadFeedback = "wgIface-" + iface + "-loading"

    postJSON(url, alertContainer, alertType, loadFeedback);
});
