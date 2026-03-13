const THEME_STORAGE_KEY = "arpvpn.theme";
const DARK_THEME_COLOR = "#0e1727";
const LIGHT_THEME_COLOR = "#f4f7fb";
const THEME_API_ENDPOINT = "/api/v1/themes";

let mediaQuery = null;

function safeGetStorageItem(key) {
    try {
        return localStorage.getItem(key);
    } catch (e) {
        return null;
    }
}

function safeSetStorageItem(key, value) {
    try {
        localStorage.setItem(key, value);
    } catch (e) {
        // Ignore storage restrictions.
    }
}

function isThemeApiAvailable() {
    return Boolean(document.getElementById("layoutSidenav"));
}

function getCsrfToken() {
    const meta = document.querySelector("meta[name='arpvpn-csrf-token']");
    return meta ? (meta.getAttribute("content") || "").trim() : "";
}

async function fetchThemeChoiceFromApi() {
    if (!isThemeApiAvailable()) return null;
    try {
        const response = await fetch(THEME_API_ENDPOINT, {
            method: "GET",
            credentials: "same-origin",
            headers: {
                "Accept": "application/json"
            }
        });
        const contentType = response.headers.get("content-type") || "";
        if (!response.ok || !contentType.includes("application/json")) {
            return null;
        }
        const payload = await response.json();
        const choice = payload && payload.choice;
        if (choice === "auto" || choice === "light" || choice === "dark") {
            return choice;
        }
    } catch (e) {
        // Ignore API errors and keep local preference.
    }
    return null;
}

async function persistThemeChoiceToApi(choice) {
    if (!isThemeApiAvailable()) return;
    try {
        const csrfToken = getCsrfToken();
        await fetch(THEME_API_ENDPOINT, {
            method: "POST",
            credentials: "same-origin",
            headers: {
                "Content-Type": "application/json",
                "Accept": "application/json",
                ...(csrfToken ? {"X-CSRFToken": csrfToken} : {})
            },
            body: JSON.stringify({choice})
        });
    } catch (e) {
        // Keep local preference even if API persistence fails.
    }
}

function getSystemTheme() {
    if (window.matchMedia && window.matchMedia("(prefers-color-scheme: dark)").matches) {
        return "dark";
    }
    return "light";
}

export function getThemeChoice() {
    const value = safeGetStorageItem(THEME_STORAGE_KEY) || "auto";
    if (value === "light" || value === "dark" || value === "auto") {
        return value;
    }
    return "auto";
}

export function resolveTheme(choice = getThemeChoice()) {
    if (choice === "auto") {
        return getSystemTheme();
    }
    return choice;
}

function getThemeColor(resolvedTheme) {
    return resolvedTheme === "dark" ? DARK_THEME_COLOR : LIGHT_THEME_COLOR;
}

function updateThemeMetaColor(resolvedTheme) {
    const meta = document.querySelector("meta[name='theme-color']");
    if (!meta) return;
    meta.setAttribute("content", getThemeColor(resolvedTheme));
}

function emitThemeChange(choice, resolved) {
    window.dispatchEvent(new CustomEvent("arpvpn:theme-change", {
        detail: { choice, resolved }
    }));
}

export function applyTheme(choice = getThemeChoice()) {
    const resolved = resolveTheme(choice);
    document.documentElement.setAttribute("data-theme-choice", choice);
    document.documentElement.setAttribute("data-theme", resolved);
    updateThemeMetaColor(resolved);
    emitThemeChange(choice, resolved);
    return resolved;
}

export function setThemeChoice(choice) {
    if (!["auto", "light", "dark"].includes(choice)) return;
    safeSetStorageItem(THEME_STORAGE_KEY, choice);
    applyTheme(choice);
    initThemeControls();
    void persistThemeChoiceToApi(choice);
}

function makeChoiceLabel(choice, resolved) {
    if (choice === "auto") {
        return `Auto (${resolved})`;
    }
    return choice.charAt(0).toUpperCase() + choice.slice(1);
}

export function initThemeControls(root = document) {
    const choice = getThemeChoice();
    const resolved = resolveTheme(choice);

    root.querySelectorAll("[data-theme-choice]").forEach((button) => {
        const buttonChoice = button.getAttribute("data-theme-choice");
        if (!buttonChoice) return;
        button.classList.toggle("active", buttonChoice === choice);
        button.setAttribute("aria-pressed", buttonChoice === choice ? "true" : "false");
        button.onclick = () => setThemeChoice(buttonChoice);
    });

    root.querySelectorAll("[data-theme-current]").forEach((current) => {
        current.textContent = makeChoiceLabel(choice, resolved);
    });
}

function initSystemThemeListener() {
    if (!window.matchMedia) return;
    mediaQuery = window.matchMedia("(prefers-color-scheme: dark)");
    mediaQuery.addEventListener("change", () => {
        if (getThemeChoice() !== "auto") return;
        applyTheme("auto");
        initThemeControls();
    });
}

async function init() {
    const apiChoice = await fetchThemeChoiceFromApi();
    if (apiChoice) {
        safeSetStorageItem(THEME_STORAGE_KEY, apiChoice);
    }
    applyTheme(getThemeChoice());
    initThemeControls();
    initSystemThemeListener();
}

window.arpvpnTheme = {
    getThemeChoice,
    resolveTheme,
    applyTheme,
    setThemeChoice,
    initThemeControls
};

if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", () => {
        void init();
    });
} else {
    void init();
}
