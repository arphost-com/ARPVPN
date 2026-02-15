const THEME_STORAGE_KEY = "arpvpn.theme";
const DARK_THEME_COLOR = "#0e1727";
const LIGHT_THEME_COLOR = "#f4f7fb";

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

function init() {
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
    document.addEventListener("DOMContentLoaded", init);
} else {
    init();
}
