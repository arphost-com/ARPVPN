function setSubmitFeedback(form, submitter) {
    const control = submitter || form.querySelector('button[type="submit"], input[type="submit"]');
    if (!control) {
        return;
    }

    control.disabled = true;
    control.setAttribute("aria-busy", "true");
    const pendingText = form.dataset.submittingText || "Working…";
    if (control.tagName === "INPUT") {
        control.value = pendingText;
    } else {
        control.textContent = pendingText;
    }
}

for (const form of document.querySelectorAll("form[data-submit-feedback]")) {
    form.addEventListener("submit", (event) => {
        const confirmation = form.dataset.confirm;
        if (confirmation && !window.confirm(confirmation)) {
            event.preventDefault();
            return;
        }
        form.setAttribute("aria-busy", "true");
        setSubmitFeedback(form, event.submitter);
    });
}
