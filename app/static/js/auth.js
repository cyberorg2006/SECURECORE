document.querySelectorAll("[data-password-toggle]").forEach((toggle) => {
    const inputId = toggle.getAttribute("aria-controls");
    const input = inputId ? document.getElementById(inputId) : null;

    if (!(toggle instanceof HTMLButtonElement) || !(input instanceof HTMLInputElement)) {
        return;
    }

    toggle.addEventListener("click", () => {
        const showPassword = input.type === "password";
        input.type = showPassword ? "text" : "password";
        toggle.textContent = showPassword ? "Hide" : "Show";
        toggle.setAttribute(
            "aria-label",
            showPassword ? "Hide password" : "Show password",
        );
        toggle.setAttribute("aria-pressed", String(showPassword));
    });
});
