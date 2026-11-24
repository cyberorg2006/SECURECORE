const terminalState = document.body.dataset.terminalState;
const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
const successUrl = document.body.dataset.successUrl;

if (terminalState === "failure") {
    window.setTimeout(
        () => window.location.replace(document.body.dataset.homeUrl),
        reducedMotion ? 800 : 2600,
    );
} else if (terminalState === "success") {
    window.setTimeout(
        () => window.location.replace(successUrl),
        reducedMotion ? 600 : 1700,
    );
}
