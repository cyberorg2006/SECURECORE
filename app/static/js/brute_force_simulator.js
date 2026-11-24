(() => {
    const form = document.querySelector("[data-simulator-form]");
    const status = document.querySelector("[data-simulator-status]");
    const eventTable = document.querySelector("[data-simulation-events]");
    const runButton = document.querySelector("[data-run-button]");

    if (
        !(form instanceof HTMLFormElement) ||
        !(status instanceof HTMLElement) ||
        !(eventTable instanceof HTMLTableSectionElement) ||
        !(runButton instanceof HTMLButtonElement)
    ) {
        return;
    }

    const summaryNodes = {
        successful: document.querySelector('[data-summary="successful"]'),
        failed: document.querySelector('[data-summary="failed"]'),
        blocked: document.querySelector('[data-summary="blocked"]'),
        completed: document.querySelector('[data-summary="completed"]'),
    };
    const csrfInput = form.querySelector('input[name="csrf_token"]');
    const endpoint = form.getAttribute("data-endpoint");
    const outcomeLabels = {
        success: "Password matched; mock login accepted",
        mfa_required: "Password matched; MFA still required",
        failed: "Rejected by mock authentication",
        blocked_rate_limit: "Blocked by the mock rate limiter",
        blocked_lockout: "Blocked by mock account lockout",
    };

    const delay = (milliseconds) =>
        new Promise((resolve) => window.setTimeout(resolve, milliseconds));

    const updateSummary = (events) => {
        const values = {
            successful: events.filter((event) =>
                ["success", "mfa_required"].includes(event.outcome),
            ).length,
            failed: events.filter((event) => event.outcome === "failed").length,
            blocked: events.filter((event) =>
                event.outcome.startsWith("blocked_"),
            ).length,
            completed: events.filter((event) => event.outcome === "success").length,
        };

        Object.entries(values).forEach(([key, value]) => {
            const node = summaryNodes[key];
            if (node instanceof HTMLElement) {
                node.textContent = String(value);
            }
        });
    };

    form.addEventListener("submit", async (event) => {
        event.preventDefault();
        if (!form.reportValidity()) {
            return;
        }

        if (!(csrfInput instanceof HTMLInputElement) || !endpoint) {
            status.textContent = "The local simulation form is unavailable.";
            return;
        }

        const formData = new FormData(form);
        const attemptCount = Number(formData.get("attempt_count"));
        const scenario = formData.get("scenario");
        if (!Number.isInteger(attemptCount) || attemptCount < 1 || attemptCount > 20) {
            status.textContent = "Choose between 1 and 20 synthetic attempts.";
            return;
        }

        runButton.disabled = true;
        eventTable.replaceChildren();
        updateSummary([]);
        status.textContent = "Running the bounded local mock simulation...";

        try {
            const response = await fetch(endpoint, {
                method: "POST",
                credentials: "same-origin",
                cache: "no-store",
                headers: {
                    "Content-Type": "application/json",
                    "X-CSRFToken": csrfInput.value,
                },
                body: JSON.stringify({
                    attempt_count: attemptCount,
                    scenario,
                }),
            });
            if (response.status === 429) {
                throw new Error(
                    "The local simulator is rate-limited. Wait a minute before another run.",
                );
            }
            const result = await response.json();
            if (!response.ok) {
                throw new Error(result.error || "The simulation request was rejected.");
            }

            const shownEvents = [];
            for (const simulationEvent of result.events) {
                shownEvents.push(simulationEvent);
                const row = document.createElement("tr");
                row.dataset.outcome = simulationEvent.outcome;
                [
                    `#${simulationEvent.attempt_number}`,
                    simulationEvent.guess_label,
                    outcomeLabels[simulationEvent.outcome] || "Recorded",
                    simulationEvent.details,
                ].forEach((value) => {
                    const cell = document.createElement("td");
                    cell.textContent = value;
                    row.appendChild(cell);
                });
                eventTable.appendChild(row);
                updateSummary(shownEvents);
                status.textContent =
                    `Displayed synthetic attempt ${simulationEvent.attempt_number} ` +
                    `of ${result.attempt_count}.`;
                await delay(140);
            }
            status.textContent =
                `Simulation complete. ${result.summary.successful_guesses} ` +
                `password match(es), ${result.summary.failed_guesses} failed, ` +
                `${result.summary.blocked_attempts} blocked.`;
        } catch (error) {
            eventTable.replaceChildren();
            status.textContent =
                error instanceof Error
                    ? error.message
                    : "The simulation could not be completed.";
        } finally {
            runButton.disabled = false;
        }
    });
})();
