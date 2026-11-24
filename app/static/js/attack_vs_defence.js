(() => {
    const root = document.querySelector("[data-dashboard]");
    const status = document.querySelector("[data-dashboard-status]");
    const filter = document.querySelector("[data-scenario-filter]");
    const comparisonChart = document.querySelector("[data-comparison-chart]");
    const timelineChart = document.querySelector("[data-timeline-chart]");

    if (
        !(root instanceof HTMLElement) ||
        !(status instanceof HTMLElement) ||
        !(filter instanceof HTMLSelectElement) ||
        !(comparisonChart instanceof HTMLElement) ||
        !(timelineChart instanceof HTMLElement)
    ) {
        return;
    }

    const endpoint = root.getAttribute("data-endpoint");
    const numberFormatter = new Intl.NumberFormat();
    const percentageKeys = new Set([
        "defence_success_percent",
        "rate_limiting_effectiveness_percent",
        "account_lockout_effectiveness_percent",
        "mfa_protection_percent",
    ]);
    const percentage = (value) =>
        value === null ? "N/A" : `${Number(value).toFixed(1)}%`;

    const setStat = (key, value) => {
        const node = root.querySelector(`[data-stat="${key}"]`);
        if (node instanceof HTMLElement) {
            node.textContent =
                percentageKeys.has(key)
                    ? percentage(value)
                    : numberFormatter.format(value);
        }
    };

    const showEmptyMessage = (node, text) => {
        const message = document.createElement("p");
        message.className = "dashboard-empty";
        message.textContent = text;
        node.replaceChildren(message);
    };

    const renderComparison = (items, hasData) => {
        if (!hasData || items.length === 0) {
            showEmptyMessage(comparisonChart, "No simulation records for this selection yet.");
            return;
        }

        const maximum = Math.max(...items.map((item) => item.total), 1);
        const outcomes = ["failed", "blocked", "completed", "mfa_challenges"];
        const rows = items.map((item) => {
            const row = document.createElement("div");
            row.className = "comparison-row";

            const label = document.createElement("span");
            label.className = "comparison-label";
            label.textContent = item.label;

            const track = document.createElement("div");
            track.className = "comparison-track";
            track.setAttribute("role", "img");
            track.setAttribute(
                "aria-label",
                `${item.label}: ${item.total} attempts, ${item.failed} failed, ` +
                    `${item.blocked} blocked, ${item.completed} completed, ` +
                    `${item.mfa_challenges} held for MFA`,
            );

            outcomes.forEach((outcome) => {
                const amount = item[outcome];
                if (!amount) {
                    return;
                }
                const segment = document.createElement("span");
                segment.className = "comparison-segment";
                segment.dataset.series = outcome;
                segment.style.width = `${(amount / maximum) * 100}%`;
                segment.title = `${outcome.replace("_", " ")}: ${amount}`;
                track.appendChild(segment);
            });

            const total = document.createElement("span");
            total.className = "comparison-total";
            total.textContent = numberFormatter.format(item.total);
            row.append(label, track, total);
            return row;
        });
        comparisonChart.replaceChildren(...rows);
    };

    const renderTimeline = (items, hasData) => {
        if (!hasData) {
            showEmptyMessage(timelineChart, "No attempts recorded in the last 24 hours.");
            return;
        }

        const maximum = Math.max(...items.map((item) => item.attempts), 1);
        const bars = items.map((item, index) => {
            const bar = document.createElement("div");
            bar.className = "timeline-bar";
            bar.setAttribute("role", "img");
            bar.setAttribute(
                "aria-label",
                `${item.label}: ${item.attempts} attempts, ${item.failed} failed, ` +
                    `${item.blocked} blocked, ${item.completed} logins completed, ` +
                    `${item.mfa_challenges} held for MFA`,
            );
            bar.title = `${item.label}: ${item.attempts} attempt(s)`;

            ["failed", "blocked", "completed", "mfa_challenges"].forEach((outcome) => {
                const amount = item[outcome];
                if (!amount) {
                    return;
                }
                const segment = document.createElement("span");
                segment.dataset.series = outcome;
                segment.style.height = `${(amount / maximum) * 100}%`;
                bar.appendChild(segment);
            });

            const label = document.createElement("span");
            label.className = "timeline-label";
            label.textContent = index % 6 === 0 ? item.label : "";
            label.setAttribute("aria-hidden", "true");
            bar.appendChild(label);
            return bar;
        });
        timelineChart.replaceChildren(...bars);
    };

    const render = (data) => {
        const { stats } = data;
        [
            "total_attacks",
            "failed_password_guesses",
            "blocked_attempts",
            "successful_simulated_guesses",
            "defence_success_percent",
            "rate_limiting_effectiveness_percent",
            "rate_limit_blocks",
            "rate_limited_attempts",
            "account_lockout_effectiveness_percent",
            "lockout_blocks",
            "lockout_attempts",
            "mfa_protection_percent",
            "mfa_challenges",
            "mfa_completed_logins",
            "mfa_password_matches",
        ].forEach((key) => setStat(key, stats[key]));

        const defenceDetail = root.querySelector('[data-stat-detail="defence"]');
        if (defenceDetail instanceof HTMLElement) {
            defenceDetail.textContent =
                `${numberFormatter.format(stats.defence_stops)} control stop(s) recorded`;
        }

        renderComparison(data.comparison, data.has_data);
        renderTimeline(data.timeline, data.has_data);
        const updatedAt = new Date(data.updated_at);
        const updatedNode = root.querySelector("[data-dashboard-updated]");
        if (updatedNode instanceof HTMLElement) {
            updatedNode.textContent = `Updated ${updatedAt.toLocaleTimeString()}`;
        }
        status.textContent = data.has_data
            ? "Live statistics from recorded local mock attempts."
            : "No simulation records match this selection yet.";
    };

    const loadDashboard = async () => {
        if (!endpoint) {
            status.textContent = "The dashboard data endpoint is unavailable.";
            return;
        }

        const url = new URL(endpoint, window.location.href);
        url.searchParams.set("scenario", filter.value);
        try {
            const response = await fetch(url, {
                credentials: "same-origin",
                cache: "no-store",
                headers: { Accept: "application/json" },
            });
            const result = await response.json();
            if (!response.ok) {
                throw new Error(result.error || "Statistics could not be loaded.");
            }
            render(result);
        } catch (error) {
            status.textContent =
                error instanceof Error
                    ? error.message
                    : "Statistics could not be loaded.";
        }
    };

    filter.addEventListener("change", loadDashboard);
    loadDashboard();
    window.setInterval(loadDashboard, 15000);
})();
