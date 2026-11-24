(() => {
    const root = document.querySelector("[data-security-monitor]");
    const filterForm = document.querySelector("[data-security-filters]");
    const status = document.querySelector("[data-monitor-status]");
    const eventTable = document.querySelector("[data-security-events]");
    const alertList = document.querySelector("[data-security-alerts]");
    const timeline = document.querySelector("[data-security-timeline]");
    const filterButton = document.querySelector("[data-filter-button]");

    if (
        !(root instanceof HTMLElement) ||
        !(filterForm instanceof HTMLFormElement) ||
        !(status instanceof HTMLElement) ||
        !(eventTable instanceof HTMLTableSectionElement) ||
        !(alertList instanceof HTMLElement) ||
        !(timeline instanceof HTMLElement) ||
        !(filterButton instanceof HTMLButtonElement)
    ) {
        return;
    }

    const endpoint = root.getAttribute("data-endpoint");
    const numberFormatter = new Intl.NumberFormat();
    const seriesNames = [
        "successful_logins",
        "failed_logins",
        "lockouts",
        "mfa_activity",
    ];

    const textCell = (value) => {
        const cell = document.createElement("td");
        cell.textContent = value;
        return cell;
    };

    const formatDateTime = (value) => {
        const date = new Date(value);
        return Number.isNaN(date.getTime())
            ? "Unknown time"
            : `${date.toLocaleDateString()} ${date.toLocaleTimeString()}`;
    };

    const setStats = (stats) => {
        Object.entries(stats).forEach(([key, value]) => {
            const node = root.querySelector(`[data-stat="${key}"]`);
            if (node instanceof HTMLElement) {
                node.textContent = numberFormatter.format(value);
            }
        });
    };

    const renderEvents = (events) => {
        if (events.length === 0) {
            const row = document.createElement("tr");
            const cell = textCell("No recorded events match these filters.");
            cell.colSpan = 5;
            row.appendChild(cell);
            eventTable.replaceChildren(row);
            return;
        }

        const rows = events.map((event) => {
            const row = document.createElement("tr");
            row.dataset.severity = event.severity;
            row.append(
                textCell(formatDateTime(event.timestamp)),
                textCell(event.label),
                textCell(event.actor),
            );
            const severity = textCell(
                `${event.severity.toUpperCase()} · ${event.risk_score}`,
            );
            severity.className = "security-severity-cell";
            row.append(severity, textCell(event.details));
            return row;
        });
        eventTable.replaceChildren(...rows);
    };

    const renderAlerts = (alerts) => {
        const count = root.querySelector("[data-alert-count]");
        if (count instanceof HTMLElement) {
            count.textContent = numberFormatter.format(alerts.length);
        }
        if (alerts.length === 0) {
            const empty = document.createElement("p");
            empty.className = "security-empty-state";
            empty.textContent = "No matching risk indicators were detected.";
            alertList.replaceChildren(empty);
            return;
        }

        const items = alerts.map((alert) => {
            const item = document.createElement("article");
            item.className = "security-alert";
            item.dataset.severity = alert.severity;

            const heading = document.createElement("div");
            heading.className = "security-alert-heading";
            const title = document.createElement("h3");
            title.textContent = alert.title;
            const score = document.createElement("span");
            score.textContent = `${alert.severity.toUpperCase()} · ${alert.risk_score}`;
            heading.append(title, score);

            const actor = document.createElement("p");
            actor.className = "security-alert-actor";
            actor.textContent = alert.actor;
            const detail = document.createElement("p");
            detail.textContent = alert.details;
            const time = document.createElement("time");
            time.dateTime = alert.timestamp;
            time.textContent = formatDateTime(alert.timestamp);
            item.append(heading, actor, detail, time);
            return item;
        });
        alertList.replaceChildren(...items);
    };

    const renderTimeline = (items) => {
        if (items.length === 0) {
            timeline.textContent = "No activity for the selected dates.";
            return;
        }
        const totals = items.map((item) =>
            seriesNames.reduce((sum, key) => sum + item[key], 0),
        );
        const maximum = Math.max(...totals, 1);
        const labelStep = Math.max(1, Math.ceil(items.length / 10));
        timeline.style.gridTemplateColumns =
            `repeat(${items.length}, minmax(0, 1fr))`;
        const bars = items.map((item, index) => {
            const total = seriesNames.reduce((sum, key) => sum + item[key], 0);
            const bar = document.createElement("div");
            bar.className = "security-timeline-bar";
            bar.setAttribute("role", "img");
            bar.setAttribute(
                "aria-label",
                `${item.date}: ${item.successful_logins} successful logins, ` +
                    `${item.failed_logins} failed attempts, ${item.lockouts} lockouts, ` +
                    `${item.mfa_activity} MFA events`,
            );
            bar.title = `${item.date}: ${total} activity record(s)`;

            seriesNames.forEach((key) => {
                if (!item[key]) {
                    return;
                }
                const segment = document.createElement("span");
                segment.dataset.series = key;
                segment.style.height = `${(item[key] / maximum) * 100}%`;
                bar.appendChild(segment);
            });

            const label = document.createElement("span");
            label.className = "security-timeline-label";
            if (index % labelStep === 0 || index === items.length - 1) {
                const day = new Date(`${item.date}T00:00:00Z`);
                label.textContent = day.toLocaleDateString(undefined, {
                    month: "short",
                    day: "numeric",
                    timeZone: "UTC",
                });
            }
            label.setAttribute("aria-hidden", "true");
            bar.appendChild(label);
            return bar;
        });
        timeline.replaceChildren(...bars);
    };

    const loadMonitoringData = async (event) => {
        if (event) {
            event.preventDefault();
        }
        if (!endpoint) {
            status.textContent = "The monitoring data endpoint is unavailable.";
            return;
        }

        const formData = new FormData(filterForm);
        const startDate = formData.get("start_date");
        const endDate = formData.get("end_date");
        if (
            typeof startDate !== "string" ||
            typeof endDate !== "string" ||
            startDate > endDate
        ) {
            status.textContent = "Choose a valid date range.";
            return;
        }

        filterButton.disabled = true;
        const url = new URL(endpoint, window.location.href);
        for (const [key, value] of formData.entries()) {
            if (typeof value === "string" && value) {
                url.searchParams.set(key, value);
            }
        }

        try {
            const response = await fetch(url, {
                credentials: "same-origin",
                cache: "no-store",
                headers: { Accept: "application/json" },
            });
            const result = await response.json();
            if (!response.ok) {
                throw new Error(result.error || "Security data could not be loaded.");
            }

            setStats(result.stats);
            renderTimeline(result.timeline);
            renderEvents(result.events);
            renderAlerts(result.alerts);
            const updated = root.querySelector("[data-monitor-updated]");
            if (updated instanceof HTMLElement) {
                updated.textContent = `Updated ${new Date().toLocaleTimeString()}`;
            }
            status.textContent =
                `Showing recorded activity from ${result.filters.start_date} ` +
                `through ${result.filters.end_date}.`;
        } catch (error) {
            status.textContent =
                error instanceof Error
                    ? error.message
                    : "Security data could not be loaded.";
        } finally {
            filterButton.disabled = false;
        }
    };

    filterForm.addEventListener("submit", loadMonitoringData);
    loadMonitoringData();
    window.setInterval(() => loadMonitoringData(), 20000);
})();
