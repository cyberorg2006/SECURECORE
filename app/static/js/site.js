const navToggle = document.querySelector("[data-nav-toggle]");
const navLinks = document.querySelector("[data-nav-links]");
const navbar = navToggle instanceof HTMLButtonElement
    ? navToggle.closest(".navbar")
    : null;

if (
    navToggle instanceof HTMLButtonElement &&
    navLinks instanceof HTMLElement &&
    navbar instanceof HTMLElement
) {
    const mobileMenuQuery = window.matchMedia("(max-width: 680px)");

    const syncNavigation = () => {
        const isMobile = mobileMenuQuery.matches;
        navbar.classList.toggle("has-mobile-menu", isMobile);
        navToggle.hidden = !isMobile;
        navLinks.hidden = isMobile;
        navLinks.classList.remove("is-open");
        navToggle.setAttribute("aria-expanded", "false");
    };

    syncNavigation();
    if (typeof mobileMenuQuery.addEventListener === "function") {
        mobileMenuQuery.addEventListener("change", syncNavigation);
    } else {
        mobileMenuQuery.addListener(syncNavigation);
    }

    navToggle.addEventListener("click", () => {
        const isOpen = navLinks.hidden;
        navLinks.hidden = !isOpen;
        navLinks.classList.toggle("is-open", isOpen);
        navToggle.setAttribute("aria-expanded", String(isOpen));
    });

    navLinks.addEventListener("click", (event) => {
        if (event.target instanceof Element && event.target.closest("a")) {
            navLinks.hidden = true;
            navLinks.classList.remove("is-open");
            navToggle.setAttribute("aria-expanded", "false");
        }
    });

    document.addEventListener("keydown", (event) => {
        if (event.key === "Escape" && !navLinks.hidden) {
            navLinks.hidden = true;
            navLinks.classList.remove("is-open");
            navToggle.setAttribute("aria-expanded", "false");
            navToggle.focus();
        }
    });
}
