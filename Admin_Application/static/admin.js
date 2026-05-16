(function () {
    const storedTheme = localStorage.getItem("amtel-admin-theme");
    if (storedTheme === "dark") {
        document.documentElement.dataset.theme = "dark";
    }

    const toggle = document.querySelector("[data-theme-toggle]");
    if (toggle) {
        toggle.addEventListener("click", () => {
            const nextTheme = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
            if (nextTheme === "dark") {
                document.documentElement.dataset.theme = "dark";
                localStorage.setItem("amtel-admin-theme", "dark");
            } else {
                delete document.documentElement.dataset.theme;
                localStorage.setItem("amtel-admin-theme", "light");
            }
        });
    }

    if (window.Chart) {
        Chart.defaults.font.family = "'Work Sans', system-ui, -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif";
        Chart.defaults.color = getComputedStyle(document.documentElement).getPropertyValue("--admin-muted").trim() || "#6b7280";
        Chart.defaults.plugins.tooltip.backgroundColor = "rgba(7, 27, 58, 0.94)";
        Chart.defaults.plugins.tooltip.padding = 12;
        Chart.defaults.plugins.tooltip.cornerRadius = 12;
        Chart.defaults.elements.line.borderWidth = 3;
        Chart.defaults.elements.point.radius = 3;
        Chart.defaults.elements.point.hoverRadius = 5;
    }
})();
