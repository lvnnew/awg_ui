/**
 * Shared panel UI helpers (theme, toasts, modals, shell, api).
 * Loaded from base.html for authenticated pages.
 */
(function () {
  "use strict";

  window.I18N = window.I18N || {};
  window._ = window._ || function (key) {
    return window.I18N[key] || key;
  };

  /* Theme */
  function updateThemeButtons() {
    const isLight = document.documentElement.getAttribute("data-theme") === "light";
    document.querySelectorAll("[data-theme-toggle]").forEach(function (btn) {
      btn.textContent = isLight ? "☀" : "☾";
    });
  }

  window.toggleTheme = function () {
    const current = document.documentElement.getAttribute("data-theme") || "dark";
    const next = current === "dark" ? "light" : "dark";
    document.documentElement.setAttribute("data-theme", next);
    localStorage.setItem("theme", next);
    updateThemeButtons();
  };

  /* Sidebar */
  window.toggleSidebar = function (force) {
    const open = typeof force === "boolean" ? force : !document.body.classList.contains("sidebar-open");
    document.body.classList.toggle("sidebar-open", open);
  };

  /* Active nav */
  function markActiveNav() {
    const path = window.location.pathname;
    document.querySelectorAll(".app-sidebar-nav .nav-link, .section-nav a").forEach(function (link) {
      const href = link.getAttribute("href") || "";
      const clean = href.split("?")[0];
      let active = false;
      if (clean === "/" && path === "/") active = true;
      else if (clean === "/settings" && path.startsWith("/settings")) {
        const want = new URL(href, window.location.origin).searchParams.get("section") || "appearance";
        const have = new URLSearchParams(window.location.search).get("section") || "appearance";
        active = link.classList.contains("section-link") ? want === have : true;
        if (!link.classList.contains("section-link")) active = path.startsWith("/settings");
      } else if (clean !== "/" && path.startsWith(clean)) active = true;
      link.classList.toggle("active", active);
    });
    // section panels
    const section = new URLSearchParams(window.location.search).get("section") || "appearance";
    document.querySelectorAll(".settings-section").forEach(function (el) {
      el.classList.toggle("active", el.getAttribute("data-section") === section);
    });
    document.querySelectorAll(".section-nav a.section-link").forEach(function (a) {
      const want = new URL(a.href).searchParams.get("section") || "appearance";
      a.classList.toggle("active", want === section);
    });
  }

  /* Toasts */
  window.showToast = function (message, type) {
    type = type || "info";
    const container = document.getElementById("toastContainer");
    if (!container) return;
    const toast = document.createElement("div");
    toast.className = "toast toast-" + type;
    const icons = { success: "✓", error: "✕", info: "ℹ" };
    toast.innerHTML = "<span>" + (icons[type] || "ℹ") + "</span> <span></span>";
    toast.querySelectorAll("span")[1].textContent = message;
    container.appendChild(toast);
    setTimeout(function () {
      toast.style.opacity = "0";
      toast.style.transform = "translateX(100%)";
      toast.style.transition = "all 0.3s ease";
      setTimeout(function () {
        toast.remove();
      }, 300);
    }, 4000);
  };

  /* Modals */
  window.openModal = function (id) {
    const modal = document.getElementById(id);
    if (modal) {
      modal.classList.add("active");
      document.body.style.overflow = "hidden";
    }
  };

  window.closeModal = function (id) {
    const modal = document.getElementById(id);
    if (modal) {
      modal.classList.remove("active");
      document.body.style.overflow = "";
    }
  };

  document.addEventListener("click", function (e) {
    if (e.target.classList.contains("modal-backdrop") && e.target.classList.contains("active")) {
      e.target.classList.remove("active");
      document.body.style.overflow = "";
    }
    if (e.target.classList.contains("sidebar-backdrop")) {
      window.toggleSidebar(false);
    }
  });

  document.addEventListener("keydown", function (e) {
    if (e.key === "Escape") {
      document.querySelectorAll(".modal-backdrop.active").forEach(function (m) {
        m.classList.remove("active");
      });
      document.body.style.overflow = "";
      window.toggleSidebar(false);
    }
  });

  /* API */
  window.apiCall = async function (url, method, body) {
    method = method || "GET";
    const opts = { method: method, headers: { "Content-Type": "application/json" } };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(url, opts);
    if (res.status === 401 || res.status === 403) {
      window.location.href = "/login";
      throw new Error("Session expired");
    }
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || "Unknown error");
    return data;
  };

  window.copyToClipboard = async function (text) {
    try {
      await navigator.clipboard.writeText(text);
      showToast(_("copied_to_clipboard"), "success");
    } catch (e) {
      const ta = document.createElement("textarea");
      ta.value = text;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand("copy");
      ta.remove();
      showToast(_("copied_to_clipboard"), "success");
    }
  };

  window.downloadFile = function (content, filename) {
    const blob = new Blob([content], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  };

  document.addEventListener("DOMContentLoaded", function () {
    updateThemeButtons();
    markActiveNav();
  });
})();
