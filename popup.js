document.addEventListener("DOMContentLoaded", () => {
  const statusEl = document.getElementById("status-text");
  if (statusEl) {
    statusEl.textContent = "Browser TOTP extension is ready.";
  }
});
