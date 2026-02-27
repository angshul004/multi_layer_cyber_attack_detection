function initTooltips() {
  if (!window.bootstrap) return;
  const tooltipTriggerList = [].slice.call(document.querySelectorAll('[data-bs-toggle="tooltip"]'));
  tooltipTriggerList.forEach((el) => new window.bootstrap.Tooltip(el));
}

function setButtonLoading(button, loadingText = "Loading...") {
  if (!button) return () => {};
  const original = button.innerHTML;
  button.disabled = true;
  button.innerHTML = `<span class="spinner-border spinner-border-sm me-2" role="status" aria-hidden="true"></span>${loadingText}`;
  return () => {
    button.disabled = false;
    button.innerHTML = original;
  };
}
