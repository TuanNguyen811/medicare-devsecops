// Rich-text editor for doctor notes on the record page: a contenteditable area with a
// small formatting toolbar; the HTML is copied into the hidden "body" field on submit.
document.querySelectorAll("form[data-rich-note]").forEach((form) => {
  const editor = form.querySelector("[contenteditable]");
  const field = form.querySelector('input[name="body"]');
  form.querySelectorAll("[data-cmd]").forEach((button) => {
    button.addEventListener("click", () => {
      editor.focus();
      document.execCommand(button.dataset.cmd);
    });
  });
  form.addEventListener("submit", () => {
    field.value = editor.innerHTML.trim();
  });
});
