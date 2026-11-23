const copyButton = document.getElementById("copy-install");
const installCommand = document.getElementById("install-command");
const copyStatus = document.getElementById("copy-status");

if (navigator.clipboard) {
  const label = copyButton.querySelector("span");
  copyButton.hidden = false;
  copyButton.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(installCommand.textContent);
      label.textContent = "Copied";
      copyStatus.textContent = "Install command copied.";
    } catch {
      const range = document.createRange();
      range.selectNodeContents(installCommand);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      label.textContent = "Selected";
      copyStatus.textContent = "Install command selected. Copy it using your browser.";
    }
  });
}
