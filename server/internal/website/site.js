const copyButton = document.getElementById("copy-install");
const installCommand = document.getElementById("install-command");

if (navigator.clipboard) {
  copyButton.hidden = false;
  copyButton.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(installCommand.textContent);
      copyButton.textContent = "Copied";
    } catch {
      const range = document.createRange();
      range.selectNodeContents(installCommand);
      const selection = window.getSelection();
      selection.removeAllRanges();
      selection.addRange(range);
      copyButton.textContent = "Selected";
    }
  });
}
