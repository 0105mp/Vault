const tokenEl = document.getElementById("token");
const statusEl = document.getElementById("status");

chrome.storage.local.get(["vaultToken"], (result) => {
  if (result.vaultToken) tokenEl.value = result.vaultToken;
});

document.getElementById("save").addEventListener("click", () => {
  const token = tokenEl.value.trim();
  if (!token) {
    statusEl.textContent = "Enter a token first.";
    return;
  }
  chrome.storage.local.set({ vaultToken: token }, () => {
    statusEl.textContent = "Saved. You can close this tab.";
  });
});
