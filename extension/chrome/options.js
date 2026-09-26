const field = document.getElementById("port");
const state = document.getElementById("state");

chrome.storage.sync.get({ port: 8080 }).then((stored) => {
  field.value = stored.port;
});

document.getElementById("save").addEventListener("click", async () => {
  const port = Number(field.value);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    state.textContent = "Invalid port";
    return;
  }
  await chrome.storage.sync.set({ port });
  state.textContent = "Saved";
  setTimeout(() => (state.textContent = ""), 1500);
});
