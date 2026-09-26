const DEFAULT_PORT = 8080;
const NAME = /^[a-z0-9][a-z0-9.-]{0,62}$/;

async function gatewayPort() {
  const stored = await chrome.storage.sync.get({ port: DEFAULT_PORT });
  const port = Number(stored.port);
  return Number.isInteger(port) && port > 0 && port < 65536 ? port : DEFAULT_PORT;
}

function parseTarget(text) {
  let rest = text.trim().replace(/^internet:\/\//i, "");
  const hash = rest.indexOf("#");
  if (hash >= 0) rest = rest.slice(0, hash);
  const slash = rest.indexOf("/");
  const name = (slash < 0 ? rest : rest.slice(0, slash)).toLowerCase();
  if (!NAME.test(name)) return null;
  return { name, path: slash < 0 ? "/" : rest.slice(slash) };
}

async function targetUrl(text) {
  const port = await gatewayPort();
  const target = parseTarget(text);
  if (!target) {
    return text.trim() ? `http://localhost:${port}/go?url=${encodeURIComponent(text.trim())}` : `http://localhost:${port}/`;
  }
  return `http://${target.name}.localhost:${port}${target.path}`;
}

function open(url, disposition) {
  if (disposition === "currentTab") {
    chrome.tabs.update({ url });
  } else {
    chrome.tabs.create({ url, active: disposition === "newForegroundTab" });
  }
}

chrome.omnibox.setDefaultSuggestion({ description: "Open an internet:// site: <match>name/path</match>" });

chrome.omnibox.onInputChanged.addListener(async (text, suggest) => {
  try {
    const port = await gatewayPort();
    const reply = await fetch(`http://localhost:${port}/_nodes`);
    const data = await reply.json();
    const typed = text.trim().replace(/^internet:\/\//i, "").toLowerCase();
    suggest(
      data.nodes
        .filter((node) => node.name.startsWith(typed.split("/")[0]))
        .slice(0, 8)
        .map((node) => ({ content: `${node.name}/`, description: `internet://<match>${node.name}</match>/` }))
    );
  } catch (error) {
    suggest([]);
  }
});

chrome.omnibox.onInputEntered.addListener(async (text, disposition) => {
  open(await targetUrl(text), disposition);
});

chrome.action.onClicked.addListener(async () => {
  open(`http://localhost:${await gatewayPort()}/`, "newForegroundTab");
});
