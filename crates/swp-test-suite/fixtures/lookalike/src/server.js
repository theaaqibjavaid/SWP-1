const http = require("node:http");
const { pickTheme, themeList } = require("./palette");

const LISTEN_PORT = 8080;
const HEALTH_TTL = 30;

function bodyFor(url) {
  const parts = url.split("/");
  if (parts[1] === "themes") {
    return JSON.stringify(themeList(4));
  }
  if (parts[1] === "theme") {
    const index = Number.parseInt(parts[2] ?? "0", 10);
    return JSON.stringify(pickTheme(index));
  }
  return JSON.stringify({ ok: true, ttl: HEALTH_TTL });
}

const server = http.createServer((req, res) => {
  const payload = bodyFor(req.url ?? "/");
  res.writeHead(200, { "content-type": "application/json" });
  res.end(payload);
});

if (require.main === module) {
  server.listen(LISTEN_PORT, () => {
    console.log("themes listening on", LISTEN_PORT);
  });
}

module.exports = { server, bodyFor, LISTEN_PORT };
