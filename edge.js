/**
 * Lumen v32 Railway edge.
 *
 * TLS is terminated by Railway. This process preserves the raw HTTP Upgrade
 * stream (the key SideRail behavior) and forwards XHTTP requests to loopback
 * Xray. All dashboard/API/native legacy traffic is reverse-proxied to FastAPI.
 * No third-party Node dependencies are used.
 */
"use strict";

const http = require("node:http");
const net = require("node:net");
const crypto = require("node:crypto");
const { spawn } = require("node:child_process");
const { Transform } = require("node:stream");

const PUBLIC_PORT = Number(process.env.PORT || 8080);
const APP_PORT = Number(process.env.LUMEN_APP_PORT || 8001);
const APP_HOST = "127.0.0.1";
const EDGE_SECRET = crypto.randomBytes(32).toString("hex");

const child = spawn(process.env.PYTHON || "python", ["main.py"], {
  cwd: __dirname,
  env: {
    ...process.env,
    PORT: String(APP_PORT),
    LUMEN_EDGE_SECRET: EDGE_SECRET,
  },
  stdio: "inherit",
});

child.on("exit", (code, signal) => {
  console.error(`Lumen application exited (${code ?? signal})`);
  process.exitCode = code || 1;
  server.close(() => process.exit(process.exitCode));
});

function clientIp(req) {
  const forwarded = String(req.headers["x-forwarded-for"] || "");
  return forwarded.split(",")[0].trim() || req.socket.remoteAddress || "";
}

function parseXrayPath(rawUrl) {
  const url = new URL(rawUrl, "http://lumen.internal");
  // XHTTP appends session/action segments to the configured base path. Keep
  // those suffixes when rewriting to Xray's private /lumen base.
  const match = url.pathname.match(
    /^\/xray\/(ws|httpupgrade|xhttp)\/([0-9a-fA-F-]{36})(\/.*)?$/
  );
  if (!match) return null;
  return {
    transport: match[1],
    uuid: match[2].toLowerCase(),
    suffix: match[3] || "",
    location: url.searchParams.get("loc") || "",
    url,
  };
}

function appRequest(options, bodyWriter) {
  return new Promise((resolve, reject) => {
    const request = http.request(
      {
        host: APP_HOST,
        port: APP_PORT,
        ...options,
      },
      resolve
    );
    request.on("error", reject);
    bodyWriter(request);
  });
}

async function routeInfo(req, parsed) {
  const query = parsed.location
    ? `?loc=${encodeURIComponent(parsed.location)}`
    : "";
  const response = await appRequest(
    {
      method: "GET",
      path: `/internal/xray/route/${parsed.transport}/${parsed.uuid}${query}`,
      headers: {
        "x-lumen-edge-secret": EDGE_SECRET,
        "x-client-ip": clientIp(req),
        accept: "application/json",
      },
    },
    (request) => request.end()
  );
  const chunks = [];
  for await (const chunk of response) chunks.push(chunk);
  const body = Buffer.concat(chunks).toString("utf8");
  if (response.statusCode !== 200) {
    const error = new Error(body || "route unavailable");
    error.statusCode = response.statusCode || 503;
    throw error;
  }
  return JSON.parse(body);
}

function reportUsage(uuid, connectionId, bytes) {
  const payload = Buffer.from(
    JSON.stringify({ connection_id: connectionId, bytes })
  );
  const request = http.request({
    host: APP_HOST,
    port: APP_PORT,
    method: "POST",
    path: `/internal/xray/usage/${uuid}`,
    headers: {
      "x-lumen-edge-secret": EDGE_SECRET,
      "content-type": "application/json",
      "content-length": payload.length,
    },
  });
  request.on("error", () => {});
  request.end(payload);
}

function forwardedHeaders(req) {
  return {
    ...req.headers,
    "x-forwarded-for": [
      req.headers["x-forwarded-for"],
      req.socket.remoteAddress,
    ]
      .filter(Boolean)
      .join(", "),
    "x-forwarded-proto": req.headers["x-forwarded-proto"] || "https",
  };
}

class MeterTransform extends Transform {
  constructor(usage) {
    super();
    this.usage = usage;
  }
  _transform(chunk, _encoding, callback) {
    const usage = this.usage;
    usage.bytes += chunk.length;
    if (usage.remaining !== null) {
      usage.remaining -= chunk.length;
      if (usage.remaining < 0) {
        callback(new Error("quota exceeded"));
        return;
      }
    }
    const rate = usage.rate;
    if (!rate) {
      callback(null, chunk);
      return;
    }
    const now = Date.now();
    const ready = Math.max(now, usage.nextAt || now);
    usage.nextAt = ready + Math.ceil((chunk.length * 1000) / rate);
    const wait = Math.max(0, ready - now);
    if (wait) setTimeout(() => callback(null, chunk), wait);
    else callback(null, chunk);
  }
}

function proxyHttp(req, res, targetPort, targetPath, usage) {
  const upstream = http.request(
    {
      host: APP_HOST,
      port: targetPort,
      method: req.method,
      path: targetPath,
      headers: forwardedHeaders(req),
    },
    (upstreamResponse) => {
      res.writeHead(upstreamResponse.statusCode || 502, upstreamResponse.headers);
      if (usage) {
        const meter = new MeterTransform(usage);
        meter.on("error", () => res.destroy());
        upstreamResponse.pipe(meter).pipe(res);
      } else {
        upstreamResponse.pipe(res);
      }
    }
  );
  const finish = () => {
    if (usage && !usage.reported) {
      usage.reported = true;
      reportUsage(usage.uuid, usage.connectionId, usage.bytes);
    }
  };
  res.on("close", finish);
  upstream.on("error", (error) => {
    if (!res.headersSent) res.writeHead(502);
    res.end("upstream unavailable");
    finish();
  });
  if (usage) {
    const meter = new MeterTransform(usage);
    meter.on("error", () => upstream.destroy());
    req.pipe(meter).pipe(upstream);
  } else {
    req.pipe(upstream);
  }
}

function xrayTargetPath(parsed, route) {
  const query = new URLSearchParams(parsed.url.searchParams);
  query.delete("loc");
  const suffix = query.toString();
  return route.path + parsed.suffix + (suffix ? `?${suffix}` : "");
}

const server = http.createServer(async (req, res) => {
  const parsed = parseXrayPath(req.url || "/");
  if (parsed && parsed.transport === "xhttp") {
    try {
      const route = await routeInfo(req, parsed);
      const usage = {
        uuid: parsed.uuid,
        connectionId: route.connection_id,
        bytes: 0,
        reported: false,
        rate: Math.max(0, Number(route.speed_limit_bytes || 0)),
        remaining:
          route.remaining_bytes === null
            ? null
            : Math.max(0, Number(route.remaining_bytes || 0)),
        nextAt: 0,
      };
      proxyHttp(req, res, Number(route.port), xrayTargetPath(parsed, route), usage);
    } catch (error) {
      res.writeHead(error.statusCode || 503, { "content-type": "text/plain" });
      res.end("Xray route unavailable");
    }
    return;
  }
  proxyHttp(req, res, APP_PORT, req.url || "/", null);
});

function rawRequest(req, path) {
  const lines = [`${req.method} ${path} HTTP/${req.httpVersion}`];
  for (let i = 0; i < req.rawHeaders.length; i += 2) {
    lines.push(`${req.rawHeaders[i]}: ${req.rawHeaders[i + 1]}`);
  }
  lines.push("\r\n");
  return Buffer.from(lines.join("\r\n"));
}

function rawUpgrade(req, socket, head, port, path, usage) {
  const upstream = net.connect(port, APP_HOST, () => {
    upstream.write(rawRequest(req, path));
    if (head && head.length) upstream.write(head);
    if (usage) {
      const upload = new MeterTransform(usage);
      const download = new MeterTransform(usage);
      upload.on("error", close);
      download.on("error", close);
      socket.pipe(upload).pipe(upstream);
      upstream.pipe(download).pipe(socket);
    } else {
      socket.pipe(upstream);
      upstream.pipe(socket);
    }
  });
  let closed = false;
  const close = () => {
    if (closed) return;
    closed = true;
    upstream.destroy();
    socket.destroy();
    if (usage) reportUsage(usage.uuid, usage.connectionId, usage.bytes);
  };
  upstream.on("error", close);
  socket.on("error", close);
  upstream.on("close", close);
  socket.on("close", close);
}

server.on("upgrade", async (req, socket, head) => {
  const parsed = parseXrayPath(req.url || "/");
  if (!parsed || parsed.transport === "xhttp") {
    rawUpgrade(req, socket, head, APP_PORT, req.url || "/", null);
    return;
  }
  try {
    const route = await routeInfo(req, parsed);
    rawUpgrade(req, socket, head, Number(route.port), route.path, {
      uuid: parsed.uuid,
      connectionId: route.connection_id,
      bytes: 0,
      rate: Math.max(0, Number(route.speed_limit_bytes || 0)),
      remaining:
        route.remaining_bytes === null
          ? null
          : Math.max(0, Number(route.remaining_bytes || 0)),
      nextAt: 0,
    });
  } catch {
    socket.write("HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\n\r\n");
    socket.destroy();
  }
});

server.listen(PUBLIC_PORT, "0.0.0.0", () => {
  console.log(`Lumen v32 edge listening on ${PUBLIC_PORT}; app on ${APP_PORT}`);
});

function shutdown(signal) {
  server.close();
  if (!child.killed) child.kill(signal);
  setTimeout(() => process.exit(0), 5000).unref();
}
process.on("SIGTERM", () => shutdown("SIGTERM"));
process.on("SIGINT", () => shutdown("SIGINT"));