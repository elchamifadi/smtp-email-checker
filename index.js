import express from "express";
import dns from "dns/promises";
import SMTPConnection from "smtp-connection";
import os from "os";
import crypto from "crypto";

const app = express();

/* ===== Config (override with env vars) ===== */
const PORT = Number(process.env.PORT || 3000);
const PROBE_FROM = process.env.PROBE_FROM || "probe@nexusautomation.ai";
const HELO_NAME = process.env.HELO_NAME || "checker.nexusautomation.ai";
const CONNECT_TIMEOUT_MS = Number(process.env.CONNECT_TIMEOUT_MS || 10000); // 10s
const SMTP_TIMEOUT_MS = Number(process.env.SMTP_TIMEOUT_MS || 10000);       // 10s
const MAX_MX_TRIES = Number(process.env.MAX_MX_TRIES || 3);                 // try up to 3 MX hosts
const DO_CATCH_ALL_CHECK = (process.env.CATCH_ALL || "true").toLowerCase() === "true";

const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/* Providers that typically block SMTP verification */
const providerBlocks = [
  { name: "gmail", domains: ["gmail.com", "googlemail.com"], mxContains: ["google.com"] },
  { name: "outlook", domains: ["outlook.com", "hotmail.com", "live.com"], mxContains: ["protection.outlook.com", "outlook.com"] },
  { name: "office365", domains: [], mxContains: ["protection.outlook.com"] },
  { name: "yahoo", domains: ["yahoo.com", "ymail.com"], mxContains: ["yahoodns", "yahoo.com"] }
];

/* Health */
app.get("/healthz", (_req, res) => res.status(200).send("OK"));

/* Main check */
app.get("/check", async (req, res) => {
  const started = Date.now();
  const email = String(req.query.email || "").trim();

  if (!emailRegex.test(email)) {
    return res.json(out({ email, status: "invalid_syntax", started }));
  }

  const [localPart, domain] = email.split("@");
  try {
    // 1) MX resolution
    let mxRecords = [];
    try {
      mxRecords = await dns.resolveMx(domain);
      mxRecords.sort((a, b) => a.priority - b.priority);
    } catch (e) {
      return res.json(out({
        email, domain, status: "invalid_domain",
        error: reasonFromErr(e).message,
        started
      }));
    }
    if (!mxRecords.length) {
      return res.json(out({ email, domain, status: "invalid_domain", started }));
    }

    // 1a) Detect providers that block verification
    const provider = detectBlockingProvider(domain, mxRecords);

    // 2) Try up to MAX_MX_TRIES hosts
    let lastErr = null;
    for (const mx of mxRecords.slice(0, MAX_MX_TRIES)) {
      try {
        const result = await smtpProbe(mx.exchange, email);

        // Optional catch-all detection when mailbox seems to exist
        if (DO_CATCH_ALL_CHECK && result.status === "exists") {
          const randomLocal = `${localPart}+${crypto.randomBytes(6).toString("hex")}`;
          const randomAddr = `${randomLocal}@${domain}`;
          try {
            const ca = await smtpProbe(mx.exchange, randomAddr, /*short*/ true);
            if (ca.status === "exists") result.status = "catch_all";
          } catch { /* ignore */ }
        }

        return res.json(out({
          email, domain,
          status: result.status,
          mx_used: mx.exchange,
          smtp_code: result.smtp_code,
          smtp_response: result.smtp_response,
          error: result.error || null,
          started
        }));
      } catch (e) {
        lastErr = e; // try next MX
      }
    }

    // 3) All MX attempts failed
    const errReason = reasonFromErr(lastErr);
    const softFail = ["timeout", "refused", "tls", "network", "temp"].includes(errReason.kind);

    if (provider && softFail) {
      return res.json(out({
        email, domain, status: "provider_blocks_verification",
        error: `${provider.name}: ${errReason.message}`,
        started
      }));
    }

    return res.json(out({
      email, domain, status: "temp_fail",
      error: errReason.message,
      started
    }));
  } catch (e) {
    return res.json(out({
      email, domain, status: "temp_fail",
      error: reasonFromErr(e).message,
      started
    }));
  }
});

/* ===== Helpers ===== */

function detectBlockingProvider(domain, mxRecords) {
  const d = domain.toLowerCase();
  const mxHosts = mxRecords.map(m => m.exchange.toLowerCase());
  for (const p of providerBlocks) {
    const domainHit = p.domains.some(x => x === d);
    const mxHit = p.mxContains.some(snip => mxHosts.some(h => h.includes(snip)));
    if (domainHit || mxHit) return { name: p.name };
  }
  return null;
}

async function smtpProbe(mxHost, targetEmail, short = false) {
  const conn = new SMTPConnection({
    host: mxHost,
    port: 25,
    name: HELO_NAME,
    connectionTimeout: short ? Math.min(4000, CONNECT_TIMEOUT_MS) : CONNECT_TIMEOUT_MS,
    socketTimeout: short ? Math.min(4000, SMTP_TIMEOUT_MS) : SMTP_TIMEOUT_MS,
    tls: { rejectUnauthorized: false }
  });

  let connected = false;
  try {
    await new Promise((resolve, reject) => {
      const onError = (err) => { conn.off("error", onError); try { conn.close(); } catch {} reject(err); };
      conn.on("error", onError);
      conn.connect((err) => {
        conn.off("error", onError);
        if (err) { try { conn.close(); } catch {} return reject(err); }
        connected = true; resolve();
      });
    });

    await sendCmd(conn, `HELO ${HELO_NAME}`);
    await sendCmd(conn, `MAIL FROM:<${PROBE_FROM}>`);
    const { code: rcptCode, text: rcptMsg } = await sendCmd(conn, `RCPT TO:<${targetEmail}>`, true);

    try { conn.quit(); } catch {}
    let status = "temp_fail";
    if (rcptCode >= 200 && rcptCode < 300) status = "exists";
    else if (rcptCode >= 500) status = "does_not_exist";

    return { status, smtp_code: rcptCode, smtp_response: rcptMsg };
  } catch (e) {
    if (connected) { try { conn.close(); } catch {} }
    throw e;
  }
}

function sendCmd(conn, line, capture = false) {
  return new Promise((resolve, reject) => {
    conn.sendCommand(line, false, (err) => {
      if (err) return reject(err);
      const text = String(conn.lastServerResponse || "");
      const m = text.match(/^(\d{3})/m);
      const code = m ? Number(m[1]) : 250;
      if (capture) return resolve({ code, text });
      if (code >= 400) return reject(new Error(text || `SMTP error ${code}`));
      resolve({ code, text });
    });
  });
}

function out({ email, domain = null, status, mx_used = null, smtp_code = null, smtp_response = null, error = null, started }) {
  return {
    email,
    domain,
    status,            // "exists" | "does_not_exist" | "catch_all" | "provider_blocks_verification" | "temp_fail" | "invalid_syntax" | "invalid_domain"
    mx_used,
    smtp_code,
    smtp_response,
    error,
    time_ms: Date.now() - started
  };
}

function reasonFromErr(e) {
  if (!e) return { kind: "unknown", message: "Unknown error" };
  const msg = String(e && e.message ? e.message : e);
  if (/timeout/i.test(msg) || /ETIMEDOUT/.test(msg)) return { kind: "timeout", message: "Connection timeout" };
  if (/ECONNREFUSED/.test(msg)) return { kind: "refused", message: "Connection refused" };
  if (/ENOTFOUND|EAI_AGAIN/.test(msg)) return { kind: "dns", message: "DNS failure" };
  if (/TLS|certificate|handshake/i.test(msg)) return { kind: "tls", message: "TLS error" };
  if (/greet/i.test(msg)) return { kind: "greeting", message: "SMTP greeting error" };
  if (/AggregateError/i.test(msg)) return { kind: "temp", message: "Provider aggregate/anti-abuse response" };
  return { kind: "other", message: msg };
}

app.listen(PORT, "0.0.0.0", () => {
  console.log(`SMTP Checker running on port ${PORT}`);
});
