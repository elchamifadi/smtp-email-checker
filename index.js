import express from "express";
import dns from "dns/promises";
import SMTPConnection from "smtp-connection";
import os from "os";

const app = express();

/* ========== Config (defaults for nexusautomation.ai) ========== */
const PORT = Number(process.env.PORT || 8080);
// Envelope sender used in MAIL FROM:
const PROBE_FROM = process.env.PROBE_FROM || "probe@nexusautomation.ai";
// Hostname used in HELO/EHLO:
const HELO_NAME = process.env.HELO_NAME || "checker.nexusautomation.ai";
// Timeouts (ms)
const CONNECT_TIMEOUT_MS = Number(process.env.CONNECT_TIMEOUT_MS || 6000);
const SMTP_TIMEOUT_MS = Number(process.env.SMTP_TIMEOUT_MS || 6000);

/* Pragmatic email gate (keeps obvious bad input out) */
const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

/* Health check */
app.get("/healthz", (_req, res) => res.status(200).send("OK"));

/* Main endpoint */
app.get("/check", async (req, res) => {
  const email = String(req.query.email || "").trim();
  const started = Date.now();

  if (!emailRegex.test(email)) {
    return res.json(out({ email, status: "invalid_syntax", started }));
  }

  const domain = email.split("@")[1].toLowerCase();

  try {
    // 1) Resolve MX in priority order
    let mxRecords = [];
    try {
      mxRecords = await dns.resolveMx(domain);
      mxRecords.sort((a, b) => a.priority - b.priority);
    } catch {
      mxRecords = [];
    }
    if (!mxRecords.length) {
      return res.json(out({ email, domain, status: "invalid_domain", started }));
    }

    // 2) Use the top-priority MX
    const mxHost = mxRecords[0].exchange;

    // 3) Connect to SMTP with robust error handling
    const conn = new SMTPConnection({
      host: mxHost,
      port: 25,
      name: HELO_NAME,
      connectionTimeout: CONNECT_TIMEOUT_MS,
      socketTimeout: SMTP_TIMEOUT_MS,
      tls: { rejectUnauthorized: false }
    });

    let connected = false;
    try {
      await new Promise((resolve, reject) => {
        const onError = (err) => {
          conn.off("error", onError);
          try { conn.close(); } catch {}
          reject(err);
        };
        conn.on("error", onError);
        conn.connect((err) => {
          conn.off("error", onError);
          if (err) {
            try { conn.close(); } catch {}
            return reject(err);
          }
          connected = true;
          resolve();
        });
      });

      // HELO
      await sendCmd(conn, `HELO ${HELO_NAME}`);
      // MAIL FROM (envelope sender)
      await sendCmd(conn, `MAIL FROM:<${PROBE_FROM}>`);
      // RCPT TO (target) — capture reply
      const { code: rcptCode, text: rcptMsg } = await sendCmd(conn, `RCPT TO:<${email}>`, true);

      let status = "temp_fail";
      if (rcptCode >= 200 && rcptCode < 300) status = "exists";
      else if (rcptCode >= 500) status = "does_not_exist";

      try { conn.quit(); } catch {}
      return res.json(out({
        email, domain, status,
        mx_used: mxHost,
        smtp_code: rcptCode,
        smtp_response: rcptMsg,
        started
      }));
    } catch (err) {
      if (connected) {
        try { conn.close(); } catch {}
      }
      return res.json(out({
        email, domain, status: "temp_fail",
        error: String(err && err.message ? err.message : err),
        started
      }));
    }
  } catch (err) {
    return res.json(out({
      email, domain, status: "temp_fail",
      error: String(err && err.message ? err.message : err),
      started
    }));
  }
});

/* Helpers */
function out({ email, domain = null, status, mx_used = null, smtp_code = null, smtp_response = null, error = null, started }) {
  return {
    email,
    domain,
    status,            // "exists" | "does_not_exist" | "temp_fail" | "invalid_syntax" | "invalid_domain"
    mx_used,
    smtp_code,
    smtp_response,
    error,
    time_ms: Date.now() - started
  };
}

// Send a raw SMTP command and parse numeric reply.
// If capture=true, resolve with { code, text }.
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

app.listen(PORT, () => {
  console.log(`SMTP Checker running on port ${PORT}`);
});
