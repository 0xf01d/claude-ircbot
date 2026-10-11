#!/usr/bin/env node
// katiabot brain sidecar — a Claude Code session as the IRC bot's brain.
//
// Tails the event stream bot.py appends to /data/events.log and reacts ONLY to
// trusted channel mentions: a `MSG TRUSTED` event on #AI-live whose BODY names
// the bot. Per-nick rate limit, then the prompt (system line + last events)
// goes to `claude -p`; the reply is written back through the FIFO as a SAY
// command. Anything the claude CLI or the network throws is logged as
// BRAIN_ERROR and the bot stays silent — the transport must never die with us.
//
// Fixed commands live in a separate sidecar (commands_sidecar.py). Both tails
// see the same events, so before spending an LLM call we check the sidecar's
// /data/handled.log: a mention it already answered (or learned) within
// BRAIN_DEDUPE seconds is skipped, else the channel would get the canned reply
// AND a brain reply for the same line.
//
// Env: BRAIN_EVENTS, BRAIN_FIFO, BRAIN_NICK (or IRC_NICK), BRAIN_RATE (s),
// BRAIN_HANDLED, BRAIN_DEDUPE (s). ANTHROPIC_BASE_URL / ANTHROPIC_AUTH_TOKEN /
// ANTHROPIC_MODEL are inherited by the spawned claude CLI unchanged.

import fs from "node:fs";
import fsp from "node:fs/promises";
import crypto from "node:crypto";
import os from "node:os";
import { spawn } from "node:child_process";

const EVENTS = process.env.BRAIN_EVENTS || "/data/events.log";
const FIFO = process.env.BRAIN_FIFO || "/data/bot.send";
const NICK = (process.env.BRAIN_NICK || process.env.IRC_NICK || "katiabot").toLowerCase();
const RATE_S = parseInt(process.env.BRAIN_RATE || "60", 10);
const HANDLED = process.env.BRAIN_HANDLED || "/data/handled.log";
const DEDUPE_S = parseInt(process.env.BRAIN_DEDUPE || "120", 10);
const CHANNEL = "#AI-live"; // comparisons lowercase, SAY keeps this exact case
const POLL_MS = 1000;
const CLAUDE_TIMEOUT_MS = 120000;
const MAX_REPLY = 400; // bot.py wraps SAY bodies at MAX_BODY=400 anyway
const CONTEXT_LINES = 30;
const CONTEXT_BYTES = 16384;
const SYSTEM =
  "Sei katiabot, bot di test della flotta IRC di katia su irc.freebnc.net. " +
  "Rispondi BREVE (max 2 frasi), italiano, secco, utile. " +
  "Non inventare fatti sulla flotta.";

const log = (kind, ...parts) => console.log(`[brain] ${kind} ${parts.join(" ")}`);
const bodyHash = (body) =>
  crypto.createHash("sha256").update(body, "utf8").digest("hex").slice(0, 16);

// MUST match commands_sidecar.py's marker format: "<epoch> <nick> <hash>\n".
function handledRecently(from, body, text) {
  const cutoff = Date.now() / 1000 - DEDUPE_S;
  const hash = bodyHash(body);
  return text.split("\n").some((l) => {
    const [ts, nick, h] = l.trim().split(/\s+/);
    return (
      Number(ts) >= cutoff &&
      nick && nick.toLowerCase() === from.toLowerCase() &&
      h === hash
    );
  });
}

async function alreadyHandled(ev) {
  let text = "";
  try {
    text = await fsp.readFile(HANDLED, "utf8");
  } catch {
    return false; // sidecar has not answered anything yet
  }
  return handledRecently(ev.from, ev.body, text);
}

// --- event tail: size-delta poll, tolerates truncation and restarts --------
let tailPos = 0;
let tailPartial = "";

async function pollEvents() {
  let st;
  try {
    st = await fsp.stat(EVENTS);
  } catch {
    tailPos = 0; // bot.py creates the file on its first emit()
    return;
  }
  if (st.size < tailPos) tailPos = 0; // truncated/rotated under us
  if (st.size === tailPos) return;
  const fh = await fsp.open(EVENTS, "r");
  try {
    const len = st.size - tailPos;
    const buf = Buffer.alloc(len);
    await fh.read(buf, 0, len, tailPos);
    tailPos = st.size;
    handleChunk(buf.toString("utf8"));
  } finally {
    await fh.close();
  }
}

function handleChunk(chunk) {
  // Only complete lines: park a trailing fragment until its newline arrives.
  let data = tailPartial + chunk;
  const nl = data.lastIndexOf("\n");
  if (nl === -1) {
    tailPartial = data;
    return;
  }
  tailPartial = data.slice(nl + 1);
  for (const line of data.slice(0, nl + 1).split("\n")) {
    if (line) handleEvent(line).catch((e) => log("BRAIN_ERROR", "event", e.message));
  }
}

function parseEvent(line) {
  // bot.py emit() writes "[HH:MM] KIND field=val ..."; strip the optional
  // prefix so the verb check matches the documented event format either way.
  const bare = line.replace(/^\[\d{2}:\d{2}\]\s+/, "");
  if (!bare.startsWith("MSG TRUSTED")) return null;
  const from = /\bFROM=(\S+)/.exec(bare)?.[1] ?? "";
  const to = /\bTO=(\S+)/.exec(bare)?.[1] ?? "";
  const body = /\bBODY=(.*)$/s.exec(bare)?.[1] ?? "";
  return { from, to, body };
}

const lastMention = new Map(); // nick_lower -> epoch ms of last LLM dispatch

async function handleEvent(line) {
  const ev = parseEvent(line);
  if (!ev) return;
  if (ev.to.toLowerCase() !== CHANNEL.toLowerCase()) return;
  if (!ev.body.toLowerCase().includes(NICK)) return;

  const key = ev.from.toLowerCase();
  const now = Date.now();
  if (now - (lastMention.get(key) || 0) < RATE_S * 1000) {
    log("BRAIN_RATE_LIMIT", ev.from, `${RATE_S}s window`);
    return;
  }
  if (await alreadyHandled(ev)) {
    log("BRAIN_SKIP_HANDLED", ev.from, bodyHash(ev.body));
    return;
  }
  if (lastMention.size > 500) lastMention.clear(); // trust list is tiny anyway
  lastMention.set(key, now);
  log("BRAIN_MENTION", ev.from, `hash=${bodyHash(ev.body)}`, ev.body.slice(0, 80));

  const reply = await runClaude(ev);
  if (reply) await say(`${CHANNEL} ${reply}`);
}

async function runClaude(ev) {
  const prompt = [
    SYSTEM,
    "",
    "Ultimi eventi del canale IRC:",
    await tailContext(),
    "",
    `${ev.from} ha scritto in canale un messaggio che contiene il tuo nick: "${ev.body}"`,
    "Rispondi SOLO con il testo da mandare in canale: una riga sola, italiano, " +
      "senza markdown, senza virgolette di contorno.",
  ].join("\n");
  const child = spawn(
    "npx", ["-y", "@anthropic-ai/claude-code", "-p", prompt, "--output-format", "text"],
    { env: process.env, stdio: ["ignore", "pipe", "pipe"] },
  );
  let out = "", err = "";
  child.stdout.on("data", (d) => (out += d));
  child.stderr.on("data", (d) => (err += d));
  const timer = setTimeout(() => child.kill("SIGKILL"), CLAUDE_TIMEOUT_MS);
  const code = await new Promise((res) => child.on("close", res));
  clearTimeout(timer);
  if (code !== 0) throw new Error(`claude exit ${code}: ${err.trim().slice(-200)}`);
  const reply = out.replace(/\s+/g, " ").trim().slice(0, MAX_REPLY);
  if (!reply) throw new Error("claude empty output");
  return reply;
}

async function tailContext() {
  try {
    const st = await fsp.stat(EVENTS);
    const start = Math.max(0, st.size - CONTEXT_BYTES);
    const fh = await fsp.open(EVENTS, "r");
    let text;
    try {
      const buf = Buffer.alloc(st.size - start);
      await fh.read(buf, 0, buf.length, start);
      text = buf.toString("utf8");
    } finally {
      await fh.close();
    }
    const lines = text.split("\n").filter((l) => l.trim());
    if (start > 0 && lines.length) lines.shift(); // first line may be partial
    return lines.slice(-CONTEXT_LINES).join("\n") || "(nessun evento disponibile)";
  } catch {
    return "(nessun evento disponibile)";
  }
}

async function say(text) {
  // bot.py always keeps a reader on the FIFO, so a plain open would unblock —
  // but if the bot container is mid-restart it would park in libuv's tiny
  // threadpool and stall the tail. O_NONBLOCK fails fast instead (ENXIO) and
  // the mention is simply lost; the pod is Recreate, so this is transient.
  const fh = await fsp.open(FIFO, fs.constants.O_WRONLY | os.constants.O_NONBLOCK);
  try {
    await fh.write(`SAY ${text}\n`);
  } finally {
    await fh.close();
  }
  log("BRAIN_SAY", text.slice(0, 120));
}

// belt and suspenders: node >=15 crashes on unhandled rejections, and a dead
// brain sidecar is invisible from the channel — log and stay alive instead.
process.on("unhandledRejection", (e) => log("BRAIN_ERROR", "unhandled", String(e)));

log("BRAIN_STARTED", `nick=${NICK} channel=${CHANNEL} events=${EVENTS} ` +
  `fifo=${FIFO} handled=${HANDLED} rate=${RATE_S}s dedupe=${DEDUPE_S}s`);
setInterval(() => {
  pollEvents().catch((e) => log("BRAIN_ERROR", "tail", e.message));
}, POLL_MS);
