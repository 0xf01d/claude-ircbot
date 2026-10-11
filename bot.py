#!/usr/bin/env python3
"""
Minimal IRC bot bridging a claude-code conversation <-> Azzurra IRC.

- TLS connect to irc.azzurra.chat:6697 as vjt-claude.
- Every line logged to ./bot.log (next to this script).
- Selected events emitted to stdout (one line each) so a Monitor sees them.
- Reads commands from FIFO ./bot.send:
    SAY <target> <text>     -> splits into safe PRIVMSGs
    ACT <target> <text>     -> CTCP ACTION
    NOTICE <target> <text>
    RAW <irc line>          -> send as-is
    JOIN <chan> / PART <chan> / WHOIS <nick> / QUIT [reason]
    DCC <nick> <file> [name] -> offer $BOT_DCC_DIR/<file> over DCC SEND (v4 if
                               BOT_DCC_BIND4 is set, else IPv6), announcing
                               [name] to the peer if given (else <file>)

  Any verb may carry an origin tag as `VERB:<tag>` (e.g. `SAY:impiccato`).
  The tag changes NOTHING on the wire — it is only stamped into bot.log,
  right after the direction marker, as `HH:MM:SS > [impiccato] PRIVMSG ...`.
  It exists because the stats ingest classified every outbound line as the
  LLM speaking, while five sidecars (impiccato, cena, next, list, stats)
  share this FIFO and are plain deterministic code. Untagged lines keep
  the exact old format, so old readers are unaffected.

  The tag rides ON the line and never on a separate marker line: bot.py is
  threaded, two concurrent sends would pair a marker with the wrong line
  (vjt's ruling, 2026-08-26: "tenere context su due righe no").
"""
import fnmatch
import json
import os
import queue
import random
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.request
from collections import deque
from datetime import datetime
from zoneinfo import ZoneInfo

from leak_guard import LeakGuard

# Network + file paths are env-overridable so a SECOND instance (e.g. Libera.
# Chat) runs the SAME code with its own nick / FIFO / logs / trust / startup.
# Every default reproduces the original Azzurra single-instance behaviour, so
# the Azzurra unit (which sets none of these vars) is unchanged.
HERE = os.path.dirname(os.path.abspath(__file__))


def _cfg(key, default):
    return os.environ.get(key, default)


HOST = _cfg("IRC_HOST", "irc.azzurra.chat")
PORT = int(_cfg("IRC_PORT", "6697"))
NICK = _cfg("IRC_NICK", "vjt-claude")
IDENT = _cfg("IRC_IDENT", "claude")
REAL = _cfg("IRC_REAL", "github.com/vjt/claude-ircbot")

# Source address to bind before connecting. Empty = let the kernel pick, which
# is what every instance did until now. It exists because two bots can share a
# jail and still need two different vhosts: on Azzurra the vhost is the rDNS of
# the address we come from, so the address IS the identity, and the jail's
# default source would hand both bots the same one. Order of vjt, #sbiffo
# 2026-09-09 23:48. Port stays 0 — we want the address, not a fixed port.
BIND = _cfg("IRC_BIND", "")

# TLS certificate verification. Default ON — Azzurra and Libera both present a
# chain that validates against the system CA bundle, and there is a password on
# the wire there (NickServ), so the default must stay strict.
#
# IRC_TLS_VERIFY=0 drops to CERT_NONE. It exists for IRCnet (vjt's order,
# 2026-08-25): of 24 IRCnet servers probed with `openssl s_client
# -verify_hostname`, exactly ONE (ircnet.hostsailor.com) presented a cert that
# validates, and that one flaps — the rest are expired, self-signed, or carry a
# name that does not match the one we dial. There is nothing to protect on that
# network anyway: no services, no NickServ, no password ever sent.
TLS_VERIFY = _cfg("IRC_TLS_VERIFY", "1") not in ("0", "no", "off", "false")

LOG = _cfg("BOT_LOG", os.path.join(HERE, "bot.log"))
FIFO = _cfg("BOT_FIFO", os.path.join(HERE, "bot.send"))
TRUST_FILE = _cfg("BOT_TRUST", os.path.join(HERE, "bot.trust"))
ENV_FILE = _cfg("BOT_ENV", os.path.join(HERE, ".env"))
STARTUP_FILE = _cfg("BOT_STARTUP", os.path.join(HERE, "bot.startup"))
# Shared by ALL instances on purpose (not per-network): see leak_guard.py.
RESERVED_FILE = _cfg("BOT_RESERVED", os.path.join(HERE, "bot.reserved"))
RESERVED_STORE = _cfg("BOT_RESERVED_STORE", os.path.join(HERE, "reserved_recent.tsv"))

# Wall-clock timestamps in Europe/Rome (CET/CEST, DST-aware) instead of the
# host's UTC. bot.log + the event stream were UTC until 2026-07-02, when vjt
# asked for Italian local time. Explicit zoneinfo so it stays correct whatever
# the host TZ is (pi5 runs UTC).
_TZ = ZoneInfo("Europe/Rome")


def _now(fmt):
    return datetime.now(_TZ).strftime(fmt)


def load_env():
    out = {}
    try:
        with open(ENV_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip().strip('"').strip("'")
    except FileNotFoundError:
        pass
    return out


ENV = load_env()
NICKSERV_PASS = ENV.get("NICKSERV_PASS") or os.environ.get("NICKSERV_PASS") or ""
startup_fired = False

# Ghost-on-connect state. A line drop leaves our old connection holding NICK as
# a ghost for ~7min (until the server ping-times it out). Every reconnect in
# that window hit 433 pre-001 and just gave up -> registration never completed
# -> recv timeout -> systemd restart -> flap loop for the whole 7min. Instead:
# on a pre-001 433 take a throwaway nick to reach 001, GHOST the stale nick from
# services, reclaim it, then IDENTIFY. (vjt 2026-07-20: "fatti un ghost on connect".)
registered = False      # True once we've received 001 (registration complete)
ghost_needed = False    # True while we hold a temp nick and still want NICK back
tmp_nick = None         # the throwaway nick we fell back to

# Trust state: nick must be in trust_rules, host must match the nick's glob,
# AND we must have received RPL_WHOISREGNICK (307) confirming the nick is
# registered+identified to services. Cache reset on PART/QUIT/NICK.
trust_rules = []  # list of (nick_lower, host_glob)
verified = set()  # lowercase nicks confirmed via 307
whois_pending = set()  # lowercase nicks we WHOIS'd, awaiting 307/318

# IRC line limit is 512 incl CRLF. Body safe ~400.
MAX_BODY = 400

sock = None
send_lock = threading.Lock()
leak_guard = LeakGuard(HOST, RESERVED_FILE, RESERVED_STORE)

# Idle-tick config: per-channel random cooldown (seconds) after the last
# HUMAN PRIVMSG. When elapsed, bot emits `IDLE <chan>` exactly once, then
# disarms. Next human PRIVMSG re-arms with a fresh random cooldown.
# Our own outgoing messages do NOT reset the timer.
IDLE_RANGES = {
    "#sniffo": (5 * 60, 20 * 60),
    "#olografix": (10 * 60, 40 * 60),
    "#it-opers": (30 * 60, 90 * 60),
}
# state[chan_lower] = fire_at (monotonic) or None if disarmed
idle_state: dict[str, float | None] = {c.lower(): None for c in IDLE_RANGES}
idle_lock = threading.Lock()

# Rolling kick history per channel (monotonic timestamps). If > KICK_MAX in KICK_WINDOW, give up rejoin.
kick_history: dict[str, list[float]] = {}
kick_lock = threading.Lock()
KICK_WINDOW = 60.0
KICK_MAX = 3


def _arm_idle(chan: str) -> None:
    key = chan.lower()
    rng = IDLE_RANGES.get(key)
    if not rng:
        return
    lo, hi = rng
    delay = random.uniform(lo, hi)
    with idle_lock:
        idle_state[key] = time.monotonic() + delay


def idle_ticker_loop() -> None:
    while True:
        time.sleep(10)
        now = time.monotonic()
        fired = []
        with idle_lock:
            for chan, fire_at in list(idle_state.items()):
                if fire_at is not None and now >= fire_at:
                    idle_state[chan] = None
                    fired.append(chan)
        for chan in fired:
            emit("IDLE", chan)
            # also to bot.log so Monitor tails pick it up alongside IRC traffic
            log("*", f"IDLE {chan}")


def emit(kind, *parts):
    # [HH:MM] prefix gives the Monitor/Claude a real time anchor per event
    # instead of extrapolating elapsed time from turn order (vjt 2026-06-07).
    # No seconds by request. start-monitor.sh's grep tolerates this prefix.
    print(f"[{_now('%H:%M')}] " + kind + " " + " ".join(str(p) for p in parts), flush=True)


def load_trust():
    global trust_rules
    out = []
    try:
        with open(TRUST_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(None, 1)
                if len(parts) == 2:
                    out.append((parts[0].lower(), parts[1]))
    except FileNotFoundError:
        pass
    trust_rules = out
    emit("TRUST_LOADED", len(trust_rules))


def is_trust_listed(nick):
    n = nick.lower()
    return any(tn == n for tn, _ in trust_rules)


def host_matches(nick, host):
    n = nick.lower()
    for tn, hg in trust_rules:
        if tn == n and fnmatch.fnmatch(host, hg):
            return True
    return False


def trust_check(nick, host):
    """Evaluate (trusted_bool, reason). Fires WHOIS on first sighting
    of a trust-listed nick. Trust requires: listed, host glob match,
    AND registered (307 seen). Anything less => untrusted."""
    n = nick.lower()
    if not is_trust_listed(n):
        return (False, "not-listed")
    if not host_matches(n, host):
        return (False, "host-mismatch")
    if n not in verified:
        if n not in whois_pending:
            whois_pending.add(n)
            send_raw(f"WHOIS {nick}")
            emit("WHOIS_FIRED", nick)
        return (False, "pending-whois")
    return (True, "ok")


# Hard block on private messages from strangers (vjt 2026-08-03). The written
# policy alone is not enough: by the time Claude can apply it, the payload is
# already in its context. Dropping at the bot is the only real filter.
#
# The gate is `is_trust_listed`, NOT full `trust_check`: full trust needs a 307
# WHOIS round-trip, which is asynchronous, so the FIRST DM from a trusted nick
# would always be dropped. Listed nicks therefore still get through, tagged
# UNTRUSTED until 307 lands — a nick-squatter on a listed nick reaches the
# event stream but arrives visibly untrusted, which is the case the refusal
# policy already covers. Unlisted nicks never reach the event stream at all.
#
# The raw line is still written to bot.log by handle_server_line() before
# dispatch, so nothing is lost forensically — it just never becomes an event.
SERVICE_NICKS = {
    "nickserv", "chanserv", "memoserv", "operserv", "hostserv",
    "botserv", "helpserv", "statserv", "global", "services",
}
DM_REJECT_MSG = _cfg(
    "BOT_DM_REJECT",
    "Con me si parla in canale, non in privato. / I only talk in channels, not in private.",
)
DM_REJECT_COOLDOWN = 6 * 3600.0
dm_rejected: dict[str, float] = {}  # nick_lower -> monotonic ts of last auto-reply
dm_lock = threading.Lock()


def dm_blocked(nick):
    """True if a private message from `nick` must be dropped before it can
    become an event. Services and our own nick are never blocked."""
    n = nick.lower()
    if not n or n == NICK.lower() or n in SERVICE_NICKS:
        return False
    return not is_trust_listed(n)


def dm_reject_once(nick):
    """Send the 'talk in channel' line at most once per DM_REJECT_COOLDOWN per
    nick. NOTICE, not PRIVMSG: RFC-correct for an automated reply, and it keeps
    two bots from ping-ponging auto-replies at each other.

    An empty BOT_DM_REJECT disables the reply entirely (EliteWarez: "con me si
    parla in canale" is a channel act, not a private rebound). The DM is still
    dropped upstream — only the outbound rebound is suppressed."""
    if not DM_REJECT_MSG:
        return False
    n = nick.lower()
    now = time.monotonic()
    with dm_lock:
        last = dm_rejected.get(n)
        if last is not None and now - last < DM_REJECT_COOLDOWN:
            return False
        dm_rejected[n] = now
        if len(dm_rejected) > 500:
            for k, ts in sorted(dm_rejected.items(), key=lambda kv: kv[1])[:100]:
                dm_rejected.pop(k, None)
    send_raw(f"NOTICE {nick} :{DM_REJECT_MSG}")
    return True


# Second half of the same gate (vjt 2026-09-15, after "ma quindi sei
# promptinjectabile in pvt??"). Unlisted nicks are already dropped above, but a
# LISTED nick whose WHOIS hasn't resolved yet used to reach the event stream
# tagged UNTRUSTED — payload in context, only policy stopping it from being
# obeyed. Policy is applied by a model; the gate is not. So the DM is now HELD
# until the WHOIS answers: 307/330 releases it as TRUSTED, 318-without-307 drops
# it. Holding rather than dropping outright is what keeps the FIRST DM from a
# genuinely trusted nick (vjt's own, right after a reconnect) from vanishing.
# Nothing is ever lost forensically: the raw line is in bot.log either way, and
# vjt can order it read from there.
DM_HOLD_MAX = 5  # per nick, newest wins — a flood can't grow the queue
dm_held: dict[str, list[tuple[str, str]]] = {}  # nick_lower -> [(host, body)]


def dm_hold(nick, host, body):
    """Park a DM awaiting WHOIS. Returns the queue depth for the event line."""
    n = nick.lower()
    with dm_lock:
        q = dm_held.setdefault(n, [])
        q.append((host, body))
        del q[:-DM_HOLD_MAX]
        return len(q)


def dm_flush(nick, reason):
    """Resolve the held DMs for `nick`. Each one is re-checked at release time
    (host glob + 307), never trusted on the strength of the earlier sighting."""
    n = nick.lower()
    with dm_lock:
        queued = dm_held.pop(n, [])
    for host, body in queued:
        if n in verified and host_matches(n, host):
            emit("MSG", "TRUSTED", f"FROM={nick}", f"HOST={host}",
                 f"TO={NICK}", "HELD=1", f"BODY={body}")
        else:
            emit("DM_DROPPED", f"FROM={nick}", f"HOST={host}",
                 f"LEN={len(body)}", reason)


def trust_reset(nick, reason):
    n = nick.lower()
    dm_flush(nick, f"reset:{reason}")
    if n in verified or n in whois_pending:
        verified.discard(n)
        whois_pending.discard(n)
        emit("TRUST_RESET", nick, reason)


def _mask_secrets(line):
    if NICKSERV_PASS and NICKSERV_PASS in line:
        return line.replace(NICKSERV_PASS, "********")
    return line


# Origin tags are stamped into bot.log and read back by parsers, so keep them
# boring: no spaces, no brackets, nothing that could forge a second field.
ORIGIN_PAT = re.compile(r"^[a-z0-9_-]{1,24}$")


def log(direction, line, origin=None):
    tag = f"[{origin}] " if origin else ""
    try:
        with open(LOG, "a") as f:
            f.write(f"{_now('%H:%M:%S')} {direction} {tag}{_mask_secrets(line)}\n")
    except Exception:
        pass


def send_raw(s, origin=None):
    log(">", s, origin)
    with send_lock:
        try:
            sock.sendall((s + "\r\n").encode("utf-8", errors="replace"))
        except Exception as e:
            emit("ERROR", "send-fail", repr(e))


def split_say(target, text, origin=None):
    """Send text as one or more PRIVMSGs, preserving whitespace verbatim.

    Lines that fit in MAX_BODY go out untouched, so ascii art keeps its
    indentation and internal spacing (#86). Longer lines wrap at the last
    space before the limit WITHOUT stripping or collapsing spaces; a single
    oversized word is hard-split on a utf-8 char boundary.
    """
    b = text.encode("utf-8")
    if len(b) <= MAX_BODY:
        send_raw(f"PRIVMSG {target} :{text}", origin)
        return
    while b:
        if len(b) <= MAX_BODY:
            send_raw(f"PRIVMSG {target} :{b.decode('utf-8', errors='ignore')}", origin)
            return
        cut = b.rfind(b" ", 1, MAX_BODY + 1)
        if cut <= 0:
            cut = MAX_BODY
            while cut > 1 and (b[cut] & 0xC0) == 0x80:
                cut -= 1
        else:
            cut += 1  # keep the breaking space on this chunk, don't strip it
        send_raw(f"PRIVMSG {target} :{b[:cut].decode('utf-8', errors='ignore')}", origin)
        b = b[cut:]


# --------------------------------------------------------------------------
# Brain: LLM replies via the zai OpenAI-compatible API (fleet standard).
# k8s test deployment, 2026-10-11: on a trust-listed channel mention the bot
# answers through POST {OMP_API_BASE}/chat/completions. Stdlib-only (urllib),
# single-file philosophy kept. The API key lives only in the Authorization
# header and is never logged: error events carry the HTTP status or the
# exception repr, neither of which contains it. If OMP_API_KEY is unset the
# brain is disabled — no canned fallback, the bot just transports.
# --------------------------------------------------------------------------
BRAIN_API_KEY = os.environ.get("OMP_API_KEY", "")
BRAIN_API_BASE = _cfg("OMP_API_BASE", "https://api.z.ai/api/paas/v4").rstrip("/")
BRAIN_MODEL = _cfg("OMP_MODEL", "glm-5.3-flash")
BRAIN_MAX_TOKENS = int(_cfg("BRAIN_MAX_TOKENS", "300"))
BRAIN_RATE_SECONDS = 60.0
BRAIN_CONTEXT_LINES = 8
BRAIN_TIMEOUT = 30
BRAIN_SYSTEM_PROMPT = (
    "Sei katiabot, bot di test della flotta IRC di katia. "
    "Rispondi BREVE (max 2 frasi), in italiano, secco e utile."
)
BRAIN_ENABLED = bool(BRAIN_API_KEY)

_brain_queue = queue.Queue()
_brain_seen = deque(maxlen=BRAIN_CONTEXT_LINES)  # last channel lines: (nick, body)
_brain_last = {}                                 # nick_lower -> last-reply monotonic
_brain_lock = threading.Lock()


def brain_observe(nick, target, body):
    """Channel PRIVMSG hook: remember the line, maybe enqueue a reply.

    Fires on is_trust_listed only (not full trust_check: its 307 WHOIS
    round-trip is asynchronous — see the DM path). DMs never reach the brain.
    """
    if not target.startswith(("#", "&")):
        return
    with _brain_lock:
        _brain_seen.append((nick, body))
    if not BRAIN_ENABLED or not is_trust_listed(nick):
        return
    if NICK.lower() not in body.lower():
        return
    _brain_queue.put((nick, target, body))


def brain_start():
    """Start the worker thread, or log the disabled state once."""
    if BRAIN_ENABLED:
        threading.Thread(target=_brain_worker, daemon=True).start()
    else:
        emit("BRAIN_DISABLED", "OMP_API_KEY unset: brain off")


def _brain_chat(messages):
    url = BRAIN_API_BASE + "/chat/completions"
    payload = json.dumps({
        "model": BRAIN_MODEL,
        "messages": messages,
        "max_tokens": BRAIN_MAX_TOKENS,
        "temperature": 0.7,
    }).encode("utf-8")
    req = urllib.request.Request(
        url, data=payload, method="POST",
        headers={
            "Authorization": f"Bearer {BRAIN_API_KEY}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=BRAIN_TIMEOUT) as resp:
        return json.loads(resp.read().decode("utf-8", errors="ignore"))


def _brain_worker():
    while True:
        nick, target, body = _brain_queue.get()
        try:
            # One reply per nick per BRAIN_RATE_SECONDS. A dropped mention
            # burns nothing: the window starts at the last reply actually sent.
            now = time.monotonic()
            key = nick.lower()
            with _brain_lock:
                if now - _brain_last.get(key, 0.0) < BRAIN_RATE_SECONDS:
                    emit("BRAIN_RATE_LIMITED", f"TO={nick}", f"CHAN={target}")
                    continue
                _brain_last[key] = now
            # The triggering line was appended to the ring in brain_observe;
            # it comes back as its own user message below, so drop it from the
            # context when it is still the ring's tail (worker keeping up).
            with _brain_lock:
                context = list(_brain_seen)
            if context and context[-1] == (nick, body):
                context.pop()
            messages = [{"role": "system", "content": BRAIN_SYSTEM_PROMPT}]
            messages += [{"role": "user", "content": f"{n}: {b}"} for n, b in context]
            messages.append({"role": "user", "content": f"{nick}: {body}"})
            try:
                data = _brain_chat(messages)
                reply = (data["choices"][0].get("message") or {}).get("content") or ""
                reply = reply.strip()
            except urllib.error.HTTPError as e:
                emit("BRAIN_ERROR", f"FROM={nick}", f"HTTP={e.code}")
                continue
            except Exception as e:
                emit("BRAIN_ERROR", f"FROM={nick}", repr(e))
                continue
            if not reply:
                emit("BRAIN_ERROR", f"FROM={nick}", "empty-reply")
                continue
            split_say(target, reply)
            emit("BRAIN_REPLIED", f"TO={nick}", f"CHAN={target}", f"LEN={len(reply)}")
        finally:
            _brain_queue.task_done()


# DCC SEND. Serve a EliteWarez: il `!list` offre "warez", e prima o poi uno
# prova a scaricarli. Un listener effimero sull'indirizzo da cui usciamo, il
# CTCP con la porta, UNA connessione servita e chiuso.
#
# Nasce solo IPv6 (ordine di vjt #sbiffo 2026-09-12 01:29, "va bene facciamolo
# solo ipv6"), e sul campo si e' visto il prezzo: il DCC storico vuole l'IP come
# intero decimale a 32 bit, e un client che il v6 in quel campo non lo digerisce
# — HexChat, misurato con peluche il 14/09 — legge la stringa come numero e ne
# cava 0.0.0.2, cioe' "No route to host". irssi e mIRC 7 invece il letterale v6
# lo leggono, quindi il ramo v6 resta e non si tocca.
#
# BOT_DCC_BIND4 accende il ramo v4 e ha la precedenza: si ascolta li' (nella
# jail e' un privato di <jail_v4>) e si annuncia BOT_DCC_ADDR4, il pubblico
# davanti alla rdr di pf, come intero a 32 bit. Ordine di vjt 2026-09-14 23:28
# ("VA BENE IPV4", poi "ipv4 e basta"): cosi' prendono anche i client v4-only.
#
# La porta non puo' essere effimera: dietro un firewall la finestra va aperta
# in anticipo, e non si apre quello che sceglie il kernel. BOT_DCC_PORT_MIN /
# MAX danno un intervallo fisso da rispecchiare nella regola di pf; a zero (il
# default) si torna alla porta effimera, buona solo dove non c'e' firewall.
DCC_DIR = _cfg("BOT_DCC_DIR", os.path.join(HERE, "dcc"))
DCC_TIMEOUT = int(_cfg("BOT_DCC_TIMEOUT", "180"))
# Quanto aspettiamo che il peer chiuda dopo l'ultimo byte, prima di mollare.
DCC_DRAIN_TIMEOUT = int(_cfg("BOT_DCC_DRAIN_TIMEOUT", "60"))
DCC_PORT_MIN = int(_cfg("BOT_DCC_PORT_MIN", "0"))
DCC_PORT_MAX = int(_cfg("BOT_DCC_PORT_MAX", "0"))
# Ramo v4: indirizzo su cui ascoltare, e indirizzo da annunciare (uguale al
# primo se non c'e' NAT davanti). Vuoto = si resta sul v6 di IRC_BIND.
DCC_BIND4 = _cfg("BOT_DCC_BIND4", "")
DCC_ADDR4 = _cfg("BOT_DCC_ADDR4", "") or DCC_BIND4
DCC_NAME_PAT = re.compile(r"[A-Za-z0-9._-]{1,80}\Z")
# The offer name is what the peer's client shows and never touches the disk,
# so it needs no traversal guard — only CTCP safety (no spaces, the field
# separator) and a length that fits a scene title (~78) plus extension.
DCC_OFFER_NAME_PAT = re.compile(r"[A-Za-z0-9._-]{1,120}\Z")


def _dcc_bind(srv, addr):
    """Bind the listener inside the configured range, or ephemeral if unset.

    Every offer holds its port for the whole transfer, so with N offers in
    flight the first N ports of the range are taken: we walk it until one
    binds. Range exhausted -> the caller refuses the offer.
    """
    if DCC_PORT_MIN <= 0 or DCC_PORT_MAX < DCC_PORT_MIN:
        srv.bind((addr, 0))
        return
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    for port in range(DCC_PORT_MIN, DCC_PORT_MAX + 1):
        try:
            srv.bind((addr, port))
        except OSError:
            continue
        return
    raise OSError(f"no free port in {DCC_PORT_MIN}-{DCC_PORT_MAX}")


def _dcc_drain(conn):
    """Half-close, read the peer's ACK stream to EOF, return the last ACK.

    Un ricevente DCC risponde a ogni blocco con un ACK di 4 byte big-endian, il
    totale ricevuto finora. Quegli ACK si accumulano nel nostro buffer di
    ricezione, e chiudere un socket con dati non letti fa emettere al kernel un
    RST invece del FIN: il peer perde tutto quello che era ancora in volo e si
    ritrova un file mozzato mentre noi abbiamo gia' loggato DCC_DONE (vjt su
    #sbiffo il 2026-09-14: "il transfer non completa" — misurato, 131072 byte su
    246254 con un client lento). Mezza chiusura, si drena, e il close finale e'
    un FIN pulito. L'ultimo ACK e' anche l'unica prova di consegna che abbiamo.
    """
    last = None
    try:
        conn.shutdown(socket.SHUT_WR)
        conn.settimeout(DCC_DRAIN_TIMEOUT)
        tail = b""
        while True:
            more = conn.recv(65536)
            if not more:
                break
            tail = (tail + more)[-4:]
        if len(tail) == 4:
            last = int.from_bytes(tail, "big")
    except OSError:
        pass
    return last


def _dcc_event(kind, *parts):
    """Emit a DCC lifecycle event on BOTH stdout and bot.log.

    stdout is the Monitor's stream; bot.log is what the sidecars tail. A
    sidecar that wants to announce "nick ha ricevuto il file" only follows
    bot.log (it is the PRIVMSG stream), so without this second write the
    completion would be invisible to it. Same trick as IDLE above.
    """
    emit(kind, *parts)
    log("*", kind + " " + " ".join(str(p) for p in parts))


def _dcc_serve(srv, path, nick, name):
    """Accept one peer, push the file, hang up. Runs off the reader thread."""
    try:
        conn, _peer = srv.accept()
    except Exception as e:
        _dcc_event("DCC_TIMEOUT", f"TO={nick}", f"FILE={name}", repr(e))
        return
    finally:
        srv.close()
    sent = 0
    try:
        # accept() does NOT inherit the listener's timeout reliably; set it.
        conn.settimeout(DCC_TIMEOUT)
        with open(path, "rb") as f:
            while True:
                chunk = f.read(65536)
                if not chunk:
                    break
                conn.sendall(chunk)
                sent += len(chunk)
    except Exception as e:
        _dcc_event("DCC_ERROR", f"TO={nick}", f"FILE={name}", f"SENT={sent}", repr(e))
    else:
        ack = _dcc_drain(conn)
        _dcc_event("DCC_DONE", f"TO={nick}", f"FILE={name}", f"BYTES={sent}",
                   f"ACK={ack if ack is not None else 'none'}")
    finally:
        conn.close()


def dcc_send(nick, name, origin=None, offer=None):
    # `name` is the file on disk; `offer` is the name announced to the peer,
    # defaulting to `name`. Both come from a sidecar and ride a CTCP whose
    # fields are space-separated and unquotable: no path, no traversal, no
    # spaces. `name` must stay a bare basename (it opens a file); `offer`
    # never touches disk, so it only needs to be CTCP-safe.
    if not DCC_NAME_PAT.match(name):
        emit("CMD_ERROR", "dcc-bad-name", repr(name))
        return
    if offer is None:
        offer = name
    elif not DCC_OFFER_NAME_PAT.match(offer):
        emit("CMD_ERROR", "dcc-bad-offer", repr(offer))
        return
    path = os.path.join(DCC_DIR, name)
    if not os.path.isfile(path):
        emit("CMD_ERROR", "dcc-no-file", path)
        return
    bind = DCC_BIND4 or BIND
    if not bind:
        emit("CMD_ERROR", "dcc-no-bind", "IRC_BIND empty: no address, no offer")
        return
    if DCC_BIND4:
        # Il campo indirizzo del DCC e' un intero a 32 bit, non una stringa.
        try:
            advertise = str(int.from_bytes(socket.inet_aton(DCC_ADDR4), "big"))
        except OSError as e:
            emit("CMD_ERROR", "dcc-bad-addr4", repr(DCC_ADDR4), repr(e))
            return
    else:
        advertise = BIND
    size = os.path.getsize(path)
    family = socket.AF_INET if DCC_BIND4 else socket.AF_INET6
    srv = socket.socket(family, socket.SOCK_STREAM)
    try:
        srv.settimeout(DCC_TIMEOUT)
        _dcc_bind(srv, bind)
        srv.listen(1)
    except Exception as e:
        srv.close()
        emit("CMD_ERROR", "dcc-listen-fail", repr(e))
        return
    port = srv.getsockname()[1]
    threading.Thread(
        target=_dcc_serve, args=(srv, path, nick, offer), daemon=True
    ).start()
    send_raw(f"PRIVMSG {nick} :\x01DCC SEND {offer} {advertise} {port} {size}\x01",
             origin)
    emit("DCC_OFFER", f"TO={nick}", f"FILE={name}", f"OFFER={offer}",
         f"ADDR={advertise}", f"PORT={port}", f"SIZE={size}")


def run_startup():
    try:
        with open(STARTUP_FILE) as f:
            lines = f.readlines()
    except FileNotFoundError:
        emit("STARTUP_DONE", "no-file")
        return
    count = 0
    for raw in lines:
        line = raw.rstrip("\r\n").strip()
        if not line or line.startswith("#"):
            continue
        try:
            process_cmd(line)
            count += 1
        except Exception as e:
            emit("ERROR", "startup-fail", repr(e), line[:80])
        time.sleep(0.5)
    emit("STARTUP_DONE", count)


def fire_startup(reason):
    global startup_fired
    if startup_fired:
        return
    startup_fired = True
    emit("STARTUP_FIRED", reason)
    threading.Thread(target=run_startup, daemon=True).start()


def _reclaim_after_ghost():
    # GHOST is near-instant but async; give services a beat to kill the ghost,
    # then reclaim the real nick. The server's echo of our own NICK change (in
    # handle_server_line) fires IDENTIFY. This is wording-agnostic on purpose,
    # so we don't depend on the exact "has been ghosted" NOTICE text differing
    # between Azzurra (suxserv) and Libera (atheme).
    time.sleep(4)
    if ghost_needed:
        send_raw(f"NICK {NICK}")
        emit("NS_GHOST_RECLAIM", NICK)


def handle_server_line(line):
    global registered, ghost_needed, tmp_nick
    log("<", line)
    if line.startswith("PING "):
        send_raw("PONG " + line[5:])
        return

    m = re.match(r"^(?::(\S+)\s+)?(\S+)(?:\s+(.*))?$", line)
    if not m:
        return
    prefix, cmd, rest = m.groups()
    nick = prefix.split("!")[0] if prefix else ""
    # Host from the source prefix (nick!user@host). Computed once so EVERY
    # emitted event can carry HOST= — the Monitor must never be host-blind on a
    # JOIN/NICK the way it was when a *.diostronzo.org flooder spoofed nick
    # `vjt_` and only the raw bot.log (not the event stream) revealed it wasn't
    # vjt's trust host *.openssl.it (vjt 2026-07-02).
    host = prefix.split("@", 1)[1] if prefix and "@" in prefix else ""
    rest = rest or ""
    if cmd in ("PRIVMSG", "NOTICE", "TOPIC") and " :" in rest:
        tgt, _, body = rest.partition(" :")
        leak_guard.record(tgt.strip(), body)

    if cmd == "001":
        registered = True
        emit("CONNECTED", NICK)
        for tn, _ in trust_rules:
            whois_pending.add(tn)
            send_raw(f"WHOIS {tn}")
            emit("WHOIS_FIRED", tn)
        if NICKSERV_PASS:
            if ghost_needed:
                # Our real nick is held (by our own ghost after a line drop):
                # kill it from services, then reclaim + IDENTIFY (see below).
                send_raw(f"PRIVMSG NickServ :GHOST {NICK} {NICKSERV_PASS}")
                emit("NS_GHOST_SENT", NICK)
                threading.Thread(target=_reclaim_after_ghost, daemon=True).start()
            else:
                send_raw(f"PRIVMSG NickServ :IDENTIFY {NICKSERV_PASS}")
                emit("NS_IDENTIFY_SENT")
        else:
            fire_startup("no-nickserv-pass")
        return
    if cmd in ("433", "432", "437"):
        emit("NICK_ERROR", cmd, rest)
        if not registered:
            # Pre-registration collision, almost always our own lingering
            # ghost. Grab a throwaway nick so registration completes and we
            # reach 001 -> then GHOST the real nick and reclaim it. Random
            # suffix so a second flap doesn't collide with the same temp.
            tmp_nick = f"{NICK}-{random.randint(100, 999)}"
            send_raw(f"NICK {tmp_nick}")
            ghost_needed = True
            emit("NICK_FALLBACK", tmp_nick)
        return
    if cmd in ("464", "465"):
        emit("AUTH_ERROR", cmd, rest)
        return
    if cmd == "401":
        # ERR_NOSUCHNICK: ":server 401 <me> <target> :No such nick/channel"
        # Surface as event so silent PRIVMSG/NOTICE failures become visible
        # (otherwise they only land in bot.log and the sender never retries).
        parts = rest.split(" :", 1)
        head = parts[0].split()
        tgt = head[1] if len(head) > 1 else ""
        reason = parts[1] if len(parts) > 1 else "No such nick/channel"
        emit("IRC_ERROR", "401", tgt, reason)
        return
    if cmd == "307":
        # RPL_WHOISREGNICK: ":server 307 <me> <target> :has identified for this nick"
        parts = rest.split()
        if len(parts) >= 2:
            target = parts[1].lower()
            verified.add(target)
            whois_pending.discard(target)
            emit("VERIFIED", parts[1])
            dm_flush(parts[1], "307")
        return
    if cmd == "330":
        # RPL_WHOISACCOUNT (Libera/solanum): ":srv 330 <me> <nick> <account>
        # :is logged in as". Libera does NOT emit 307 (a Bahamut-ism), so this
        # is its identified-to-services signal — mirror the 307 path or a
        # trust-listed nick never verifies there. Safe: on Libera only the real
        # account holder wears the `user/<account>` cloak the host-glob already
        # pins, so account-vs-nick mismatch can't slip trust through.
        parts = rest.split()
        if len(parts) >= 2:
            target = parts[1].lower()
            verified.add(target)
            whois_pending.discard(target)
            emit("VERIFIED", parts[1])
            dm_flush(parts[1], "330")
        return
    if cmd == "318":
        # RPL_ENDOFWHOIS: if nick was pending and not verified => not registered
        parts = rest.split()
        if len(parts) >= 2:
            target = parts[1].lower()
            if target in whois_pending:
                whois_pending.discard(target)
                if target not in verified:
                    emit("NOT_REGISTERED", parts[1])
            # Either way the WHOIS is over: nothing may stay parked past it.
            dm_flush(parts[1], "318")
        return
    if cmd == "NOTICE":
        parts = rest.split(" :", 1)
        tgt = parts[0]
        msg = parts[1] if len(parts) > 1 else ""
        if nick.lower() == "nickserv" and NICKSERV_PASS:
            low = msg.lower()
            if any(k in low for k in ("identified", "accepted", "recognized", "riconosciuto", "autenticato", "accettata", "identificato")):
                fire_startup("nickserv-ok")
            elif any(k in low for k in ("incorrect", "invalid", "failed", "errata", "errato")):
                emit("NS_IDENTIFY_FAIL", msg)
        if nick and nick.lower() != NICK.lower():
            emit("NOTICE", f"FROM={nick}", f"HOST={host}", f"TO={tgt}", f"BODY={msg}")
        return
    if cmd == "INVITE":
        parts = rest.split(" :", 1)
        target_chan = parts[1] if len(parts) == 2 else rest.split()[-1]
        trusted, reason = trust_check(nick, host)
        emit("INVITE", nick, f"HOST={host}", target_chan, "trusted" if trusted else f"untrusted:{reason}")
        if trusted:
            send_raw(f"JOIN {target_chan}")
        return
    if cmd == "KICK":
        # rest = "#chan target[ :reason]"
        kick_parts = rest.split(" :", 1)
        head = kick_parts[0].split()
        kick_chan = head[0] if head else ""
        kick_target = head[1] if len(head) > 1 else ""
        kick_reason = kick_parts[1] if len(kick_parts) > 1 else ""
        emit("KICK", nick, f"HOST={host}", kick_chan, kick_target, kick_reason)
        if kick_chan and kick_target.lower() == NICK.lower():
            # Auto-rejoin with kick-flood backoff. Repeated kicks in a short
            # window = a hostile op. Walk away rather than trigger Excess Flood.
            now = time.monotonic()
            key = kick_chan.lower()
            with kick_lock:
                history = [t for t in kick_history.get(key, []) if now - t < KICK_WINDOW]
                history.append(now)
                kick_history[key] = history
                count = len(history)
            if count > KICK_MAX:
                emit("KICK_GIVEUP", kick_chan, nick, f"{count} kicks in {KICK_WINDOW}s")
            else:
                def _rejoin(ch: str = kick_chan) -> None:
                    send_raw(f"PRIVMSG ChanServ :INVITE {ch}")
                    threading.Timer(0.5, lambda: send_raw(f"JOIN {ch}")).start()
                threading.Timer(2.0, _rejoin).start()
                emit("KICK_REJOIN", kick_chan, nick, f"{count}/{KICK_MAX}")
        return
    if cmd == "PRIVMSG":
        parts = rest.split(" :", 1)
        target = parts[0].strip()
        body = parts[1] if len(parts) > 1 else ""
        if body.startswith("\x01") and body.endswith("\x01"):
            ctcp = body.strip("\x01")
            emit("CTCP", f"FROM={nick}", f"HOST={host}", f"TO={target}", f"BODY={ctcp}")
            if ctcp.upper() == "VERSION":
                send_raw(f"NOTICE {nick} :\x01VERSION claude-code PoC\x01")
            elif ctcp.upper().startswith("PING"):
                send_raw(f"NOTICE {nick} :\x01{ctcp}\x01")
            return
        # Private message from a nick that isn't even trust-listed: drop it
        # here. No BODY is emitted — the whole point is that the payload never
        # reaches the event stream (vjt 2026-08-03).
        if not target.startswith(("#", "&")) and dm_blocked(nick):
            replied = dm_reject_once(nick)
            emit(
                "DM_BLOCKED",
                f"FROM={nick}",
                f"HOST={host}",
                f"LEN={len(body)}",
                "replied" if replied else "silent",
            )
            return
        trusted, reason = trust_check(nick, host)
        trust = "TRUSTED" if trusted else "UNTRUSTED"
        if not target.startswith(("#", "&")) and not trusted:
            # Listed (dm_blocked already ate the strangers) but not trusted yet.
            # pending-whois => park it, the 307/330/318 handler decides. Anything
            # else (host-mismatch: a squatter on a listed nick) will never become
            # trusted, so drop it now and rebound the notice.
            if reason == "pending-whois":
                depth = dm_hold(nick, host, body)
                emit("DM_HELD", f"FROM={nick}", f"HOST={host}",
                     f"LEN={len(body)}", f"QUEUED={depth}")
            else:
                replied = dm_reject_once(nick)
                emit("DM_BLOCKED", f"FROM={nick}", f"HOST={host}",
                     f"LEN={len(body)}", reason,
                     "replied" if replied else "silent")
            return
        emit("MSG", trust, f"FROM={nick}", f"HOST={host}", f"TO={target}", f"BODY={body}")
        # Real brain (zai API). Records the channel line as context and, when a
        # trust-LISTED nick addresses us by name on a channel, enqueues a reply.
        # Still gated on is_trust_listed only, like the canned pong it replaces
        # (2026-10-11): NOT on trust_check's 307 — test pod, not the production
        # gate. When the brain is disabled the hook is a no-op, no fallback.
        brain_observe(nick, target, body)
        if is_trust_listed(nick) and not trusted:
            emit("TRUST_DENIED", nick, host, reason)
        # Re-arm the idle timer only on HUMAN PRIVMSG to a tracked channel.
        # Our own outgoing messages don't reach this path.
        if target.startswith("#") and nick.lower() != NICK.lower():
            _arm_idle(target)
        return
    if cmd == "JOIN":
        emit("JOIN", nick, f"HOST={host}", rest.lstrip(":"))
        return
    if cmd == "PART":
        emit("PART", nick, f"HOST={host}", rest)
        trust_reset(nick, "part")
        return
    if cmd == "QUIT":
        emit("QUIT", nick, f"HOST={host}", rest)
        trust_reset(nick, "quit")
        return
    if cmd == "NICK":
        new_nick = rest.lstrip(":")
        emit("NICK_CHANGE", nick, f"HOST={host}", new_nick)
        trust_reset(nick, "nick-change")
        if ghost_needed and new_nick.lower() == NICK.lower():
            # We just reclaimed the real nick after ghosting the stale one.
            # Now IDENTIFY on it (NickServ's "identified" NOTICE then fires the
            # channel-join startup, so JOINs happen on the right nick).
            ghost_needed = False
            if NICKSERV_PASS:
                send_raw(f"PRIVMSG NickServ :IDENTIFY {NICKSERV_PASS}")
                emit("NS_IDENTIFY_SENT")
        return
    if cmd == "ERROR":
        emit("SERVER_ERROR", rest)
        return


# EAGAIN on a TLS socket means "the record isn't complete yet", not "the link
# is dead" — retrying is correct. But retrying FOREVER would leave a process
# that looks alive and hears nothing, which is worse than dying, so the retry
# is capped and a real recv resets the count.
RECV_RETRY_SLEEP = 0.05
RECV_RETRY_MAX = 200            # ~10s of solid EAGAIN, then die for real


def reader_loop():
    buf = b""
    retries = 0
    while True:
        try:
            data = sock.recv(8192)
        except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError) as e:
            # Measured 2026-08-19 13:03: one BlockingIOError(11) killed the
            # process and cost a full reconnect. Against 37 genuine
            # TimeoutErrors in the same history — so the two must NOT share a
            # handler. Timeout and reset still fall through and kill us.
            retries += 1
            if retries > RECV_RETRY_MAX:
                emit("ERROR", "recv-fail", f"{retries} consecutive {e!r}")
                return
            time.sleep(RECV_RETRY_SLEEP)
            continue
        except Exception as e:
            emit("ERROR", "recv-fail", repr(e))
            return
        retries = 0
        if not data:
            emit("DISCONNECTED")
            return
        buf += data
        while b"\n" in buf:
            raw, buf = buf.split(b"\n", 1)
            line = raw.rstrip(b"\r").decode("utf-8", errors="replace")
            if line:
                try:
                    handle_server_line(line)
                except Exception as e:
                    emit("ERROR", "handler-fail", repr(e), line[:80])


def writer_loop():
    if os.path.exists(FIFO):
        try:
            os.remove(FIFO)
        except Exception:
            pass
    os.mkfifo(FIFO, 0o600)
    emit("FIFO_READY", FIFO)
    while True:
        with open(FIFO, "r") as f:
            for line in f:
                line = line.rstrip("\r\n")
                if not line:
                    continue
                try:
                    process_cmd(line)
                except Exception as e:
                    emit("CMD_ERROR", "cmd-fail", repr(e), line[:80])


def outbound_ok(verb, rest, origin):
    """Leak gate for every chat line the FIFO asks for (leak_guard.py).

    RAW is parsed too, or `RAW PRIVMSG #x :...` would be the way around it.
    A line to a reserved channel of ours is recorded here, since our own
    words there are just as reserved as anyone else's.
    """
    if verb == "RAW":
        m = re.match(r"(?i)(PRIVMSG|NOTICE|TOPIC)\s+(\S+)\s+:(.*)", rest)
        if not m:
            return True
        target, text = m.group(2), m.group(3)
    elif verb in ("SAY", "ACT", "NOTICE") and " " in rest:
        target, text = rest.split(" ", 1)
    else:
        return True
    # Services commands name the reserved channel by design (bot.startup's
    # `ChanServ :INVITE #it-opers` got eaten on the first restart, 2026-09-24).
    if target.lower() in ("chanserv", "nickserv"):
        return True
    reason = leak_guard.check(target, text, dm_ok=is_trust_listed(target))
    if reason:
        log("!", f"LEAK_BLOCKED {verb} {target} {reason}", origin)
        emit("LEAK_BLOCKED", verb, f"TO={target}", reason, f"LEN={len(text)}")
        return False
    leak_guard.record(target, text)
    return True


def process_cmd(line):
    if " " in line:
        verb, rest = line.split(" ", 1)
    else:
        verb, rest = line, ""
    origin = None
    if ":" in verb:
        verb, _, origin = verb.partition(":")
        origin = origin.lower()
        if not ORIGIN_PAT.match(origin):
            emit("CMD_ERROR", "bad-origin-tag", repr(origin),
                 "allowed: [a-z0-9_-]{1,24}")
            return
    verb = verb.upper()
    if not outbound_ok(verb, rest, origin):
        return
    if verb == "SAY":
        if " " not in rest:
            emit("CMD_ERROR", "SAY needs <target> <text>", repr(rest))
            return
        target, text = rest.split(" ", 1)
        split_say(target, text, origin)
    elif verb == "ACT":
        if " " not in rest:
            emit("CMD_ERROR", "ACT needs <target> <text>", repr(rest))
            return
        target, text = rest.split(" ", 1)
        send_raw(f"PRIVMSG {target} :\x01ACTION {text}\x01", origin)
    elif verb == "NOTICE":
        if " " not in rest:
            emit("CMD_ERROR", "NOTICE needs <target> <text>", repr(rest))
            return
        target, text = rest.split(" ", 1)
        send_raw(f"NOTICE {target} :{text}", origin)
    elif verb == "JOIN":
        send_raw(f"JOIN {rest}", origin)
    elif verb == "PART":
        send_raw(f"PART {rest}", origin)
    elif verb == "WHOIS":
        send_raw(f"WHOIS {rest}", origin)
    elif verb == "QUIT":
        send_raw(f"QUIT :{rest or 'bye'}", origin)
    elif verb == "RAW":
        send_raw(rest, origin)
    elif verb == "DCC":
        if " " not in rest:
            emit("CMD_ERROR", "DCC needs <nick> <file> [name]", repr(rest))
            return
        parts = rest.split(" ", 2)
        nick, name = parts[0], parts[1].strip()
        offer = parts[2].strip() if len(parts) > 2 and parts[2].strip() else None
        dcc_send(nick, name, origin, offer)
    else:
        emit("CMD_ERROR", "unknown-verb", repr(verb),
             "valid: SAY ACT NOTICE JOIN PART WHOIS QUIT RAW DCC")


def main():
    global sock
    load_trust()
    ctx = ssl.create_default_context()
    if not TLS_VERIFY:
        # Order matters: check_hostname must go first, CERT_NONE with hostname
        # checking still enabled raises ValueError.
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    raw = socket.create_connection(
        (HOST, PORT), timeout=30, source_address=((BIND, 0) if BIND else None)
    )
    # Belt-and-suspenders against silent TCP death (NAT/ISP drops):
    # kernel keepalive probes + app-level recv timeout. Server PINGs us
    # ~3-5min; 420s timeout on recv surfaces a stalled socket as
    # socket.timeout -> reader_loop returns -> systemd Restart=always.
    raw.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if hasattr(socket, "TCP_KEEPIDLE"):
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 15)
        raw.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 4)
    sock = ctx.wrap_socket(raw, server_hostname=HOST)
    sock.settimeout(420)
    emit("TLS_OK", HOST, PORT, "verify" if TLS_VERIFY else "NOVERIFY")
    send_raw(f"NICK {NICK}")
    send_raw(f"USER {IDENT} 0 * :{REAL}")

    threading.Thread(target=writer_loop, daemon=True).start()
    threading.Thread(target=idle_ticker_loop, daemon=True).start()
    brain_start()
    reader_loop()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        emit("FATAL", repr(e))
        sys.exit(1)
