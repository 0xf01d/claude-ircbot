#!/usr/bin/env python3
"""katiabot fixed-commands sidecar (k8s test pod, container 3 of 3).

Sits next to bot.py (transport) and driver.mjs (LLM brain), tails the same
/data/events.log stream and owns two things:

Fixed commands: a channel mention whose body matches an entry of
/commands/commands.json

    {"commands": [{"match": "ciao", "reply": "ciao!"}, ...]}

is answered immediately with the canned reply through the FIFO
(`SAY #AI-live ...`) — no LLM round-trip. Match is a case-insensitive
substring, first entry wins. Every answered mention appends a marker to
/data/handled.log (`<epoch> <nick> <sha256(body)[:16]>`); the brain reads the
same file to skip mentions it must not answer a second time.

LEARN: a trust-listed nick saying `katiabot impara: <trigger> => <risposta>`
patches the claude-ircbot-test-commands ConfigMap through the in-cluster API
(SA token + CA, verbs get/patch/update granted by RoleBinding) and confirms in
channel. The learned entry replaces an existing entry with the same trigger
(case-insensitive), else it is appended. The CM is live-only (git-registry-auth
pattern: applied by hand, never committed), and because the ConfigMap volume is
mounted WITHOUT subPath the kubelet hot-reloads it — commands.json is re-read
every loop iteration, so the new command goes live within a sync period.
"""
import hashlib
import json
import os
import re
import ssl
import time
import urllib.error
import urllib.request

EVENTS = os.environ.get("SIDECAR_EVENTS", "/data/events.log")
FIFO = os.environ.get("SIDECAR_FIFO", "/data/bot.send")
CMDS_FILE = os.environ.get("SIDECAR_CMDS", "/commands/commands.json")
HANDLED = os.environ.get("SIDECAR_HANDLED", "/data/handled.log")
NICK = os.environ.get("IRC_NICK", "katiabot").lower()
CHANNEL = "#AI-live"
CM_NAME = os.environ.get("SIDECAR_CM_NAME", "claude-ircbot-test-commands")
SA_DIR = "/var/run/secrets/kubernetes.io/serviceaccount"
K8S_API = os.environ.get("SIDECAR_K8S_API", "https://kubernetes.default.svc")
POLL_SECONDS = 1.0

LEARN_RE = re.compile(r"\bimpara:\s*(.+?)\s*=>\s*(.+)", re.I)
MSG_RE = re.compile(r"^(?:\[\d{2}:\d{2}\]\s+)?MSG TRUSTED\b")
FROM_RE = re.compile(r"\bFROM=(\S+)")
TO_RE = re.compile(r"\bTO=(\S+)")
BODY_RE = re.compile(r"\bBODY=(.*)$", re.S)


def log(kind, *parts):
    print(f"[commands] {kind} " + " ".join(str(p) for p in parts), flush=True)


def body_hash(body):
    # MUST match driver.mjs bodyHash(): sha256 hex, first 16 chars.
    return hashlib.sha256(body.encode("utf-8")).hexdigest()[:16]


def load_commands():
    """Re-read commands.json every iteration; [] when absent or invalid."""
    try:
        with open(CMDS_FILE) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    entries = data.get("commands") if isinstance(data, dict) else None
    if not isinstance(entries, list):
        return []
    return [
        e for e in entries
        if isinstance(e, dict)
        and isinstance(e.get("match"), str) and e["match"]
        and isinstance(e.get("reply"), str)
    ]


def match_command(commands, body):
    low = body.lower()
    for entry in commands:
        if entry["match"].lower() in low:
            return entry["reply"]
    return None


def tail_events(state, commands):
    """Handle complete lines appended to EVENTS since the last poll."""
    try:
        size = os.path.getsize(EVENTS)
    except OSError:
        state["pos"] = 0  # bot.py creates the file on its first emit()
        return
    if size < state["pos"]:  # truncated/rotated
        state["pos"] = 0
    if size == state["pos"]:
        return
    with open(EVENTS) as f:
        f.seek(state["pos"])
        data = f.read()
    state["pos"] = size
    state["partial"] += data
    *lines, state["partial"] = state["partial"].split("\n")
    for line in lines:
        if line:
            handle_event(line, commands)


def handle_event(line, commands):
    if not MSG_RE.match(line):
        return
    frm = FROM_RE.search(line)
    to = TO_RE.search(line)
    body = BODY_RE.search(line)
    if not (frm and to and body):
        return
    if to.group(1).lower() != CHANNEL.lower():
        return
    text = body.group(1)
    if NICK not in text.lower():
        return

    learned = try_learn(frm.group(1), text)
    if learned is not None:
        reply_to(frm.group(1), text, learned, tag="CMD_LEARNED")
        return
    reply = match_command(commands, text)
    if reply is None:
        return
    reply_to(frm.group(1), text, reply, tag="CMD_REPLIED")


def reply_to(nick, body, reply, tag):
    with open(FIFO, "w") as f:  # bot.py always keeps a reader on the FIFO
        f.write(f"SAY {CHANNEL} {reply}\n")
    with open(HANDLED, "a") as f:
        # Marker format "<epoch> <nick> <sha256(body)[:16]>" — parsed verbatim
        # by driver.mjs handledRecently() for its dedupe window.
        f.write(f"{int(time.time())} {nick} {body_hash(body)}\n")
    log(tag, nick, f"hash={body_hash(body)}", reply[:80])


def cm_url():
    ns = os.environ.get("SIDECAR_NAMESPACE")
    if not ns:
        try:
            with open(os.path.join(SA_DIR, "namespace")) as f:
                ns = f.read().strip()
        except OSError:
            ns = "ircbot-test"
    return f"{K8S_API}/api/v1/namespaces/{ns}/configmaps/{CM_NAME}"


def _api(op, url, payload=None, content_type="application/json"):
    token_file = os.path.join(SA_DIR, "token")
    ca_file = os.path.join(SA_DIR, "ca.crt")
    ctx = ssl.create_default_context(cafile=ca_file)
    headers = {"Authorization": f"Bearer {open(token_file).read().strip()}"}
    data = None
    method = "GET"
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
        method = op
        headers["Content-Type"] = content_type
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    with urllib.request.urlopen(req, timeout=15, context=ctx) as resp:
        return json.loads(resp.read().decode("utf-8", errors="ignore"))


def try_learn(nick, body):
    """`katiabot impara: <trigger> => <risposta>` -> patched CM reply text.

    Returns the confirmation line on success, None when the message is not a
    LEARN command. API failures log LEARN_ERROR and return None so the fixed
    commands and the brain still see the message untouched.
    """
    m = LEARN_RE.search(body)
    if not m:
        return None
    trigger = m.group(1).strip()
    answer = m.group(2).strip()
    if not trigger or not answer:
        return None
    try:
        cm = _api("GET", cm_url())
        entries = json.loads(cm["data"].get("commands.json", "{}")).get("commands", [])
        low = trigger.lower()
        for e in entries:
            if isinstance(e, dict) and isinstance(e.get("match"), str) \
                    and e["match"].lower() == low:
                e["reply"] = answer  # re-teach wins over append
                break
        else:
            entries.append({"match": trigger, "reply": answer})
        patch = {"data": {"commands.json": json.dumps(
            {"commands": entries}, ensure_ascii=False, indent=2)}}
        _api("PATCH", cm_url(), payload=patch,
             content_type="application/merge-patch+json")
    except (OSError, ValueError, KeyError, urllib.error.URLError) as e:
        log("LEARN_ERROR", nick, f"trigger={trigger!r}", repr(e))
        return None
    log("LEARN_OK", nick, f"trigger={trigger!r}")
    return f"imparato: {trigger} => {answer}"


def main():
    log("SIDECAR_STARTED", f"nick={NICK} channel={CHANNEL} events={EVENTS} "
        f"fifo={FIFO} cmds={CMDS_FILE} handled={HANDLED} cm={CM_NAME}")
    state = {"pos": 0, "partial": ""}
    while True:
        try:
            tail_events(state, load_commands())  # re-read commands every loop
        except Exception as e:
            log("SIDECAR_ERROR", repr(e))
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()
