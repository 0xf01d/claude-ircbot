# k8s manifests

Single test Deployment (namespace `ircbot-test`, maintained in the flux repo
under `apps/claude-ircbot-test/`, NOT here). The container runs the stock
`python:3.12-slim` image; `bot.py`, `leak_guard.py` and the trust/startup
files are provided by a ConfigMap mounted into the container.

- Outbound TLS only, to one IRC host; no inbound ports.
- Commands reach the bot through the named pipe `/data/bot.send` (FIFO mode
  0600, created by bot.py itself at startup).
- `bot.startup` replays FIFO-style commands after registration, so the test
  instance joins its channel without baking JOINs into bot.py.
- No `NICKSERV_PASS` is configured: the bot skips NickServ auth entirely.

Caveat when sending commands from inside the pod: the FIFO must be opened for
reading or the writer blocks. `printf 'SAY #chan hi\n' > /data/bot.send`
blocks until the bot reads it (it always has a reader thread open, so this is
fine) — but never use `echo -n` without a trailing newline and never leave a
writer holding the FIFO open, or the bot sees EOF handling quirks. Prefer one
short `sh -c 'printf ... > /data/bot.send'` per command.
