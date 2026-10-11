FROM python:3.12-slim
WORKDIR /app
COPY bot.py leak_guard.py bot.say ./
RUN mkdir -p /data
ENV BOT_FIFO=/data/bot.send \
    BOT_LOG=/data/bot.log \
    BOT_ENV=/data/.env \
    BOT_TRUST=/data/bot.trust \
    BOT_STARTUP=/data/bot.startup \
    BOT_RESERVED_STORE=/data/reserved_recent.tsv
CMD ["python3", "-u", "bot.py"]
