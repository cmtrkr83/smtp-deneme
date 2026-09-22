FROM node:20-alpine

WORKDIR /app

ENV PORT=4004

COPY package*.json ./
RUN npm ci --omit=dev

COPY . .

RUN mkdir -p /app/data/uploads && \
    for f in announcements surveys responses file-requests requests logs files users; do \
      if [ -f "/app/$f.json" ]; then cp "/app/$f.json" "/app/data/"; fi; \
    done && \
    if [ -d /app/uploads ]; then cp -a /app/uploads/. /app/data/uploads/; fi

EXPOSE 4004

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:4004/ || exit 1

CMD ["node", "server.js"]
