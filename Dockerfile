FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1
ENV PORT=8080

WORKDIR /app

COPY main.py /app/main.py

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       curl \
       ca-certificates \
       procps \
       bash \
    && rm -rf /var/lib/apt/lists/*

EXPOSE 8080

CMD ["python3", "/app/main.py"]
