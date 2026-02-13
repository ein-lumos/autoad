FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*

COPY app/ /app/


RUN pip install --no-cache-dir -r requirements.txt || true


CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:python3 main.py"]

