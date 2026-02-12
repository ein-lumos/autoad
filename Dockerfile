FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y socat && rm -rf /var/lib/apt/lists/*

COPY service/vulnerable_service/ /app/


RUN pip install --no-cache-dir -r requirements.txt || true

ENV PORT=5000

CMD ["socat", "TCP-LISTEN:5000,reuseaddr,fork", "EXEC:python3 main.py"]

