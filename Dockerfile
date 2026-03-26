FROM python:3.11-slim

WORKDIR /app

# System deps for xhtml2pdf / reportlab / Pillow / cryptography / pycairo
RUN apt-get update && apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
        libssl-dev \
        libjpeg-dev \
        zlib1g-dev \
        libcairo2-dev \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5100

CMD ["gunicorn", \
     "--workers", "2", \
     "--worker-class", "gthread", \
     "--threads", "4", \
     "--bind", "0.0.0.0:5101", \
     "--timeout", "120", \
     "--forwarded-allow-ips", "*", \
     "run:app"]
