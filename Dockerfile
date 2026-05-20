FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    iputils-ping \
    traceroute \
    curl \
    libpcap-dev \
    procps \
    nodejs \
    npm \
    && rm -rf /var/lib/apt/lists/*

# Kernel tuning (applied at runtime via docker --sysctl or docker-compose sysctls)
COPY infrastructure/sysctl.conf /etc/sysctl.d/90-cybersec.conf
COPY infrastructure/limits.conf /etc/security/limits.d/90-cybersec.conf

RUN pip install poetry==1.8.2
ENV POETRY_NO_INTERACTION=1 \
    POETRY_VENV_IN_PROJECT=1 \
    POETRY_VIRTUALENVS_CREATE=false

COPY pyproject.toml poetry.lock* ./
RUN poetry install --only=main --no-root --no-interaction --no-ansi || \
    pip install fastapi uvicorn sqlalchemy asyncpg alembic python-jose[cryptography] \
                passlib[bcrypt] click rich httpx dnspython python-whois cryptography \
                reportlab pydantic-settings email-validator slowapi scapy groq \
                mitreattack-python arq python-multipart

COPY . .

# Build the React frontend
RUN cd cybersec/web/ui && npm install && npm run build

EXPOSE 8000

COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]
CMD ["uvicorn", "cybersec.apps.api.main:app", "--host", "0.0.0.0", "--port", "8000"]
