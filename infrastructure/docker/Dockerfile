FROM python:3.11-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    iputils-ping \
    traceroute \
    curl \
  && rm -rf /var/lib/apt/lists/*

RUN pip install poetry==1.8.2
ENV POETRY_NO_INTERACTION=1 \
    POETRY_VENV_IN_PROJECT=1

COPY pyproject.toml poetry.lock* ./
RUN poetry install --only=main --no-root

COPY . .
RUN poetry install --only=main

EXPOSE 8000

CMD ["poetry", "run", "uvicorn", "cybersec.apps.api.main:app", \
     "--host", "0.0.0.0", "--port", "8000"]
