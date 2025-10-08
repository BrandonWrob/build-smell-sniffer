# syntax=docker/dockerfile:1

# 1) Base image
FROM python:3.12-slim

# 2) Environment tweaks
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_NO_INTERACTION=1 \
    POETRY_HOME=/opt/poetry \
    PATH=/opt/poetry/bin:$PATH

# 3) System dependencies
RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl \
      build-essential \
 && rm -rf /var/lib/apt/lists/*

# 4) Install Poetry
RUN curl -sSL https://install.python-poetry.org | python3 - \
 && poetry --version

# 5) Set working dir
WORKDIR /app

# 6) Copy metadata and install only main deps
COPY pyproject.toml poetry.lock ./
RUN poetry install --no-root --only main

# 7) Copy application code
COPY . .

# 8) Clean up any stray venv
RUN rm -rf /app/.venv

# 9) Create unprivileged user & fix permissions
RUN useradd --no-log-init -m appuser \
 && chown -R appuser /app
USER appuser

# 10) Expose port & launch
EXPOSE 5000
CMD ["python", "app.py"]
