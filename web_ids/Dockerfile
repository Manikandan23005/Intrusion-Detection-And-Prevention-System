FROM python:3.10-slim

WORKDIR /app

# Install iptables, sudo, systemd, and tzdata (non-interactive)
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y tzdata && \
    apt-get install -y \
    iptables \
    sudo \
    systemd \
    procps \
    && rm -rf /var/lib/apt/lists/*

# Install poetry
RUN pip install --default-timeout=100 poetry

# Copy dependency files
COPY pyproject.toml poetry.lock* ./

# Install python packages
RUN poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-ansi --no-root

# Copy application code
COPY . .

# Expose port (now using 9090 to avoid Jenkins conflict)
EXPOSE 9090

# Start Flask app
CMD ["python", "app.py"]
