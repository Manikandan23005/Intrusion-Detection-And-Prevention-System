FROM python:3.10-slim

WORKDIR /app

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y tzdata && \
    apt-get install -y \
    iptables \
    sudo \
    systemd \
    libglib2.0-0 \
    libgl1 \
    libxcb-cursor0 \
    && rm -rf /var/lib/apt/lists/*


# Install poetry
RUN pip install --no-cache-dir poetry

COPY pyproject.toml poetry.lock* ./

RUN poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-ansi --no-root

COPY . .

# Run the client
CMD ["python", "main.py"]
