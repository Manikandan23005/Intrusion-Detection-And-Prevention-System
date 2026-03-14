FROM python:3.10-slim

WORKDIR /app

# Install poetry
RUN pip install --no-cache-dir poetry

COPY pyproject.toml poetry.lock* ./

RUN poetry config virtualenvs.create false && \
    poetry install --no-interaction --no-ansi --no-root

COPY . .

# Make the start script executable
RUN chmod +x start.sh

# Expose both API and Dashboard ports
EXPOSE 5000 8080

CMD ["./start.sh"]
