FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y libpq-dev gcc curl nmap && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Ensure empty migrations folder exists for alembic
RUN mkdir -p /app/alembic/versions

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
