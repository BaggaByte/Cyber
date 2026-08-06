# Use a lightweight official Python runtime as a parent image
FROM python:3.10-slim

# Prevent Python from writing pyc files to disc and buffering stdout
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set the working directory in the container
WORKDIR /app

# Install system dependencies (Git is required for some Semgrep features)
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/*

# Copy requirements file first to cache pip install layer
COPY Aegis-AI/requirements.txt /app/requirements.txt

# Install the Python packages your backend relies on
RUN pip install --no-cache-dir -r /app/requirements.txt

# Copy environment variables
COPY .env /app/.env

# Copy your source code into the container
COPY Aegis-AI/src/ /app/src/

# Expose the FastAPI port
EXPOSE 8001

# Command to boot the backend server when the container starts
CMD ["uvicorn", "src.main:app", "--host", "0.0.0.0", "--port", "8001"]
