# Use a small Python base image
FROM python:3.11-slim

# Create working directory
WORKDIR /app

# Install system dependencies (optional)
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential && \
    rm -rf /var/lib/apt/lists/*

# Copy app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Expose port for FastAPI
EXPOSE 8000

# Render will call this command
CMD ["uvicorn", "server:app", "--host", "0.0.0.0", "--port", "8000"]
