# Dockerfile for BlacksmithAI Dashboard
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY blacksmithAI/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy app code
COPY blacksmithAI/ .

# Create directories
RUN mkdir -p store outputs/reports outputs/runs outputs/memory

# Expose port
EXPOSE 8501

# Run dashboard
CMD ["python", "web/dashboard.py", "--host=0.0.0.0"]
