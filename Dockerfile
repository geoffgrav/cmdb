# Use the official lightweight Python image
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /workspace

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements.txt first to leverage Docker caching
COPY requirements.txt .

# Upgrade pip and install Python dependencies
RUN pip install --upgrade pip \
    && pip install -r requirements.txt

# Install optional dev tools globally (you can remove if not needed)
RUN pip install \
    black \
    flake8 \
    isort \
    pip-tools \
    debugpy

# Copy everything else (scripts, .env, customers.csv, etc.)
COPY . .

# Expose debug port if needed
EXPOSE 5678

# Set default shell (optional)
CMD [ "bash" ]