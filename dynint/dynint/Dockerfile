FROM python:3.11-slim

# Install system dependencies for Frida and Capstone
RUN apt-get update && apt-get install -y \
    build-essential \
    pkg-config \
    libffi-dev \
    libssl-dev \
    git \
    file \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy project files
COPY . .

# Install Python dependencies
RUN pip install --upgrade pip setuptools wheel

# Install the package with all optional dependencies
RUN pip install -e .[analysis]

# Install pytest for testing
RUN pip install pytest pytest-cov

# Set environment variables
ENV PYTHONPATH=/app/dynint

# Default command to run tests
CMD ["python", "-m", "pytest", "tests/", "-v"]