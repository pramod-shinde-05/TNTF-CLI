FROM python:3.10-slim

# Install system dependencies required for packet sniffing and ML
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    gcc \
    python3-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the project
COPY . .

# Set PYTHONPATH so absolute imports work
ENV PYTHONPATH="/app"

# Keep container alive to allow interactive exec
CMD ["tail", "-f", "/dev/null"]
