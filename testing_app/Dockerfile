FROM python:3.10-slim

WORKDIR /app

# Install dependencies (flask) and openssh-server for brute-force simulation
RUN apt-get update && apt-get install -y openssh-server && \
    pip install --no-cache-dir flask && \
    mkdir -p /var/run/sshd && \
    useradd -m -s /bin/bash mobile && \
    echo 'mobile:mobile' | chpasswd && \
    echo 'MaxStartups 1000:30:1200' >> /etc/ssh/sshd_config && \
    echo 'MaxSessions 1000' >> /etc/ssh/sshd_config

# Copy the flask application code
COPY python_app/ /app/

EXPOSE 8080 22

# Run sshd in background and flask in foreground
CMD service ssh start && python app.py
