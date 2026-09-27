FROM kalilinux/kali-rolling

RUN apt-get update && apt-get install -y \
    curl \
    git \
    python3 \
    python3-pip \
    hping3 \
    wrk \
    slowhttptest \
    nmap \
    psmisc \
    && rm -rf /var/lib/apt/lists/*

# Install paramiko for our custom SSH brute-force script
RUN pip3 install --break-system-packages paramiko

WORKDIR /scripts

# Wait infinitely. The user will attach via docker exec
CMD ["tail", "-f", "/dev/null"]