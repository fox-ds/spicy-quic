FROM debian:bookworm

WORKDIR /quic-plugin

# Expand PATH to include Zeek
ENV PATH="${PATH}:/opt/zeek/bin"

# Install Zeek (5.2.2-0)
RUN apt-get update && \
    apt-get install -y curl gpg && \
    echo 'deb http://download.opensuse.org/repositories/security:/zeek/Debian_Testing/ /' | tee /etc/apt/sources.list.d/security:zeek.list && \
    curl -fsSL https://download.opensuse.org/repositories/security:zeek/Debian_Testing/Release.key | gpg --dearmor | tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null && \
    apt-get update && \
    apt-get install -y zeek=5.2.2-0 && \
    # Install dependencies for spicy-quic plugin
    apt-get install -y libssl-dev git build-essential cmake && \
    rm -rf /var/lib/apt/lists/*

# Copy plugin files
COPY . .

# OPTIONAL: Create commit in the container to not have 'dirty' git clone, useful when developing
# RUN git config user.name "tmp" && git config user.email "tmp" && git add . && git commit -m "tmp"

# Install the package
RUN zkg install . --force
RUN zeek -NN | grep QUIC