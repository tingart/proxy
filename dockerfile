FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        make \
        libc6-dev \
        ca-certificates \
        libcurl4-openssl-dev \
        libssl-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY main.c .

RUN gcc -O2 -pthread main.c -o orbit-proxy \
    -lcurl -lssl -lcrypto

EXPOSE 10000

CMD ["./orbit-proxy"]
