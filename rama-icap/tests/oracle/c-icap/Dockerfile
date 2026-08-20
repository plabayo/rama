FROM debian:bookworm-slim AS builder

ARG C_ICAP_COMMIT=25f881d16f4dfbc943ee0a01d4c174d231afbb57

RUN apt-get update \
    && apt-get install --yes --no-install-recommends \
        autoconf \
        automake \
        build-essential \
        ca-certificates \
        git \
        libltdl-dev \
        libtool \
        pkg-config \
    && rm -rf /var/lib/apt/lists/*

RUN git clone https://github.com/c-icap/c-icap-server.git /src/c-icap \
    && git -C /src/c-icap checkout --detach "${C_ICAP_COMMIT}" \
    && printf '%s\n' '0.6.5-dev.25f881d' > /src/c-icap/VERSION.m4 \
    && cd /src/c-icap \
    && autoreconf --force --install --verbose --warnings=all \
    && ./configure \
        --prefix=/opt/c-icap \
        --libdir=/opt/c-icap/lib \
        --disable-dependency-tracking \
    && make -j2 \
    && make install-strip

FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates libatomic1 libltdl7 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/c-icap /opt/c-icap
COPY c-icap.conf /opt/c-icap/etc/rama-oracle.conf
COPY c-icap-204.conf /opt/c-icap/etc/rama-oracle-204.conf
COPY reference-matrix.sh /opt/rama-icap-oracle/reference-matrix.sh

RUN chmod 0555 /opt/rama-icap-oracle/reference-matrix.sh

ENV LD_LIBRARY_PATH=/opt/c-icap/lib

EXPOSE 1344

HEALTHCHECK --interval=2s --timeout=3s --start-period=2s --retries=20 \
    CMD ["/opt/c-icap/bin/c-icap-client", "-i", "127.0.0.1", "-p", "1344", "-s", "echo"]

CMD ["/opt/c-icap/bin/c-icap", "-N", "-S", "-D", "-d", "3", "-f", "/opt/c-icap/etc/rama-oracle.conf"]
