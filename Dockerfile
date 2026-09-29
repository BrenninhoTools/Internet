FROM debian:bookworm-slim AS build
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential cmake ninja-build ca-certificates \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY . .
RUN cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release -DINTERNET_BUILD_APP=OFF -DINTERNET_BUILD_TESTS=OFF \
    && cmake --build build --target internet internet-server

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --home-dir /srv/internet --shell /usr/sbin/nologin internet
COPY --from=build /src/build/internet /src/build/internet-server /usr/local/bin/
COPY deploy/entrypoint.sh /usr/local/bin/internet-entrypoint
RUN sed -i 's/\r$//' /usr/local/bin/internet-entrypoint && chmod +x /usr/local/bin/internet-entrypoint
USER internet
WORKDIR /srv/internet
VOLUME /srv/internet
EXPOSE 4000 8080 4100-4199
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s CMD internet list --registry 127.0.0.1:4000 || exit 1
ENTRYPOINT ["internet-entrypoint"]
