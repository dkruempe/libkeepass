FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    ninja-build \
    libssl-dev \
    zlib1g-dev \
    libpugixml-dev \
    libargon2-dev

RUN git clone --depth 1 https://github.com/dkruempe/libkeepass.git "$SRC/libkeepass"

COPY build.sh "$SRC/"

WORKDIR "$SRC/libkeepass"
