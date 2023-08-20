FROM zeek/zeek:6.0

RUN apt-get update

RUN apt-get install -y --no-install-recommends \
  build-essential \
  cmake \
  libpcap-dev \
  libssl-dev

RUN zeek --version
RUN spicyc --version
RUN openssl version

WORKDIR /src

COPY CMakeLists.txt ./
COPY ./analyzer ./analyzer
COPY ./cmake ./cmake
COPY ./testing ./testing
COPY ./scripts ./scripts

RUN ls -lha
WORKDIR /src/build
RUN cmake ../ && make

WORKDIR /src/testing
RUN btest -j -d ./tests
