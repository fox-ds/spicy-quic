# Spicy analyzer for the QUIC protocol
### WORK IN PROGRESS - DEFINITELY NOT SUITABLE FOR PRODUCTION ENVIRONMENTS

A QUIC protocol analyzer for Zeek, based on Spicy. This analyzer tries to be compabile with [QUIC IETF version 1](https://datatracker.ietf.org/doc/html/rfc9000). 

Updates via Zeek slack and/or https://github.com/zeek/zeek/issues/2326. Feel free to contribute via issues/PR's. This repository will probably be moved/merged into some other repository in the future. This code is merely a starting point for future improvements.

Clone locally and build with:
```bash
git clone https://github.com/fox-ds/spicy-quic.git
cd spicy-quic && zkg install .
```
or without the use of `zkg`:
```bash
mkdir -p build && cd build && cmake .. && cmake --build .
zeek -Cr ../testing/Traces/quic_win11_firefox_google.pcap spicy-modules/quic.hlto
```