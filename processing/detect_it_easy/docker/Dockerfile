FROM debian:trixie-slim

RUN apt update && \
    apt install -y wget && \
    wget https://github.com/horsicq/DIE-engine/releases/download/3.21/die_3.21_Debian_13_amd64.deb && \
    apt install -y ./die_3.21_Debian_13_amd64.deb && \
    rm die_3.21_Debian_13_amd64.deb && \
    apt install -f

ENTRYPOINT ["/usr/bin/diec"]
