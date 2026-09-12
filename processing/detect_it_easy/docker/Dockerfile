FROM debian:trixie-slim

RUN apt update && apt upgrade -y && apt install -y wget &&  wget https://github.com/horsicq/DIE-engine/releases/download/3.21/die_3.21_Debian_13_amd64.deb && apt install /die_3.21_Debian_13_amd64.deb -y && rm die_3.21_Debian_13_amd64.deb

ENTRYPOINT ["/usr/bin/diec"]
