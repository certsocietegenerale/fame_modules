FROM python:3.7-alpine


RUN apk add libffi-dev gcc musl-dev libressl-dev
RUN pip3 install XLMMacroDeobfuscator

VOLUME ["/data"]

WORKDIR /data

ENTRYPOINT ["xlmdeobfuscator"]