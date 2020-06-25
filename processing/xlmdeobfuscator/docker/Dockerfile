FROM python:3.7-alpine


RUN apk add libffi-dev gcc musl-dev libressl-dev

RUN pip3 install -U https://github.com/DissectMalware/xlrd2/archive/master.zip
RUN pip3 install -U https://github.com/DissectMalware/pyxlsb2/archive/master.zip
RUN pip3 install -U https://github.com/DissectMalware/XLMMacroDeobfuscator/archive/master.zip

VOLUME ["/data"]

WORKDIR /data

ENTRYPOINT ["xlmdeobfuscator"]
