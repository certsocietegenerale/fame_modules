FROM python:3.7-alpine


# Install system dependencies
RUN apk add libarchive-dev git


# Install PyEasyArchive from CERT SG's fork (to manage encrypted files)
RUN pip3 install -U https://github.com/DissectMalware/XLMMacroDeobfuscator/archive/master.zip


VOLUME ["/data"]

WORKDIR /data

ENTRYPOINT ["xlmdeobfuscator", "--"]