FROM python:3.7-alpine


# Install system dependencies
RUN apk add libarchive-dev git


# Install PyEasyArchive from CERT SG's fork (to manage encrypted files)
RUN pip3 install git+git://github.com/certsocietegenerale/PyEasyArchive#egg=libarchive


COPY extract.py /

RUN chmod u+x /extract.py

VOLUME ["/data"]

WORKDIR /data

ENTRYPOINT ["/extract.py", "--"]