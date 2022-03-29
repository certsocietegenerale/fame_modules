FROM python:3.7-alpine


# Install system dependencies
RUN apk add libarchive-dev git


# Install PyEasyArchive from CERT SG's fork (to manage encrypted files)
RUN pip3 install git+https://github.com/certsocietegenerale/PyEasyArchive@f4f386ccb9552d58cab241fc16cc31a2b00a8341#egg=libarchive


COPY extract.py /

RUN chmod u+x /extract.py

VOLUME ["/data"]

WORKDIR /data

ENTRYPOINT ["/extract.py", "--"]
