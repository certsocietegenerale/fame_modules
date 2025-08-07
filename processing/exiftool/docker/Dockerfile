FROM alpine:3

ENV EXIFTOOL_VERSION=13.33

RUN apk add --no-cache perl perl-utils make

# Install uesefull packages
RUN cpan -f Archive::Zip

# Download and install exiftool
RUN wget https://github.com/exiftool/exiftool/archive/refs/tags/${EXIFTOOL_VERSION}.tar.gz \
    && tar -zxvf ${EXIFTOOL_VERSION}.tar.gz \
    && cd exiftool-${EXIFTOOL_VERSION} \
    && perl Makefile.PL \
    && make test \
    && make install \
    && cd .. \
    && rm -rf exiftool-${EXIFTOOL_VERSION}

# Directory used to mount files to analyze
WORKDIR /data

ENTRYPOINT ["exiftool"]
