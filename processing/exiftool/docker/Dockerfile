FROM alpine:3

ENV EXIFTOOL_VERSION=12.34

RUN apk add --no-cache perl perl-utils make

# Install uesefull packages
RUN cpan -f Archive::Zip

# Download and install exiftool
RUN wget https://exiftool.org/Image-ExifTool-${EXIFTOOL_VERSION}.tar.gz \
    && tar -zxvf Image-ExifTool-${EXIFTOOL_VERSION}.tar.gz \
    && cd Image-ExifTool-${EXIFTOOL_VERSION} \
    && perl Makefile.PL \
    && make test \
    && make install \
    && cd .. \
    && rm -rf Image-ExifTool-${EXIFTOOL_VERSION}

# Directory used to mount files to analyze
WORKDIR /data

ENTRYPOINT ["exiftool"]
