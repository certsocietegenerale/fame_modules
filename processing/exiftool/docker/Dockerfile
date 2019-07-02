FROM perl:5

ENV EXIFTOOL_VERSION=11.24

# Install uesefull packages
RUN cpan Archive::Zip

# Download and install exiftool
RUN wget http://www.sno.phy.queensu.ca/~phil/exiftool/Image-ExifTool-${EXIFTOOL_VERSION}.tar.gz \
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