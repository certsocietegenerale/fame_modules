#!/bin/bash
SCRIPT=`realpath $0`
SCRIPTPATH=`dirname $SCRIPT`

docker build -t fame/qr_extractor $SCRIPTPATH/docker
