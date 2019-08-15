#!/bin/bash

apt-get update && apt-get install -y --no-install-recommends docker.io || exit $?

bash build.sh || exit $?
