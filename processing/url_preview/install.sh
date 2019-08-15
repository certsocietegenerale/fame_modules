#!/bin/bash

apt-get update && apt-get install --no-install-recommends -y docker.io || exit $?

bash build.sh || exit $?
