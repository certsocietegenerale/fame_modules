#!/bin/bash

apt-get update && apt-get install -y docker.io || exit $?

bash build.sh || exit $?
