#!/bin/bash

./docker-build.sh
./docker-run.sh ./fast-setup.sh
./docker-run.sh ./make-sodium.sh
./docker-run.sh ./make-musl.sh
if [ -z "$MAKE_FIRESIM" ]; then
  ./docker-run.sh ./make.sh
  ./docker-run.sh ./make-sdk.sh
  ./docker-run.sh ./make.sh image
else
  ./docker-run.sh ./make-firesim.sh
  ./docker-run.sh ./make-sdk.sh
  ./docker-run.sh ./make-firesim.sh image
fi

