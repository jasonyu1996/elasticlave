#!/bin/bash

if [ -z "$*" ]; then
    echo "No commands given!"
    exit 1
fi

docker run -i -t --rm --volume=$(pwd):/keystone:rw -a stdin -a stdout -w /keystone -u $(id -u):$(id -g) elasticlave-build $*

