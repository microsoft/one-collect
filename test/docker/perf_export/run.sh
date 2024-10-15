#!/bin/bash

declare CONTEXTDIR=../../../
declare DOCKERFILE=perf_export.dockerfile
declare IMAGENAME=one_collect__perf_export

# Build the image.
docker build $CONTEXTDIR \
 -f $DOCKERFILE \
 -t $IMAGENAME

# Run the perf_export example.
docker run --privileged $IMAGENAME