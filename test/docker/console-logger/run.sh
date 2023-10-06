#!/bin/bash

declare CONTEXTDIR=../../../
declare DOCKERFILE=console-logger.dockerfile
declare IMAGENAME=one_collect_cli_console_logger

# Build the image.
docker build $CONTEXTDIR \
 -f $DOCKERFILE \
 -t $IMAGENAME

# Run the console logger for 5 seconds.
docker run --privileged $IMAGENAME --seconds 5