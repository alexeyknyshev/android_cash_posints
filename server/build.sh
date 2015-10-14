#!/bin/bash

SCRIPT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd "$SCRIPT_DIR"
DATE=`date -u '+%Y/%m/%dT%H:%M:%S'`
export GOPATH="$SCRIPT_DIR"
go get
go build -ldflags "-X main.BuildDate $DATE"
