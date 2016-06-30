#!/bin/bash

SCRIPT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd "$SCRIPT_DIR"
DATE=`date -u '+%Y/%m/%dT%H:%M:%S'`
export GOPATH="$SCRIPT_DIR"
export GOBIN=""
#go get
go build github.com/alexeyknyshev/cpsrv
#go build github.com/alexeyknyshev/server
#go build github.com/alexeyknyshev/tools/server_sqlite_to_redis
go build github.com/alexeyknyshev/tools/server_sqlite_to_tarantool
go install github.com/alexeyknyshev/cpsrv
#go install github.com/alexeyknyshev/server
#go install github.com/alexeyknyshev/tools/server_sqlite_to_redis
go install github.com/alexeyknyshev/tools/server_sqlite_to_tarantool
[ -e "$SCRIPT_DIR/cpsrv" ] && rm "$SCRIPT_DIR/cpsrv"
#[ -e "$SCRIPT_DIR/server" ] && rm "$SCRIPT_DIR/server"
#[ -e "$SCRIPT_DIR/server_sqlite_to_redis" ] && rm "$SCRIPT_DIR/server_sqlite_to_redis"
[ -e "$SCRIPT_DIR/server_sqlite_to_tarantool" ] && rm "$SCRIPT_DIR/server_sqlite_to_tarantool"
