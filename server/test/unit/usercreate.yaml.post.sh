#!/bin/bash

redis-cli -x del "user:user" >/dev/null &
pid=$!
sleep 0.1
#kill $pid
