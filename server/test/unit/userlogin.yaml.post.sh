#!/bin/bash

redis-cli -x del "user:i_am_stupid" >/dev/null &
pid=$1
sleep 0.1
