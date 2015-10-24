#!/bin/bash

host="$1"
curl -H 'Id: 1' -d '{"login":"i_am_stupid","password":"12345"}' "$host/user"
