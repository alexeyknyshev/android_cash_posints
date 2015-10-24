#!/bin/bash

verbose=0
if [ $# -eq 1 ]
then
    if [ $1 = "-v" ]
    then
        verbose=1
    fi
fi

SCRIPT_DIR=$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )
cd "$SCRIPT_DIR"

if [ ! -e config.json ]
then
    echo "No such file: config.json"
    exit 1
fi

SERVER_PORT=$(jq '.Port' config.json)
#echo $SERVER_PORT

SERVER_PID=''
if [ $verbose -eq 0 ]
then
    ./server config.json >/dev/null 2>/dev/null &
    SERVER_PID="$!"
else
    ./server config.json &
    SERVER_PID="$!"
fi

TEST_COUNT=$(find test/unit -name '*.yaml' | wc -l)

currentTestIndex=1

for testFile in test/unit/*.yaml
do
    preScriptPath="$testFile.pre.sh"
    postScriptPath="$testFile.post.sh"
    host="localhost:$SERVER_PORT"
    currentTestPrefix="[$currentTestIndex/$TEST_COUNT] "

    if [ -e "$preScriptPath" ]
    then
        [ $verbose -eq 1 ] && echo "running $preScriptPath"
        bash "$preScriptPath" "$host"
    fi

    [ $verbose -eq 1 ] && echo "${currentTestPrefix}running $testFile"
    printf "%s" "$currentTestPrefix"
    pyresttest "$host" "$testFile"

    if [ -e "$postScriptPath" ]
    then
        [ $verbose -eq 1 ] && echo "running $postScriptPath"
        bash "$postScriptPath" "$host"
    fi
    ((currentTestIndex++))
done

kill $SERVER_PID
