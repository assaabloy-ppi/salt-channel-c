#!/bin/sh

$1 > lol.txt 2>&1 &
pid=$!

passed=0
if java -cp $2 saltchannel.dev.TcpEchoTester > /dev/null ; then
    passed=1
fi

if ps -p $pid > /dev/null ; then
    kill $pid
    wait $pid 2>/dev/null
else
    passed=0
fi

if [ "$passed" = "1" ]; then
    echo "Test with java echo client passed"
    exit 0
else
    echo "Test with java echo client failed"
    exit 1
fi