#!/bin/sh

./examples/host_echo > /dev/null 2>&1 &
pid=$!

passed=0
if java -cp salt-channel-2.5.jar saltchannel.dev.TcpEchoTester > /dev/null ; then
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