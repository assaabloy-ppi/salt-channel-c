#!/bin/sh

mkdir DebugSan
cd DebugSan
cmake -DCMAKE_BUILD_TYPE=Debug -DSANITIZE_ADDRESS=On -DSANITIZE_UNDEFINED=On ..
make
ctest
