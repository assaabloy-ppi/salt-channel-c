#!/bin/sh

rm -rf Debug
mkdir Debug
cd Debug
cmake -DCMAKE_BUILD_TYPE=Debug ..
make
ctest


