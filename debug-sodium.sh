#!/bin/sh

rm -rf Debug
mkdir Debug
cd Debug
cmake -DCRYPTO_BACKEND=libsodium -DCMAKE_BUILD_TYPE=Debug ..
make
ctest


