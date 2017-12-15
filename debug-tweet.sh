#!/bin/sh

rm -rf Debug
mkdir Debug
cd Debug
cmake -DCRYPTO_BACKEND=tweetnacl_modified -DCMAKE_BUILD_TYPE=Debug ..
make
ctest


