salt-channel-c fuzzing
======================

This folder contains the fuzzing strategy for salt-channel-c. A salt channel is setup and test data is used to put the channel into the different states. The cryptographic library is considered to be stable and is mocked out in order to speed up the parsing process.

The possible inputs where different parsers are used is:
 * When the host receives A1 or M1.
 * When the host recieves M4.
 * When the host receives an application package. 
 * When the client receives A2.
 * When the client receives M2.
 * When the client receives M3.
 * When the client receives an application package.

 A valid input for each target is located under the input folder.

## Dependencies
In order to run the fuzz tests the following tools are required:
 * [American Fuzzy Lop](http://lcamtuf.coredump.cx/afl/)
 * gcov
 * lcov

## Usage
Make sure afl-gcc is installed to path, or if not, edit the fuzz.sh script to setup the compiler. Then run **./fuzz.sh**. In order to start fuzz see **enable.sh**. How to configure your system for fuzzing might differ, read AFL documentation for more information.

 Any input that causes crashes will end up in *output/target/crashes*.
 Any input that causes hangs will end up in *output/target/hangs*.
