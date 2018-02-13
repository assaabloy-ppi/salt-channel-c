salt-channel-c fuzzing
======================

In this folder there is a Makefile that can be used to fuzz all scenarios when the salt-channel-c parses input data. A salt channel is setup and test data is used to put the channel into the different states. The cryptographic library is considered to be stable and is mocked out in order to speed up the parsing process. However, the cryptographic library (only TweetNaCl right now) can be compiled instead of the mock if defining *USE_TWEETNACL* to the make script. 

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
To start fuzzing any of the input, just run **CC=/path/to/afl-gcc make target**. Valid targets are:
 * host_a1m1.fuzz
 * host_m4.fuzz
 * host_app.fuzz
 * client_a2.fuzz
 * client_m2.fuzz
 * client_m3.fuzz
 * client_app.fuzz

 Any input that causes crashes will end up in *output/target/crashes*.
 Any input that causes hangs will end up in *output/target/hangs*.

 All different input that results in a new path in the program will end up in *output/target/queue*. The outputs can then be runned again with coverage flags to see whats parts of the code was executed.


 Example usage using afl-clang:
 ```sh
$ CC=afl-clang make host_a1m1.fuzz
mkdir -p _build
mkdir -p output
AFL_HARDEN=1 afl-clang -DAFL ../src/salt.c ../src/salti_util.c ../src/salti_handshake.c read_util.c crypt_mock.c test_data_mock.c host_a1m1.c  -I../src -I../tests -I../src/external/tweetnacl -std=c99 -o _build/host_a1m1.fuzz
afl-cc 2.35b by <lcamtuf@google.com>
afl-as 2.35b by <lcamtuf@google.com>
[+] Instrumented 191 locations (64-bit, hardened mode, ratio 100%).
afl-as 2.35b by <lcamtuf@google.com>
[+] Instrumented 105 locations (64-bit, hardened mode, ratio 100%).
afl-as 2.35b by <lcamtuf@google.com>
[+] Instrumented 175 locations (64-bit, hardened mode, ratio 100%).
afl-as 2.35b by <lcamtuf@google.com>
[+] Instrumented 3 locations (64-bit, hardened mode, ratio 100%).
afl-as 2.35b by <lcamtuf@google.com>
[+] Instrumented 24 locations (64-bit, hardened mode, ratio 100%).
afl-as 2.35b by <lcamtuf@google.com>
[!] WARNING: No instrumentation targets found.
afl-as 2.35b by <lcamtuf@google.com>
[+] Instrumented 17 locations (64-bit, hardened mode, ratio 100%).
AFL_HARDEN=1 afl-fuzz -i input/host_a1m1 -o output/host_a1m1 ./_build/host_a1m1.fuzz
afl-fuzz 2.35b by <lcamtuf@google.com>
[+] You have 4 CPU cores and 2 runnable tasks (utilization: 50%).
[+] Try parallel jobs - see /usr/local/Cellar/afl-fuzz/2.35b/share/doc/afl/parallel_fuzzing.txt.
[*] Setting up output directories...
[+] Output directory exists but deemed OK to reuse.
[*] Deleting old session data...
[+] Output dir cleanup successful.
[*] Scanning 'input/host_a1m1'...
[+] No auto-generated dictionary tokens to reuse.
[*] Creating hard links for all input files...
[*] Validating target binary...
[*] Attempting dry run with 'id:000000,orig:001'...
[*] Spinning up the fork server...
[+] All right - fork server is up.
    len = 42, map size = 119, exec speed = 1026 us
[*] Attempting dry run with 'id:000001,orig:002'...
    len = 74, map size = 121, exec speed = 1024 us
[*] Attempting dry run with 'id:000002,orig:003'...
    len = 5, map size = 105, exec speed = 1128 us
[*] Attempting dry run with 'id:000003,orig:004'...
    len = 37, map size = 103, exec speed = 1083 us
[*] Attempting dry run with 'id:000004,orig:126fe40d9e64df223c05078f44bf57cb794dd3e7'...
    len = 1, map size = 78, exec speed = 1269 us
[*] Attempting dry run with 'id:000005,orig:29a03f2d63c198e75237328599123b579e66836e'...
    len = 6, map size = 85, exec speed = 989 us
[+] All test cases processed.

[+] Here are some useful stats:

    Test case count : 6 favored, 0 variable, 6 total
       Bitmap range : 78 to 121 bits (average: 101.83 bits)
        Exec timing : 989 to 1269 us (average: 1087 us)

[*] No -t option specified, so I'll use exec timeout of 20 ms.
[+] All set and ready to roll!
 ```

 And when the fuzzer is running:
 ```sh
                    american fuzzy lop 2.35b (host_a1m1.fuzz)

┌─ process timing ─────────────────────────────────────┬─ overall results ─────┐
│        run time : 0 days, 0 hrs, 0 min, 2 sec        │  cycles done : 0      │
│   last new path : 0 days, 0 hrs, 0 min, 2 sec        │  total paths : 9      │
│ last uniq crash : none seen yet                      │ uniq crashes : 0      │
│  last uniq hang : none seen yet                      │   uniq hangs : 0      │
├─ cycle progress ────────────────────┬─ map coverage ─┴───────────────────────┤
│  now processing : 0 (0.00%)         │    map density : 0.18% / 0.25%         │
│ paths timed out : 0 (0.00%)         │ count coverage : 1.04 bits/tuple       │
├─ stage progress ────────────────────┼─ findings in depth ────────────────────┤
│  now trying : arith 8/8             │ favored paths : 6 (66.67%)             │
│ stage execs : 1440/2571 (56.01%)    │  new edges on : 9 (100.00%)            │
│ total execs : 2649                  │ total crashes : 0 (0 unique)           │
│  exec speed : 939.3/sec             │   total hangs : 0 (0 unique)           │
├─ fuzzing strategy yields ───────────┴───────────────┬─ path geometry ────────┤
│   bit flips : 3/336, 0/335, 0/333                   │    levels : 2          │
│  byte flips : 0/42, 0/41, 0/39                      │   pending : 9          │
│ arithmetics : 0/0, 0/0, 0/0                         │  pend fav : 6          │
│  known ints : 0/0, 0/0, 0/0                         │ own finds : 3          │
│  dictionary : 0/0, 0/0, 0/0                         │  imported : n/a        │
│       havoc : 0/0, 0/0                              │ stability : 100.00%    │
│        trim : 0.00%/10, 0.00%                       ├────────────────────────┘
^C────────────────────────────────────────────────────┘             [cpu: 35%]
 ```

The code coverage can then be seen:
```sh
$ CC=clang make host_a1m1.cov
mkdir -p _build
mkdir -p ./output/host_a1m1/queue
clang -c host_a1m1.c -DAFL -I../src -I../tests -I../src/external/tweetnacl -Wall -Wpedantic -Wextra -Werror -std=c99 -O0 -g -ggdb -o _build/host_a1m1.o
clang -lm _build/salt.o _build/salti_util.o _build/salti_handshake.o _build/crypt_mock.o _build/test_data_mock.o _build/host_a1m1.o -o _build/host_a1m1.cov  --coverage -I../src -I../tests -I../src/external/tweetnacl -Wall -Wpedantic -Wextra -Werror -std=c99 -O0 -g -ggdb
cd _build; find ../input/host_a1m1 -type f -exec bash -c "cat {} | ../_build/host_a1m1.cov" \;
cd _build; find ../output/host_a1m1/queue -type f -exec bash -c "cat {} | ../_build/host_a1m1.cov" \;
lcov --base-directory . --directory . --capture --output-file _build/coverage.info
Capturing coverage data from .
Found LLVM gcov version 9.0.0, which emulates gcov version 4.2.0
Scanning . for .gcda files ...
Found 4 data files in .
Processing _build/salti_util.gcda
Processing _build/test_data_mock.gcda
geninfo: WARNING: gcov did not create any files for /Users/simonj/Development/aa/salt-channel-c/fuzz-tests/_build/test_data_mock.gcda!
Processing _build/salt.gcda
Processing _build/salti_handshake.gcda
Finished .info-file creation
genhtml -o _build _build/coverage.info
Reading data file _build/coverage.info
Found 3 entries.
Found common filename prefix "/Users/simonj/Development/aa/salt-channel-c"
Writing .css and .png files.
Generating output.
Processing file src/salti_handshake.c
Processing file src/salti_util.c
Processing file src/salt.c
Writing directory view page.
Overall coverage rate:
  lines......: 33.0% (225 of 682 lines)
  functions..: 45.0% (18 of 40 functions)
```
A HTML representation of the coverage will be created in the *_build* directory.