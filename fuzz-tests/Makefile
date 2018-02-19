
FLAGS_COMMON = -Wall -Wpedantic -Wextra -Werror -std=c99
INC_PATHS_GCC = -I../src -I../tests -I../src/external/tweetnacl
INC_PATHS_AFL = -I../src -I../tests -I../src/external/tweetnacl

GCC_FLAGS = $(INC_PATHS_GCC) $(FLAGS_COMMON) -O0 -g -ggdb -fprofile-arcs -ftest-coverage
AFL_FLAGS = $(INC_PATHS_AFL) -std=c99
SRC = ../src/salt.c ../src/salti_util.c ../src/salti_handshake.c

FUZZ_TARGETS = host_a1m1 client_m2 client_m3 host_m4 client_a2 host_app client_app read_parse

EXE_FUZZ_TARGETS = $(addsuffix .fuzz, $(FUZZ_TARGETS))
SRC_FUZZ_TARGETS = $(addsuffix .c, $(FUZZ_TARGETS))

EXE_COV = $(addsuffix .cov, $(FUZZ_TARGETS))
EXE_OBJ = _build/salt.o _build/salti_util.o _build/salti_handshake.o

ifdef USE_TWEETNACL
EXE_OBJ += _build/tweetnacl.o _build/test_data.o
SRC += ../src/external/tweetnacl/tweetnacl.c ../tests/test_data.c
else
EXE_OBJ += _build/crypt_mock.o _build/test_data_mock.o
SRC += crypt_mock.c test_data_mock.c
endif

.PHONY: all

_build/salt.o: ../src/salt.c
	gcc -c $^ $(GCC_FLAGS) -o $@

_build/salti_util.o: ../src/salti_util.c
	gcc -c $^ $(GCC_FLAGS) -o $@

_build/salti_handshake.o: ../src/salti_handshake.c
	gcc -c $^ $(GCC_FLAGS) -o $@

_build/crypt_mock.o: crypt_mock.c
	gcc -c $^ -o $@ $(INC_PATHS_GCC)

_build/test_data_mock.o: test_data_mock.c
	gcc -c $^ $(GCC_FLAGS) -o $@

_build/test_data.o: ../tests/test_data.c
	gcc -c $^ $(GCC_FLAGS) -o $@

_build/tweetnacl.o: ../src/external/tweetnacl/tweetnacl.c
	gcc -c $^ $(GCC_FLAGS) -o $@

$(EXE_FUZZ_TARGETS):

$(EXE_COV):

# check input for crashes
%.dry: $(SRC)
	find ./input/$* -type f -exec bash -c "ls -d -1 $$PWD/{}; cat {} | ./_build/$*.fuzz " \;	

# minimize input corpus in-place with afl-cmin tool
%.cmin: $(SRC) $(SRC_FUZZ_TARGETS)
	mkdir -p _build
	mkdir -p output
	afl-gcc -DAFL $(SRC) $*.c  $(AFL_FLAGS) -o _build/$*.fuzz
	afl-cmin -i input/$* -o input/cmin_$* ./_build/$*.fuzz
	rm -rf ./input/$*
	mv ./input/cmin_$* ./input/$*	

# AFL fuzz with NO sanitizers
%.fuzz:  $(SRC) $(SRC_FUZZ_TARGETS) 
	mkdir -p _build
	mkdir -p output
	AFL_HARDEN=1 afl-gcc -DAFL $(SRC) $*.c  $(AFL_FLAGS) -o _build/$*.fuzz
	AFL_HARDEN=1 afl-fuzz -i input/$* -o output/$* ./_build/$*.fuzz

# AFL fuzz with ASAN sanitizer
%.afuzz:  $(SRC) $(SRC_FUZZ_TARGETS) 
	mkdir -p _build
	mkdir -p output
	AFL_USE_ASAN=1 afl-gcc -m32 -DAFL $(SRC) $*.c  $(AFL_FLAGS) -o _build/$*.fuzz
	AFL_USE_ASAN=1 afl-fuzz -m none -i input/$* -o output/$* ./_build/$*.fuzz

# libFuzzer fuzz with ASAN+UBSAN sanitizers
%.libfuzz: $(SRC)
	mkdir -p _build
	mkdir -p output	
	clang $(GCC_FLAGS) -Wno-unused-parameter -fsanitize=fuzzer,address,undefined  \
				 $(SRC) $*.c \
				-lm -o _build/$*.libfuzz
	
	export ASAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer
	export ASAN_OPTIONS=symbolize=1
	export UBSAN_SYMBOLIZER_PATH=/usr/bin/llvm-symbolizer
	export UBSAN_OPTIONS=symbolize=1	
	mkdir -p ./output/$*/crashes	
	_build/$*.libfuzz -artifact_prefix="./output/$*/crashes/" input/$*


%.cov: $(EXE_OBJ)
	mkdir -p _build
	mkdir -p ./output/$*/queue
	gcc -c $*.c -DAFL $(GCC_FLAGS) -o _build/$*.o
	gcc -lm $^ _build/$*.o -o _build/$@  -lgcov --coverage $(GCC_FLAGS)
	cd _build; find ../input/$* -type f -exec bash -c "cat {} | ../_build/$*.cov" \;
	cd _build; find ../output/$*/queue -type f -exec bash -c "cat {} | ../_build/$*.cov" \;
	lcov --base-directory . --directory . --capture --output-file _build/coverage.info
	genhtml -o _build _build/coverage.info

coverage: $(EXE_COV)
	lcov --base-directory . --directory . --capture --output-file _build/coverage.info
	genhtml -o _build _build/coverage.info

clean:
	rm -rf _build
	rm -rf output
