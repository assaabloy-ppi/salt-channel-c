
FLAGS_COMMON = -Wall -Wpedantic -Wextra -Werror
INC_PATHS_GCC = -I../src -I../tests -I../src/external/tweetnacl
INC_PATHS_AFL = -I../src -I../tests -I../src/external/tweetnacl

GCC_FLAGS = $(INC_PATHS_GCC) $(FLAGS_COMMON) -O0 -g -ggdb -fprofile-arcs -ftest-coverage
AFL_FLAGS = $(INC_PATHS_AFL)
SRC = ../src/salt.c ../src/salt_util.c

FUZZ_TARGETS = host_a1m1 client_m2 client_m3 host_m4 client_a2 host_app client_app read_parse

EXE_FUZZ_TARGETS = $(addsuffix .fuzz, $(FUZZ_TARGETS))
SRC_FUZZ_TARGETS = $(addsuffix .c, $(FUZZ_TARGETS))

EXE_COV = $(addsuffix .cov, $(FUZZ_TARGETS))
EXE_OBJ = _build/salt.o _build/salt_util.o

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

_build/salt_util.o: ../src/salt_util.c
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

%.fuzz: $(SRC) $(SRC_FUZZ_TARGETS)
	mkdir -p _build
	mkdir -p output
	afl-gcc $(SRC) $*.c $(AFL_FLAGS) -o _build/$*.fuzz
	afl-fuzz -i input/$* -o output/$* ./_build/$*.fuzz



%.cov: $(EXE_OBJ)
	mkdir -p _build
	gcc -c $*.c $(GCC_FLAGS) -o _build/$*.o
	gcc -lm $^ _build/$*.o -o _build/$@  -lgcov --coverage $(GCC_FLAGS)
	cd _build; find ../output/$*/queue -type f -exec bash -c "cat {} | ../_build/$*.cov" \;
	lcov --base-directory . --directory . --capture --output-file _build/coverage.info
	genhtml -o _build _build/coverage.info

coverage: $(EXE_COV)
	lcov --base-directory . --directory . --capture --output-file _build/coverage.info
	genhtml -o _build _build/coverage.info

clean:
	rm -rf _build
	rm -rf output
