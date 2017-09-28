
GCC_FLAGS = -I../../src -I../ -I../../src/external/tweetnacl -g -ggdb -DSALT_DEBUG=1 -fprofile-arcs -ftest-coverage
AFL_FLAGS = -I../../src -I../ -I../../src/external/tweetnacl
SRC = ../../src/salt_v2.c ../../src/salt_util.c crypt_mock.c

FUZZ_TARGETS = host_a1m1 client_m2 client_m3 host_m4 client_a2 host_app client_app

EXE_FUZZ_TARGETS = $(addsuffix .fuzz, $(FUZZ_TARGETS))
SRC_FUZZ_TARGETS = $(addsuffix .c, $(FUZZ_TARGETS))

EXE_COV = $(addsuffix .cov, $(FUZZ_TARGETS))
EXE_OBJ = _build/salt_v2.o _build/salt_util.o _build/crypt_mock.o

.PHONY: all

_build/salt_v2.o: ../../src/salt_v2.c
	gcc -c $^ $(GCC_FLAGS) -o $@

_build/salt_util.o: ../../src/salt_util.c
	gcc -c $^ $(GCC_FLAGS) -o $@

_build/crypt_mock.o: crypt_mock.c
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
	gcc -lm $^ _build/$*.o -o _build/$@  -lgcov --coverage
	cd _build; find ../output/$*/queue -type f -exec bash -c "cat {} | ../_build/$*.cov" \;

coverage: $(EXE_COV)
	lcov --base-directory . --directory . --capture --output-file _build/coverage.info
	genhtml -o _build _build/coverage.info

clean:
	rm -rf _build
	rm -rf output
	rm *.gcda
	rm *.gcno