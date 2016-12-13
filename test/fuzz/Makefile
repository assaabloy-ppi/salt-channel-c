DEPS_SRC = ../../src/salt.c ../../src/external/binson-c-light/binson_light.c 

server_m1.gdb: server_m1/server_m1.c $(DEPS_SRC)
	gcc -g -ggdb -I../ -o $@ $^

server_m1.fuzz: server_m1/server_m1.c $(DEPS_SRC)
	afl-gcc -I../ -o $@ $^

fuzz_server_m1: server_m1.fuzz
	afl-fuzz -i server_m1/input -o server_m1/output ./server_m1.fuzz

server_m4.gdb: server_m4/server_m4.c $(DEPS_SRC)
	gcc -g -ggdb -I../ -o $@ $^ ../../src/external/tweetnacl/tweetnacl.c

server_m4.fuzz: server_m4/server_m4.c $(DEPS_SRC)
	afl-gcc -I../ -o $@ $^ ../../src/external/tweetnacl/tweetnacl.c

fuzz_server_m4: server_m4.fuzz
	afl-fuzz -i server_m4/input -o server_m4/output ./server_m4.fuzz

server_decrypt.gdb: server_decrypt/server_decrypt.c $(DEPS_SRC)
	gcc -g -ggdb -I../ -o $@ $^ ../../src/external/tweetnacl/tweetnacl.c

server_decrypt.fuzz: server_decrypt/server_decrypt.c $(DEPS_SRC)
	afl-gcc -I../ -o $@ $^ ../../src/external/tweetnacl/tweetnacl.c

fuzz_server_decrypt: server_decrypt.fuzz
	afl-fuzz -i server_decrypt/input -o server_decrypt/output ./server_decrypt.fuzz
