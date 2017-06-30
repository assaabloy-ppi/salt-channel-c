C_FLAGS := -Wall -Wextra -Werror -fno-stack-protector -Wpedantic
C_FLAGS += -g -ggdb -DSALT_DEBUG=1
C_FLAGS += -I. -I../examples -I../src -Icfifo

DEPS := ../src/salt_v2.h Makefile test_data.c

salt_util.o: ../src/salt_util.c ../src/salt_util.h
	$(CC) $(C_FLAGS) -c $< -o $@

cfifo.o: cfifo/cfifo.c cfifo/cfifo.h
	$(CC) $(C_FLAGS) $(C_FLAGS) -c $< -o $@

tweetnacl.o: ../src/external/tweetnacl/tweetnacl.c
	$(CC) -c $< -o $@

salt_2.o: ../src/salt_v2.c ../src/salt_v2.h
	$(CC) $(C_FLAGS) -c $< -o $@

hostclient.o: hostclient.c $(DEPS)
	$(CC) $(C_FLAGS) -c $< -o $@

a1a2handshake.o: a1a2handshake.c $(DEPS)
	$(CC) $(C_FLAGS) -c $< -o $@

client.o: client.c $(DEPS)
	$(CC) $(C_FLAGS) -c $< -o $@

host.o: host.c $(DEPS)
	$(CC) $(C_FLAGS) -c $< -o $@

a1a2handshake_test.out: cfifo.o tweetnacl.o salt_2.o a1a2handshake.o salt_util.o
	$(CC) -lm $^ -o $@

hostclient_test.out: cfifo.o tweetnacl.o salt_2.o hostclient.o salt_util.o
	$(CC) -lm $^ -o $@

client_test.out: client.o tweetnacl.o salt_2.o salt_util.o
	$(CC) -lm $^ -o $@

host_test.out: host.o tweetnacl.o salt_2.o salt_util.o
	$(CC) -lm $^ -o $@

test: host_test.out client_test.out hostclient_test.out a1a2handshake_test.out
	./host_test.out
	./client_test.out
	./hostclient_test.out
	./a1a2handshake_test.out

crypt_test.o: crypt_test.c
	$(CC) $(C_FLAGS) -I../src/external/tweetnacl -c crypt_test.c -o crypt_test.o

crypt_test.out: crypt_test.o tweetnacl.o
	$(CC) -lm $^ -o crypt_test.out

clean:
	rm -f *.o
