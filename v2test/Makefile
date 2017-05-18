C_FLAGS := -Wall -Wextra -Werror -fno-stack-protector -Wpedantic
C_FLAGS += -g -ggdb -DSALT_DEBUG=1
C_FLAGS += -I. -I../examples -I../src -Icfifo

salt_util.o: ../src/salt_util.c ../src/salt_util.h
	$(CC) $(C_FLAGS) -c -o $@ ../src/salt_util.c

cfifo.o: cfifo/cfifo.c
	$(CC) $(C_FLAGS) $(C_FLAGS) -c cfifo/cfifo.c -o cfifo.o

tweetnacl.o: ../src/external/tweetnacl/tweetnacl.c
	$(CC) -c ../src/external/tweetnacl/tweetnacl.c -o tweetnacl.o

salt_2.o: ../src/salt_v2.c ../src/salt_v2.h
	$(CC) $(C_FLAGS) -c ../src/salt_v2.c -o salt_2.o

hostclient.o: hostclient.c ../src/salt_v2.h
	$(CC) $(C_FLAGS) -c hostclient.c -o hostclient.o

hostclient_test: cfifo.o tweetnacl.o salt_2.o hostclient.o salt_util.o
	$(CC) -lm $^ -o hostclient_test.out

test: clean host_test client_test hostclient_test
	./host_test.out
	./client_test.out
	./hostclient_test.out

crypt_test.o: crypt_test.c
	$(CC) $(C_FLAGS) -I../src/external/tweetnacl -c crypt_test.c -o crypt_test.o

crypt_test.out: crypt_test.o tweetnacl.o
	$(CC) -lm $^ -o crypt_test.out

clean:
	rm -f *.o
