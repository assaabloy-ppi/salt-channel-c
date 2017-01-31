C_FLAGS = -Wall -Wextra -Wpedantic -g -ggdb -DSALT_DEBUG=1 -I. -I../examples -I../src


test_data.o: test_data.c
	$(CC) -c -o $@ test_data.c

util.o: ../test/util.c
	$(CC) -c -o $@ ../test/util.c

salt.o: ../src/salt.c ../src/salt.h

tweetnacl.o: ../src/external/tweetnacl/tweetnacl.c
	gcc -c ../src/external/tweetnacl/tweetnacl.c -o tweetnacl.o

salt_2.o: ../src/salt_v2.c ../src/salt_v2.h
	gcc $(C_FLAGS) -c ../src/salt_v2.c -o salt_2.o

host.o: host.c
	gcc $(C_FLAGS) -c host.c -o host.o

client.o: client.c
	gcc $(C_FLAGS) -c client.c -o client.o

client_test: util.o tweetnacl.o salt_2.o client.o test_data.o
	$(CC) -lm $^ -o client_test.out

host_test: util.o tweetnacl.o salt_2.o host.o test_data.o
	$(CC) -lm $^ -o host_test.out