C_FLAGS = -Wall -Wextra -Werror -fno-stack-protector -Wpedantic -g -ggdb -DSALT_DEBUG=1 -I. -I../examples -I../src

util.o: ../test/util.c
	$(CC) -c -o $@ ../test/util.c

salt.o: ../src/salt.c ../src/salt.h

tweetnacl.o: ../src/external/tweetnacl/tweetnacl.c
	gcc -c ../src/external/tweetnacl/tweetnacl.c -o tweetnacl.o

salt_2.o: ../src/salt_v2.c ../src/salt_v2.h
	gcc $(C_FLAGS) -c ../src/salt_v2.c -o salt_2.o

host.o: host.c test_data.c
	gcc $(C_FLAGS) -c host.c -o host.o

client.o: client.c test_data.c
	gcc $(C_FLAGS) -c client.c -o client.o

client_test: util.o tweetnacl.o salt_2.o client.o
	$(CC) -lm $^ -o client_test.out

host_test: util.o tweetnacl.o salt_2.o host.o
	$(CC) -lm $^ -o host_test.out

hostclient.o: hostclient.c
	gcc $(C_FLAGS) -c hostclient.c -o hostclient.o

hostclient_test: util.o tweetnacl.o salt_2.o hostclient.o
	$(CC) -lm $^ -o hostclient_test.out

test: clean host_test client_test hostclient_test
	./host_test.out
	./client_test.out
	./hostclient_test.out

clean:
	rm -f *.o
