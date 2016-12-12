
C_FLAGS = -Wall -Wextra -Wpedantic -g -ggdb -DSALT_DEBUG=1 -I.

salt.o: ../src/salt.c ../src/salt.h
	$(CC) -c $(C_FLAGS) -DSALT_DEBUG -c -o $@ ../src/salt.c

binson_light.o:
	$(CC) -c -o $@ ../src/external/binson-c-light/binson_light.c

tweetnacl.o:
	$(CC) -c -o $@ ../src/external/tweetnacl/tweetnacl.c

host.o: host.c ../src/salt.h
	$(CC) -c $(C_FLAGS) -c -o $@ host.c

client.o: client.c ../src/salt.h
	$(CC) -c $(C_FLAGS) -c -o $@ client.c

multi_host.o: multi_host.c ../src/salt.h
	$(CC) -c $(C_FLAGS) -c -o $@ multi_host.c

randombytes_linux.o: 
	$(CC) -c -o $@ randombytes_linux.c

host: host.o salt.o tweetnacl.o binson_light.o randombytes_linux.o
	$(CC) -lm $^ -o host.out
	./host.out

client: client.o salt.o tweetnacl.o binson_light.o randombytes_linux.o
	$(CC) -lm $^ -o client.out
	./client.out

multi_host: multi_host.o salt.o tweetnacl.o binson_light.o randombytes_linux.o
	$(CC) -lm $^ -o multi_host.out
	./multi_host.out