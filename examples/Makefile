
C_FLAGS = -Wall -Wextra -Wpedantic -g -ggdb -DSALT_DEBUG=1

salt.o: ../salt.c ../salt.h
	$(CC) -c $(C_FLAGS) -DSALT_DEBUG -c -o $@ ../salt.c

binson_light.o:
	$(CC) -c -o $@ ../binson_light.c

tweetnacl.o:
	$(CC) -c -o $@ ../tweetnacl.c

host.o: host.c ../salt.h
	$(CC) -c $(C_FLAGS) -c -o $@ host.c

client.o: client.c ../salt.h
	$(CC) -c $(C_FLAGS) -c -o $@ client.c

multi_host.o: multi_host.c ../salt.h
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