C_FLAGS = -Wall -Wextra -Werror -fno-stack-protector -Wpedantic -g -ggdb -DSALT_DEBUG=1 -I. -I../examples -I../src
LD_FLAGS = -pthread

util.o: ../test/util.c
	$(CC) -c -o $@ ../test/util.c

salt_2.o: ../src/salt_v2.c ../src/salt_v2.h
	gcc $(C_FLAGS) -c ../src/salt_v2.c -o salt_2.o

tweetnacl.o: ../src/external/tweetnacl/tweetnacl.c
	gcc -c ../src/external/tweetnacl/tweetnacl.c -o tweetnacl.o

randombytes_linux.o: randombytes_linux.c
	$(CC) $(C_FLAGS) -c -o $@ randombytes_linux.c

host.o: host.c
	gcc $(C_FLAGS) -c host.c -o host.o

client.o: client.c
	gcc $(C_FLAGS) -c client.c -o client.o

client_prog: client.o salt_2.o tweetnacl.o randombytes_linux.o
	$(CC) $(LD_FLAGS) -lm $^ -o client_prog.out

host_prog: host.o salt_2.o tweetnacl.o randombytes_linux.o
	$(CC) $(LD_FLAGS) -lm $^ -o client_prog.out

clean:
	rm -f *.o