C_FLAGS 	= -Wall -Wextra -Werror -fno-stack-protector -Wpedantic -g -ggdb -DSALT_DEBUG=1 -I. -I../examples -I../src -I../test
LD_FLAGS 	= -pthread

DEPS 		= ../src/salt_v2.h

all: client_prog host_prog client_echo host_echo

salt_util.o: ../src/salt_util.c
	$(CC) $(C_FLAGS) -c -o $@ ../src/salt_util.c

salt_2.o: ../src/salt_v2.c $(DEPS)
	gcc $(C_FLAGS) -c ../src/salt_v2.c -o salt_2.o

tweetnacl.o: ../src/external/tweetnacl/tweetnacl.c
	gcc -c -g -ggdb ../src/external/tweetnacl/tweetnacl.c -o tweetnacl.o

randombytes_linux.o: randombytes_linux.c
	$(CC) $(C_FLAGS) -c -o $@ randombytes_linux.c

salt_io.o: salt_io.c
	gcc $(C_FLAGS) -c salt_io.c -o salt_io.o

host.o: host.c $(DEPS)
	gcc $(C_FLAGS) -c host.c -o host.o

client.o: client.c $(DEPS)
	gcc $(C_FLAGS) -c client.c -o client.o

host_echo.o: host_echo.c $(DEPS)
	gcc $(C_FLAGS) -c host_echo.c -o host_echo.o

client_echo.o: client_echo.c $(DEPS)
	gcc $(C_FLAGS) -c client_echo.c -o client_echo.o

client_prog: client.o salt_2.o tweetnacl.o randombytes_linux.o salt_util.o salt_io.o
	$(CC) $(LD_FLAGS) -lm $^ -o client_prog.out

host_prog: host.o salt_2.o tweetnacl.o randombytes_linux.o salt_util.o salt_io.o
	$(CC) $(LD_FLAGS) -lm $^ -o host_prog.out

client_echo: client_echo.o salt_2.o tweetnacl.o randombytes_linux.o salt_util.o salt_io.o
	$(CC) $(LD_FLAGS) -lm $^ -o client_echo.out

host_echo: host_echo.o salt_2.o tweetnacl.o randombytes_linux.o salt_util.o salt_io.o
	$(CC) $(LD_FLAGS) -lm $^ -o host_echo.out

clean:
	rm -f *.o
