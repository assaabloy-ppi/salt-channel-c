
C_FLAGS = -I. -Wall -Wextra -Wpedantic -g -ggdb -DSALT_DEBUG=1 -Werror

salt.o: ../src/salt.c ../src/salt.h
	$(CC) -c $(C_FLAGS) -DSALT_DEBUG -c -o $@ ../src/salt.c

binson_light.o: ../src/external/binson-c-light/binson_light.c
	$(CC) -c -o $@ ../src/external/binson-c-light/binson_light.c

tweetnacl.o: ../src/external/tweetnacl/tweetnacl.c
	$(CC) -c -o $@ ../src/external/tweetnacl/tweetnacl.c

host_handshake.o: host_handshake.c ../src/salt.h
	$(CC) -c $(C_FLAGS) -c -o $@ host_handshake.c

client_handshake.o: client_handshake.c ../src/salt.h
	$(CC) -c $(C_FLAGS) -c -o $@ client_handshake.c

host_handshake: host_handshake.o salt.o tweetnacl.o binson_light.o
	$(CC) -lm $^ -o host_handshake.out
	./host_handshake.out

client_handshake: client_handshake.o salt.o tweetnacl.o binson_light.o
	$(CC) -lm $^ -o client_handshake.out
	./client_handshake.out

test: host_handshake client_handshake
