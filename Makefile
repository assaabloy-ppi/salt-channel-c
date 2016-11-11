
C_FLAGS = -Wall -Wextra -Wpedantic -g -ggdb -DSALT_DEBUG=1 -Werror

salt.o: salt.c salt.h
	$(CC) -c $(C_FLAGS) -DSALT_DEBUG -c -o $@ salt.c

binson_light.o:
	$(CC) -c -o $@ binson_light.c

tweetnacl.o:
	$(CC) -c -o $@ tweetnacl.c

host_test.o: host_test.c salt.h
	$(CC) -c $(C_FLAGS) -c -o $@ host_test.c

client_test.o: client_test.c salt.h
	$(CC) -c $(C_FLAGS) -c -o $@ client_test.c

host_test: host_test.o salt.o tweetnacl.o binson_light.o
	$(CC) -lm $^ -o host_test.out
	./host_test.out

client_test: client_test.o salt.o tweetnacl.o binson_light.o
	$(CC) -lm $^ -o client_test.out
	./client_test.out
