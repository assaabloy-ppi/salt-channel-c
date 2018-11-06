
CFLAGS := -Ofast
LIB_SRC := time_stamp.c \
	../src/salt.c \
	../src/salti_util.c \
	../src/salti_handshake.c
LIB_INC := \
	-I../src

TEST_SRC := main.c \
	time_stamp.c \
	crypto_benchmark.c \
	client_handshake_benchmark.c \
	time_stamp_linux.c \
	host_handshake_benchmark.c

SRC_OBJ := $(LIB_SRC:.c=.o)
TEST_OBJ := $(TEST_SRC:.c=.o)

LIBSODIUM_SRC := ../src/external/libsodium/libsodium_wrapper.c
TWEETNACL_SRC := \
	../src/external/tweetnacl_modified/tweetnacl_modified_wrapper.c \
	../src/external/tweetnacl_modified/tweetnacl_modified.c
LIBSODIUM_OBJ := $(LIBSODIUM_SRC:.c=.o)
TWEETNACL_OBJ := $(TWEETNACL_SRC:.c=.o)

%.o: %.c
	$(CC) $(LIB_INC) $(CFLAGS) -c $< -o $(notdir $@)

libsodium: $(SRC_OBJ) $(TEST_OBJ) $(LIBSODIUM_OBJ)
	$(CC) $(CFLAGS) $(notdir $^) -o $@.out -lsodium

tweetnacl:  $(SRC_OBJ) $(TEST_OBJ) $(TWEETNACL_OBJ)
	$(CC) $(CFLAGS) $(notdir $^) -o $@.out

clean:
	rm -rf *.o *.out