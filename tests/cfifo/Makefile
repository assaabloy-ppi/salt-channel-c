C_FLAGS = -Wall -Wextra -Wpedantic -Werror -std=c89 -fprofile-arcs -ftest-coverage
LD_FLAGS += -lgcov --coverage
BUILD_DIR 	:= _output
DEPS 		:= cfifo.h
SRC			:= cfifo.c test.c
OBJ 		:= $(addprefix $(BUILD_DIR)/, $(SRC:.c=.o))
TEST_PROG	:= $(BUILD_DIR)/cfifo_test.out

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: %.c $(DEPS) 
	$(CC) -c -o $@ $< $(C_FLAGS)

$(TEST_PROG): $(OBJ)
	$(CC) -lm $^ -o $@ $(LD_FLAGS)

run_test: $(BUILD_DIR) $(TEST_PROG)
	./$(TEST_PROG)

coverage: run_test
	lcov --base-directory . --directory $(BUILD_DIR) --capture --output-file $(BUILD_DIR)/coverage.info
	genhtml -o $(BUILD_DIR) $(BUILD_DIR)/coverage.info

clean:
	rm -rf $(BUILD_DIR)
