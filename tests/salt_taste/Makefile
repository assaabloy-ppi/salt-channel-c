.DEFAULT_GOAL := help
.PHONY: any

help: Makefile
	@echo "\nUsage: make <target>"
	@echo "\twhere <target> is one of the following:\n"
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST)  | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
	@echo

clean: ## Project cleanup
	rm -rf build

build__x86_64-linux-stdout_full: clean  ## Build for HAL 'x86_64-linux-stdout_full'
	mkdir build && cd build && \
	cmake -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain/x86_64-linux-elf-gcc.cmake \
		  -DHAL=x86_64-linux-stdout_full .. && \
	cmake --build . && \
	./salt_taste
