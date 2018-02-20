.DEFAULT_GOAL := help
.PHONY: any

help: Makefile
	@echo "\nUsage: make <target>"
	@echo "\twhere <target> is one of the following:\n"
	@grep -E '^[0-9a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST)  | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
	@echo

clean: ## Project cleanup
	rm -rf build

#-DCRYPTO_BACKEND=tweetnacl_modified
build__x86_64-linux-stdout_full: clean  ## Build for HAL 'x86_64-linux-stdout_full'
	mkdir build && cd build && \
	cmake -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain/x86_64-linux-elf-gcc.cmake \
		  -DCRYPTO_BACKEND=libsodium \
		  -DHAL=x86_64-linux-stdout_full .. && \
	cmake --build . && \
	./salt_taste

#-DCMAKE_VERBOSE_MAKEFILE:BOOL=ON 
#-DCRYPTO_BACKEND=tweetnacl_modified
build__arm_nrf52-none-eabi-gcc: clean  ## Build for HAL 'arm_nrf52-none-eabi-gcc'

	mkdir build && cd build && \
	cmake -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain/arm_nrf5x-none-eabi-gcc.cmake \
		  -DTOOLCHAIN_ROOT=/arm \
		  -DNRF5_SDK_ROOT=/home/kotomysha/ASSA/dev/nrf-sdk \
		  -DSOFTDEVICE_REL_PATH=components/softdevice/s132/hex/s132_nrf52_5.0.0_softdevice.hex \
		  -DNRF_TARGET=NRF52  \
		  -DCRYPTO_BACKEND=tweetnacl_modified \
		  -DHAL=arm_nrf52-none-serial_debug .. && \
	cmake --build . && \
	make f_salt_taste


build__msp430-none-iar_test: clean  ## Build for HAL 'msp430-none-iar_test'
	mkdir build && cd build && \
	cmake -G "MinGW Makefiles" -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain/msp430-none-eabi-iar.cmake \
		  -DHAL=msp430-none-iar_test .. && \
	cmake --build .

last: ## Build last target if './build' directory exists
	cd build && make

last_run: ## Build last target if './build' directory exists & run/flash it
	cd build && make && make f_salt_taste
