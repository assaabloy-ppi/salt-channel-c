Salt Taste: modular suite for SaltChannel multi-target testing
==========================================

Current suite depends and is built on top of crypto abstraction layer library,
located in `salt-channel-c/src/crypto`.

Suite architecture is modular, CMake-based. These makes it easy to add new tergets, add new crypto backends,
test and optimize existing crypto backends.


Targets supported
=================
* Linux x86_64 (GCC)
* Nordic Semiconductor NRF52 board (ARM Cortex-M4) (GCC)
* Generic MSP430 (IAR) - may be broken

Quick start - Linux
============================

```shell
cd test/salt_taste
make
make build__x86_64-linux-stdout_full
```


Quick start - NRF52
============================

1. Open `tests/salt_taste/Makefile` in your editor
2. Locate target `build__arm_nrf52-none-eabi-gcc`
3. Update next commandline parameters: `TOOLCHAIN_ROOT, NRF5_SDK_ROOT, SOFTDEVICE_REL_PATH`
4. Connect NRF52 development board
5. Run: `make build__arm_nrf52-none-eabi-gcc`


HowTo: switch crypto backend (tweetnacl/libsodium)
==============================

Look for '-DCRYPTO_BACKEND=libsodium' parameter. Valid values are backend directory names located under
`salt-channel-c/src/crypto/lib`. To make a copy of backend just copy its directory with new name in `lib` 
and `wrap` subdirectories. To add new backend with different API, also update wrapping code in appropriate
directory located under `wrap`.

HowTo: add new target/configuration
==============================

To add new toolchain/compiler for existing target it may be enought just to add toolchain file in
`salt-channel-c/tests/salt_taste/cmake` and then specify it's name within `-DCMAKE_TOOLCHAIN_FILE=` parameter.

To add new target it's required to implement HAL layer: see `salt-channel-c/tests/salt_taste/src/hal`.
HAL directory must be specified with `-DHAL=` parameter.

ToDo
=====
* test/fix fuzzing
* implement all required "detached" calls
* fix platform tests: RNG, Timer 
* cleanup
* add server-side handshake perfmetering
* option: MINIMIZE_MEMUSE
* your suggestions ...

