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


Typical output
====================

Below is log for Linux x86_64 target with `tweetnacl_modified` backend:
```
Ready ... 
Crypto backend: tweetnacl_modified
Crypto init ... done 
Version: ?
==========================================
EVENT: id=ready              status=done/ok           
EVENT: id=HAL                status=init              
EVENT: id=HAL                status=done/ok           
EVENT: id=crypto_sanity      status=init              
... crypto_sign_keypair()
... crypto_sign()
      srcline:565, ptr: 0x7ffc7ce37c90, size: 67 -> 7f4e2596d65bef43defcc4b0de8ffadc68f642c608859c9b7a1cebcb520ad0b0e91659a1374001707305cc25dfbb7cb720f51c2eb843d9ea344bc66d65d66c0d030303
... crypto_sign_open()
... crypto_box_keypair()
... crypto_box_beforenm()
      srcline:565, ptr: 0x7ffc7ce37c60, size: 35 -> 0000000000000000000000000000000001bf37050fa8165ab2cb2e874c29034805d321
... crypto_hash()
... crypto_hash_sha512_*()
EVENT: id=crypto_sanity      status=done/ok           
------ Handshake measurement (loops: 1)...
EVENT: id=handshake          status=init              
EVENT: id=handshake          status=done/ok           
------ Spent in one loop: 55 ms (55450 us).
EVENT: id=shutdown           status=init
```

BTW, all above events may be easely handled in HAL layer, for example, 
when HAL has no console, custom event handler may change specific pin level to monitor execution state.


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
* your suggestions ... please report via adding issues (bug/enhancement)

