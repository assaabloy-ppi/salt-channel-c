
rmdir build /s /q
mkdir build
cd build
cmake  -DCMAKE_VERBOSE_MAKEFILE:BOOL=ON -G "MinGW Makefiles" -DCMAKE_TOOLCHAIN_FILE=cmake/toolchain/msp430-none-eabi-iar.cmake ^
		  -DCMAKE_MAKE_PROGRAM=make ^
		  -DHAL=msp430-none-iar_test ..
cmake  --build .
cd ..