#!/bin/sh
REPORT_DIR="html"

SCAN_OPT="-enable-checker alpha.core.BoolAssignment \
-enable-checker alpha.core.CastSize \
-enable-checker alpha.core.DynamicTypeChecker \
-enable-checker alpha.core.FixedAddr \
-enable-checker alpha.core.IdenticalExpr \
-enable-checker alpha.core.PointerArithm \
-enable-checker alpha.core.PointerSub \
-enable-checker alpha.core.SizeofPtr \
-enable-checker alpha.core.TestAfterDivZero \
-enable-checker alpha.deadcode.UnreachableCode \
-enable-checker alpha.security.ArrayBoundV2 \
-enable-checker alpha.security.MallocOverflow \
-enable-checker alpha.security.ReturnPtrRange \
-enable-checker alpha.unix.PthreadLock \
-enable-checker alpha.unix.Stream \
-enable-checker alpha.unix.cstring.BufferOverlap \
-enable-checker alpha.unix.cstring.NotNullTerminated \
-enable-checker alpha.unix.cstring.OutOfBounds \
-enable-checker nullability.NullableDereferenced \
-enable-checker optin.performance.Padding \
-enable-checker security.insecureAPI.rand \
-enable-checker security.insecureAPI.strcpy \
--analyzer-target=arm-none-eabi"

rm -rf Debug
mkdir Debug
cd Debug
/path/to/scan-build -v -o $REPORT_DIR $SCAN_OPT cmake -DCMAKE_CXX_COMPILER=/path/to/c++-analyzer -DCMAKE_C_COMPILER=/path/to/ccc-analyzer ..
make cmocka
/path/to/scan-build -v -o $REPORT_DIR $SCAN_OPT make
